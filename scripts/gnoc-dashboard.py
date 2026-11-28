#!/usr/bin/env python3
"""gnoc dash - the redesigned GREYNOC hunt-control dashboard (scripts/GNOC-DASHBOARD.md).

    gnoc dash                      live dashboard (the view and theme you used last)
    gnoc dash --once [--size WxH]  one frame to stdout, no input (pipes, screenshots, tests)
    gnoc dash --view simple|technical  --theme neon|contrast|mono  --demo
    gnoc dash --snapshot           print the snapshot both views are drawn from, as JSON
    gnoc dash --classic [args]     the old renderer (exactly `gnoc watch [args]`)

KEYS (single keys act only while the command box is empty; otherwise you are typing a command)
    Tab or v      Simple <-> Technical view (remembered in .claude/state/orch/dashboard-view.txt)
    1-9           Technical: zoom one panel to the whole screen; 0 or Esc back; PgUp/PgDn scroll it
    , and .       Technical activity feed: cycle the kind filter / the program filter
    t or Ctrl-T   next theme (neon-noir, high-contrast, mono)
    Ctrl-D        demo mode on/off: real program, host and report names become stable fake ones
    q             quit (or Ctrl-C).  Typed words: view [simple|technical], theme [name], demo [on|off]
Every gnoc command still works in the box exactly as in `gnoc watch` (chair, pivot, orch ..., models,
dchat, lab ..., inbox, chat, help, !shell, q). NO_COLOR, TERM=dumb and non-UTF-8 locales degrade to
mono and/or plain ASCII glyphs automatically (GNOC_ASCII=1 forces ASCII).

Data comes ONLY from scripts/gnoc's own Feed collectors, imported read-only (never edited, never patched).
"""
from __future__ import annotations

import copy
import hashlib
import importlib.machinery
import importlib.util
import json
import math
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

WS = os.environ.get("GNOC_WS", (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
_ld = importlib.machinery.SourceFileLoader("gnoc_mod", os.path.join(WS, "scripts/gnoc"))
_spec = importlib.util.spec_from_loader("gnoc_mod", _ld)
g = importlib.util.module_from_spec(_spec)
_ld.exec_module(g)

GLOSSARY_PATH = os.path.join(WS, "scripts/gnoc-dashboard-glossary.json")
PREFS = os.environ.get("GNOC_DASH_PREFS") or os.path.join(g.ORCH_DIR, "dashboard-view.txt")  # override for tests
VIEWS = ("simple", "technical")
THEME_ORDER = ("neon", "contrast", "mono")


# ======================================================================================================
# glossary: raw log vocabulary -> plain English
# ======================================================================================================

class Glossary:
    """Loads scripts/gnoc-dashboard-glossary.json. Every lookup returns (text, level); a word with no entry
    falls back to a humanised copy of itself at level 'muted' and is remembered in self.missing."""

    def __init__(self, path=GLOSSARY_PATH):
        with open(path, encoding="utf-8") as fh:
            self.g = json.load(fh)
        self.missing = set()

    def _map(self, section, key):
        hit = self.g.get(section, {}).get(key)
        if hit is None:
            hit = self.g.get(section, {}).get(str(key).lower())
        if hit is None:
            self.missing.add((section, key))
            return (str(key).replace("_", " ").replace("-", " ").lower() or "update", "muted")
        return tuple(hit)

    def _prefix(self, section, value):
        v = re.sub(r"^\d+x\s+", "", str(value or "").strip())
        for pre, text, level in self.g.get(section, []):
            if v.lower().startswith(pre.lower()):
                return (text, level)
        return None

    def change(self, kind):
        return self._map("change_kind", str(kind or "change").lower())

    def action(self, a):
        return self._map("brain_action", a or "wait")

    def status(self, s):
        return self._map("brain_status", s or "ok")

    def verdict(self, v):
        hit = self._prefix("verdict_prefix", v)
        if hit is None:
            self.missing.add(("verdict_prefix", v))
            return ("hunt result recorded", "muted")
        return hit

    def ship(self, status, kind):
        hit = self._prefix("ship_status_prefix", status) if status else None
        return hit or self._map("ship_kind", kind or "")

    def inbox(self, kind):
        return self._map("inbox_kind", kind or "-")

    def oss_job(self, job):
        return self._map("oss_job", job)

    def oss_state(self, word):
        return self._map("oss_state", word)

    def vocabulary(self):
        """Every raw word the glossary knows (they name our own machinery, never a target)."""
        out = []
        for sec, v in self.g.items():
            if isinstance(v, dict):
                out += list(v)
            elif isinstance(v, list):
                out += [row[0] for row in v]
        return out

    def source(self, kind):
        return self.g.get("source", {}).get(kind, kind.lower())


# ======================================================================================================
# demo mode: a stable real -> fake name substitution applied to the WHOLE snapshot
# ======================================================================================================

FAKE_ORGS = ["acme", "globex", "initech", "umbrella", "hooli", "stark", "wayne", "wonka", "cyberdyne", "tyrell",
             "soylent", "aperture", "vandelay", "oceanic", "monarch", "nakatomi", "gringotts", "massive", "dunder",
             "prestige", "virtucon", "sirius", "oscorp", "veridian", "zorg", "nostromo", "weyland", "blackmesa",
             "pendant", "kramerica", "bluth", "sterling", "paper-st", "contoso", "fabrikam", "northwind", "tailspin",
             "woodgrove", "litware", "adatum", "fourth-coffee", "proseware", "lucerne", "margie", "wingtip"]
CODENAMES = ["aurora", "basalt", "cobalt", "delta", "ember", "fjord", "garnet", "harbor", "indigo", "juniper",
             "krypton", "lumen", "meridian", "nimbus", "onyx", "prairie", "quartz", "raven", "sierra", "topaz",
             "umber", "vesper", "willow", "xenon", "yarrow", "zephyr", "atlas", "beacon", "cinder", "drift"]
GENERIC_PARTS = {"vdp", "bbp", "bug", "bounty", "program", "and", "company", "the", "of", "public", "industries",
                 "group", "inc", "h1", "com", "net", "org", "io", "app", "www", "api", "dev", "prod", "staging",
                 "test", "auth", "admin", "portal", "web", "cdn", "static", "mail", "status", "docs", "help",
                 "login", "id", "my", "go", "m", "us", "eu", "internal", "corp", "cloud", "bugbounty", "security",
                 "hackerone", "global", "online", "service", "services", "secure", "gateway", "edge", "data", "hub"}
TECH_SAFE = set("""ssrf idor bola xss csrf rce sqli ssti oauth saml jwt api apis http https tls dns cname cdn waf
json jsonl yaml md py sh pm2 ollama qwen qwen2 qwen3 hermes hermes3 gemma gemma4 llama mistral phi deepseek opencode
greynoc gnoc orch oss nuclei cve cves pid pids vram gpu cpu ram ssh vpn burp mcp h1 hackerone bugcrowd intigriti
yeswehack immunefi huntr vdp bbp utc edt est cli tui ui url urls uri ok rc rss stdout stdin tmp env actuator
heapdump threaddump graphql grpc rest webhook webhooks sso otp mfa totp csp cors s3 gcs iam acl rbac
oc desktop keepalive onion tunnel proxy cloudflared ascii unicode brain dchat chair repl
lookup signup login logout endpoint endpoints subdomain subdomains wildcard backend frontend config sweep sweeps
unfired unauth authed auto pivot pivots escalate escalation recon triage triaged lane lanes callback redirect
""".split())
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
URL_RE = re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s\"'<>)\]]+", re.I)
SECRET_RE = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{10,}|sk-[A-Za-z0-9_\-]{10,}|xox[abpr]-[A-Za-z0-9\-]{10,}|AKIA[0-9A-Z]{12,}"
                       r"|eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-.]*|[0-9a-fA-F]{24,}"
                       r"|(?=[A-Za-z0-9_+/=]*\d)(?=[A-Za-z0-9_+/=]*[A-Za-z])[A-Za-z0-9_+/=]{32,})")
TLDS = ("com|net|org|io|app|dev|co|ai|build|me|cloud|xyz|gov|edu|us|uk|de|fr|jp|tw|in|br|ru|cn|biz|info|so|sh|gg|"
        "tv|live|tech|site|online|store|page|link|ly|to|eu|ca|au|nl|se|ch|es|it|pl|be|mx|kr|sg|hk|id|vn|th|my|ph|"
        "ae|sa|za|ng|ke|ar|cl|pe|no|fi|dk|at|cz|pt|gr|ie|il|tr|ua|nz|ro|hu|bg|is|lu|travel|bank|money|finance|"
        "games|shop|pay|wallet|exchange|network|systems|solutions|works|run|fm|am|cc|ws|one|global|zone|team|help")
HOST_RE = re.compile(r"\b(?:\*\.)?(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:" + TLDS + r")\b", re.I)
IP_RE = re.compile(r"\b(?!127\.0\.0\.1\b)(?:\d{1,3}\.){3}\d{1,3}\b")
WORD_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_\-]*")


def _h(s):
    return int(hashlib.sha1(s.encode("utf-8", "replace")).hexdigest()[:8], 16)


class Scrubber:
    """Real -> fake, stable for the life of the process (and across runs: the pick is a hash of the real
    string, collisions get a numeric suffix). What counts as real is gathered once from disk: every
    program dir under targets/, every label of every host in their SCOPE.txt, every report slug and every
    hunt-lane dir. On top of that, hostnames, URLs, e-mail addresses, non-loopback IPs and anything shaped
    like a secret are replaced by pattern, and a free-text word that is neither an English dictionary word
    nor known tech vocabulary is replaced too (over-scrubbing is the safe failure for a screenshot)."""

    def __init__(self, ws=WS):
        self.ws = ws
        self.map = {}
        self.used = set()
        self.programs, self.deny, self.slugs = set(), set(), set()
        self.safe = set(TECH_SAFE)
        self._memo = {}
        self._load()

    def _load(self):
        tdir = os.path.join(self.ws, "targets")
        for p in (os.listdir(tdir) if os.path.isdir(tdir) else []):
            if not os.path.isdir(os.path.join(tdir, p)):
                continue
            self.programs.add(p.lower())
            self.deny.update(x for x in re.split(r"[-_.]", p.lower()) if x and x not in GENERIC_PARTS and len(x) > 2)
            hunts = os.path.join(tdir, p, "hunts")
            if os.path.isdir(hunts):
                self.slugs.update(h.lower() for h in os.listdir(hunts))
            try:
                for ln in open(os.path.join(tdir, p, "SCOPE.txt"), encoding="utf-8", errors="replace"):
                    for host in HOST_RE.findall(ln):
                        labels = host.lower().lstrip("*.").split(".")
                        self.deny.update(lb for lb in labels[:-1] if lb not in GENERIC_PARTS and len(lb) > 2)
            except OSError:
                pass
        for stage in ("drafts", "submitted", "archive", "leads"):
            root = os.path.join(self.ws, "reports", stage)
            for p in (os.listdir(root) if os.path.isdir(root) else []):
                self.programs.add(p.lower())
                sub = os.path.join(root, p)
                if os.path.isdir(sub):
                    self.slugs.update(s.lower() for s in os.listdir(sub))
        # the plain English dictionary only: password wordlists (wordlist-probable, cracklib) are full of
        # brand names and would whitelist exactly the target names this exists to hide
        for wl in ("/usr/share/dict/words",):
            try:
                words = open(wl, encoding="utf-8", errors="replace").read().split()
            except OSError:
                continue
            # lowercase entries only: capitalised ones are proper nouns (brand and place names among them)
            self.safe.update(w for w in words if w.islower() and w.isalpha())
        # a label or handle part that is an ordinary English word ("review", "lookup", "circle") stays
        # readable; the whole handle still matches self.programs and is always replaced
        self.deny = {x for x in self.deny if x not in self.safe}

    def allow(self, *names):
        """Mark names (model names, pm2 process names) as safe to show: they identify our tools, not a target."""
        before = len(self.safe)
        for n in names:
            for part in re.split(r"[-_.:/@ ]", str(n or "").lower()):
                if part and part not in self.deny and part not in self.programs:
                    self.safe.add(part)
        if len(self.safe) != before:
            self._memo.clear()  # a newly allowed word may change an earlier answer

    def _pick(self, real, pool, kind):
        key = (kind, real.lower())
        if key in self.map:
            return self.map[key]
        base = pool[_h(real.lower()) % len(pool)]
        fake, n = base, 2
        while (kind, fake) in self.used:
            fake, n = f"{base}{n}", n + 1
        self.used.add((kind, fake))
        self.map[key] = fake
        return fake

    def program(self, real):
        return self._pick(real, FAKE_ORGS, "prog")

    def host(self, real):
        labels = real.lower().lstrip("*.").split(".")
        if len(labels) < 2:
            return self.program(real)
        org = self._pick(labels[-2], FAKE_ORGS, "prog")  # same namespace as program names
        subs = ["api", "app", "www", "edge", "portal", "auth", "cdn", "admin", "status", "shop"]
        head = [subs[_h(lb) % len(subs)] for lb in labels[:-2]][:2]
        return ".".join(head + [org, "example"])

    def word(self, real):
        parts = [p for p in re.split(r"[-_]", real) if p]
        if len(parts) <= 1:
            return self._pick(real, CODENAMES, "word")
        a = CODENAMES[_h(real.lower()) % len(CODENAMES)]
        b = CODENAMES[_h(real.lower()[::-1]) % len(CODENAMES)]
        return self._pick(real, [f"{a}-{b}"], "slug")

    def _part_bad(self, part):
        lo = part.lower()
        if not lo or sum(ch.isdigit() for ch in lo) * 2 >= len(lo):
            return False  # dates, times, counts, sizes like 14b or 21T20
        if lo in self.deny or lo in self.programs:
            return True
        if len(lo) <= 2 or lo in self.safe:
            return False
        if lo.endswith("s") and lo[:-1] in self.safe:
            return False
        return True

    def _word(self, m):
        w = m.group(0)
        lo = w.lower()
        if lo in self.programs:
            return self.program(w)
        if lo in self.slugs:
            return self.word(w)
        parts = [p for p in re.split(r"[-_]", w) if p]
        if any(self._part_bad(p) for p in parts):
            return self.program(w) if len(parts) == 1 and lo in self.deny else self.word(w)
        return w

    def text(self, s):
        if not s or not isinstance(s, str):
            return s
        hit = self._memo.get(s)
        if hit is None:
            if len(self._memo) > 20000:
                self._memo.clear()
            hit = self._memo[s] = self._text(s)
        return hit

    def _text(self, s):
        s = SECRET_RE.sub("[hidden]", s)
        s = EMAIL_RE.sub(lambda m: f"user{_h(m.group(0)) % 90 + 10}@example.com", s)
        s = URL_RE.sub(lambda m: "https://" + self.host(HOST_RE.search(m.group(0)).group(0)
                                                       if HOST_RE.search(m.group(0)) else "x.example") + "/...", s)
        s = HOST_RE.sub(lambda m: m.group(0) if m.group(0).endswith(".example") else self.host(m.group(0)), s)
        s = IP_RE.sub("10.0.0.x", s)
        out, last = [], 0
        for m in WORD_RE.finditer(s):
            out.append(s[last:m.start()])
            tok = m.group(0)
            # keep the words this scrubber itself produced
            out.append(tok if tok.endswith("example") or tok == "hidden" else self._word(m))
            last = m.end()
        out.append(s[last:])
        return "".join(out)

    def tree(self, v):
        if isinstance(v, str):
            return self.text(v)
        if isinstance(v, dict):
            return {k: self.tree(x) for k, x in v.items()}  # keys are our own field names, never data
        if isinstance(v, (list, tuple)):
            t = [self.tree(x) for x in v]
            return tuple(t) if isinstance(v, tuple) else t
        return v


# ======================================================================================================
# snapshot: ONE pass per Feed version, both views are drawn from it
# ======================================================================================================

def _copy_feed(feed):
    data = {}
    for k in list(feed.data.keys()):  # a collector thread may assign a key meanwhile; copy what is there
        try:
            data[k] = copy.deepcopy(feed.data[k])
        except Exception:
            data[k] = None
    return data, dict(feed.err)


def _allow_tools(scrub, data):
    names = []
    for m in ((data.get("gpu") or {}).get("models") or []) + ((data.get("desktop") or {}).get("models") or []):
        names.append(m.get("name"))
    names += list(((data.get("gpu") or {}).get("roles") or {}).values())
    names += [p[0] for p in (data.get("services") or {}).get("pm2") or []]
    names += [b[1] for b in (data.get("lab") or {}).get("board") or []]
    names.append((data.get("brain") or {}).get("model"))
    names.append((data.get("lab") or {}).get("model"))
    scrub.allow(*[n for n in names if n])


def _hours_hist(rows, pred, hours=24):
    now = time.time()
    out = [0] * hours
    for r in rows:
        t = g._ts(r.get("ts"))
        if t and 0 <= now - t < hours * 3600 and pred(r):
            out[hours - 1 - int((now - t) // 3600)] += 1
    return out


def translate_row(r, gl):
    """One merged d_changes() row -> (ts, source, text, level). The raw row text keeps the program in front
    ('prog · vector'); only the program survives into the sentence, never the raw vector or reason."""
    kind = r.get("kind") or "CHANGE"
    raw = str(r.get("text") or "")
    who = raw.split(" · ", 1)[0].strip() if " · " in raw else ""
    if kind == "OUTCOME":
        text, level = gl.verdict(r.get("tag"))
    elif kind == "SHIP":
        text, level = gl.ship(r.get("tag") if r.get("tag") not in (None, "", "DRAFT") else "", r.get("ship_kind", "draft"))
    elif kind == "BRAIN":
        act = raw.split(" · ", 1)[0].strip()
        text, level = gl.action(act)
        st_text, st_level = gl.status(r.get("tag"))
        if r.get("tag") not in ("ok", None):
            text, level = f"{text} - {st_text}", st_level if st_level in ("act", "watch") else level
        who = ""
    else:
        text, level = gl.change(kind)
    return {"ts": g._ts(r.get("ts")), "source": gl.source(kind if kind in ("OUTCOME", "SHIP", "BRAIN") else "CHANGE"),
            "kind": kind, "who": who, "text": text, "level": level}


def derive(data, err, gl, now=None):
    """The plain-language facts the Simple view shows. Pure: reads only the copied snapshot data."""
    now = now or time.time()
    h = data.get("hunt") or {}
    s = data.get("system") or {}
    b = data.get("brain") or {}
    o = data.get("oss")
    sv = data.get("services") or {}
    ib = data.get("inbox") or {}
    rp = data.get("reports") or {}
    mt = data.get("metrics") or {}
    gpu = data.get("gpu") or {}
    dk = data.get("desktop") or {}
    pm2 = sv.get("pm2") or []
    pm = {p[0]: p for p in pm2}
    ost = g.oss_state(o, pm2) if o is not None else None
    rv = (o or {}).get("review") or {}

    # ---- the team ----
    team = []
    if b:
        last = max((g._ts(r.get("ts")) or 0 for r in b.get("rows") or []), default=0)
        rate = b["acc"] / b["acc_n"] if b.get("acc_n") else None
        if not b.get("on"):
            team.append(("AI brain", "muted", "switched off, the bot follows fixed rules"))
        elif rate is not None and rate < 0.3:
            team.append(("AI brain", "watch", f"most ideas declined lately ({rate * 100:.0f}% accepted)"))
        else:
            team.append(("AI brain", "ok", f"thinking, last idea {g._dur(now - last)} ago" if last else "on, no ideas yet"))
    bot = pm.get("orch-bot")
    hb = h.get("hb_age")
    if bot is not None and bot[1] != "online":
        team.append(("Hunt bot", "act", "the bot process is not running"))
    elif hb is None:
        team.append(("Hunt bot", "watch", "no check-in from the bot yet"))
    elif hb > 300:
        team.append(("Hunt bot", "act", f"silent for {g._dur(hb)}"))
    else:
        team.append(("Hunt bot", "ok", f"checked in {g._dur(hb)} ago"))
    if ost:
        text, level = gl.oss_state(ost)
        if (o or {}).get("fail_24h"):
            text, level = "a scope safety check failed today", "act"
        n = len((o or {}).get("running") or [])
        team.append(("Scanner", level, text + (f", {n} job{'s' * (n != 1)} running" if ost == "live" and n else "")))
    tun = [p for p in pm2 if any(k in p[0] for k in ("tunnel", "onion", "proxy", "keepalive"))]
    down = [p[0] for p in tun if p[1] != "online"]
    if tun:
        team.append(("Tunnels", "act" if down else "ok", f"{', '.join(down)} down" if down else f"all {len(tun)} connected"))
    if gpu:
        n = len(gpu.get("models") or [])
        team.append(("Local AI", "ok" if gpu.get("up") else "act",
                     (f"{n} model{'s' * (n != 1)} loaded" if n else "ready, loads on first use") if gpu.get("up")
                     else "the local model server is down"))
    if dk:
        n = len(dk.get("models") or [])
        team.append(("Desktop GPU", "ok" if dk.get("up") else "muted",
                     (f"linked, {n} model{'s' * (n != 1)} loaded" if n else "linked") if dk.get("up") else "not linked"))
    if mt:
        hot = [(k, mt.get(f)) for k, f in (("memory", "ram"), ("processor", "cpu")) if g.heat(mt.get(f)) != "ok"]
        if hot:
            k, v = max(hot, key=lambda kv: kv[1] or 0)
            team.append(("This computer", "act" if g.heat(v) == "bad" else "watch", f"{k} {v:.0f}% busy"))
        else:
            team.append(("This computer", "ok", f"processor {mt.get('cpu', 0):.0f}%, memory {mt.get('ram', 0):.0f}%"))

    # ---- what only the operator can do ----
    nxt = []
    if s.get("stop"):
        nxt.append(("resume", "Hunting is paused. This starts it again.", "watch"))
    if ost == "incident":
        nxt.append(("!cat .claude/state/oss-bot/SCOPE-INCIDENTS.md", "The scanner stopped on a scope safety alert. Read it first.", "act"))
    exploit = (ib.get("exploit") or 0)
    if exploit:
        nxt.append(("inbox log", f"{exploit} possible working exploit{'s' * (exploit != 1)} to look at.", "act"))
    ready = rp.get("ready") or 0
    if ready:
        nxt.append(("approve", f"{ready} report{'s' * (ready != 1)} checked and waiting for your OK to file.", "watch"))
    if rv.get("live_open"):
        nxt.append(("chair", f"{rv['live_open']} possibly-live leaked key{'s' * (rv['live_open'] != 1)} need a decision. In the chair, press r to review them.", "watch"))
    if s.get("glock") and (s.get("glock_policy") == "BANNED" or not s.get("glock_ok")):
        nxt.append(("unlock", "The pinned target is not allowed for automatic scanning.", "act"))
    for name, level, why in team:
        if level == "act" and name == "Hunt bot":
            nxt.append(("svc restart orch-bot", f"The hunt bot is not responding ({why}).", "act"))
        elif level == "act" and name == "Tunnels":
            nxt.append(("svc", f"A tunnel is down ({why}).", "act"))
    unread_sig = sum(c for k, c in ib.get("kinds") or [] if g._inbox_rank(k) <= 2)
    if unread_sig and not exploit:
        nxt.append(("inbox log", f"{unread_sig} unread note{'s' * (unread_sig != 1)} worth a look.", "info"))

    errors = sorted(err)
    attention = [x for x in nxt if x[2] in ("act", "watch")]
    if not h and not s:
        state, level = "STARTING", "info"
    elif s.get("stop"):
        state, level = "PAUSED", "watch"
    elif attention:
        state, level = "NEEDS ATTENTION", "act" if any(x[2] == "act" for x in attention) else "watch"
    elif h.get("mode", "off") != "off" or h.get("alive"):
        state, level = "HUNTING", "ok"
    else:
        state, level = "IDLE", "info"
    focus = h.get("focus")
    healthy = not any(lv == "act" for _, lv, _ in team) and not errors
    if state == "STARTING":
        sentence = "Gathering the latest state..."
    elif state == "PAUSED":
        sentence = "Paused by you. Nothing is being scanned."
    elif state == "NEEDS ATTENTION":
        n = len(attention)
        sentence = f"{n} thing{'s' * (n != 1)} need{'s' * (n == 1)} you" + (f", still hunting {focus}" if focus else "")
    elif state == "HUNTING":
        sentence = f"on {focus or 'the next target'} - " + ("everything healthy" if healthy else "running, with a warning")
    else:
        sentence = "Automatic hunting is off. Type orch auto target to start."

    # ---- what it is doing now ----
    cur = h.get("cur") or {}
    rows = b.get("rows") or []
    last = rows[-1] if rows else {}
    if h.get("alive") and cur:
        step = "running a deep-dive investigation"
        since = h.get("cur_start")
        if h.get("quiet") and h["quiet"] > 600:
            step += f" (no new output for {g._dur(h['quiet'])})"
    elif last:
        step = gl.action(last.get("action"))[0]
        since = g._ts(last.get("ts"))
    else:
        step, since = "waiting for the first decision", None
    tot, sw = h.get("total"), h.get("swept") or 0
    frac = (sw / tot) if tot else None
    ph = h.get("per_hour") or []
    rate = sum(ph[-3:]) / 3 if ph else 0
    eta = (tot - sw) / rate * 3600 if tot and rate > 0 and tot > sw else None

    # ---- what we found ----
    changes = data.get("changes") or []
    found = {
        "leads": {"n": (h.get("leads") or 0) + ((o or {}).get("open") or 0), "label": "leads",
                  "spark": _hours_hist(changes, lambda r: r.get("kind") == "OUTCOME" and "LEAD" in str(r.get("tag")).upper())},
        "drafts": {"n": rp.get("drafts"), "label": "drafts",
                   "spark": _hours_hist(changes, lambda r: r.get("kind") == "SHIP")},
        "reviewed": {"n": rp.get("ready"), "label": "reviewed", "spark": []},
        "filed": {"n": rp.get("submitted"), "label": "filed",
                  "spark": _hours_hist(changes, lambda r: r.get("kind") == "SUBMIT")},
        "exploits": {"n": exploit + (h.get("hits") or 0), "label": "exploits",
                     "spark": _hours_hist(changes, lambda r: "CANDIDATE" in str(r.get("tag")).upper())},
    }
    activity = [translate_row(r, gl) for r in changes]
    return {"state": state, "level": level, "sentence": sentence, "focus": focus, "mode": h.get("mode", "off"),
            "parked": h.get("parked"), "step": step, "since": since, "progress": frac, "swept": sw, "total": tot,
            "eta": eta, "found": found, "needs_review": (ready or 0) + (rv.get("live_open") or 0),
            "review_split": [ready or 0, rv.get("live_open") or 0], "team": team,
            "next": nxt, "activity": activity, "errors": errors, "critical": s.get("critical"),
            "high_value": exploit + (h.get("hits") or 0) + (rv.get("live_open") or 0)}


def build_snapshot(feed, gl, demo=False, scrub=None):
    """Copy the Feed once, translate it (derive works on the REAL words, so the glossary sees the raw
    vocabulary), then, in demo mode, scrub BOTH the copied data and the derived facts in one pass. Both
    views read only the returned dict."""
    data, err = _copy_feed(feed)
    simple = derive(data, err, gl)
    if demo:
        _allow_tools(scrub, data)
        scrub.allow(*gl.vocabulary())
        data, err, simple = scrub.tree(data), scrub.tree(err), scrub.tree(simple)
    return {"ver": feed.ver, "built": time.time(), "started": feed.started, "demo": demo, "data": data, "err": err,
            "simple": simple}


class SnapFeed:
    """A Feed-shaped view (data, err, started, ver) over a snapshot, for anything that expects a Feed."""

    def __init__(self, snap):
        self.data, self.err, self.started, self.ver = snap["data"], snap["err"], snap["started"], snap["ver"]


# ======================================================================================================
# look: themes, glyphs, primitives (a subclass of gnoc's Look, so lines()/panel plumbing are shared)
# ======================================================================================================

THEMES = {
    # level colours carry ONE meaning everywhere: ok green, watch amber, act red, info cyan, hilite magenta
    "neon": {"label": "neon-noir", "ok": "#22c55e", "watch": "#f59e0b", "act": "#ef4444", "info": "#22d3ee",
             "hilite": "#e879f9", "text": "#cbd5e1", "muted": "#8391a7", "faint": "#334155", "edge": "#2b4a7e",
             "ink": "#0b0f17", "grad": [(30, 64, 175), (37, 99, 235), (6, 182, 212), (34, 211, 238), (167, 139, 250)]},
    "contrast": {"label": "high-contrast", "ok": "#00ff5f", "watch": "#ffd700", "act": "#ff4d4d", "info": "#00ffff",
                 "hilite": "#ff66ff", "text": "#ffffff", "muted": "#d7d7d7", "faint": "#9e9e9e", "edge": "#ffffff",
                 "ink": "#000000", "grad": [(255, 255, 255), (0, 255, 255), (255, 255, 255)]},
    "mono": {"label": "mono", "mono": True, "grad": [(255, 255, 255), (255, 255, 255)]},
}
LEVELS = ("ok", "watch", "act", "info", "hilite", "text", "muted", "faint")

GLYPHS_UNI = {"dot": "●", "ring": "○", "diamond": "◆", "spin": "◐◓◑◒", "ok": "✓", "bad": "✗", "fb": "↺", "wait": "…",
              "arrow": "▸", "spark": " ▁▂▃▄▅▆▇█", "full": "█", "part": " ▏▎▍▌▋▊▉", "hr": "─", "heavy": "━",
              "more": "⋯", "sep": "·", "clock": "◷", "star": "★", "up": "▲"}
GLYPHS_ASCII = {"dot": "*", "ring": "o", "diamond": "#", "spin": "|/-\\", "ok": "+", "bad": "x", "fb": "~", "wait": ".",
                "arrow": ">", "spark": " .,:-=+*#", "full": "#", "part": " ", "hr": "-", "heavy": "=", "more": "...",
                "sep": "|", "clock": "@", "star": "!", "up": "^"}


def detect_caps(env=None):
    """(color, unicode): color in mono|256|truecolor. NO_COLOR or TERM=dumb -> mono; a non-UTF-8 locale or
    GNOC_ASCII=1 -> ASCII glyphs."""
    env = os.environ if env is None else env
    term = env.get("TERM", "")
    if "NO_COLOR" in env or term == "dumb":
        color = "mono"
    elif env.get("COLORTERM", "").lower() in ("truecolor", "24bit") or env.get("GNOC_TRUECOLOR") == "1":
        color = "truecolor"
    else:
        color = "256"
    # POSIX precedence: the first non-empty of LC_ALL, LC_CTYPE, LANG decides. sys.stdout.encoding is no
    # help (Python coerces a C locale to UTF-8 output); with no locale set at all, assume a UTF-8 terminal.
    loc = next((env[k] for k in ("LC_ALL", "LC_CTYPE", "LANG") if env.get(k)), None)
    utf = True if loc is None else ("utf" in loc.lower().replace("-", ""))
    uni = env.get("GNOC_ASCII") != "1" and term != "dumb" and utf
    return color, uni


def _rgb(hexs):
    hexs = (hexs or "#ffffff").lstrip("#")
    return tuple(int(hexs[i:i + 2], 16) for i in (0, 2, 4))


class DashLook(g.Look):
    """gnoc's Look, extended: theme-aware colours, ASCII/Unicode glyph sets, the radar, big digits, a fitter that
    says what it cut. Everything returns Rich Text lines; self.lines() turns a renderable into exact-width ANSI."""

    def __init__(self, theme="neon", caps=None):
        super().__init__()
        import io
        from rich.console import Console
        color, uni = caps or detect_caps()
        self.mono = color == "mono" or theme == "mono"
        self.theme_name = "mono" if self.mono else theme
        self.th = THEMES[self.theme_name]
        self.uni = uni
        self.G = GLYPHS_UNI if uni else GLYPHS_ASCII
        self.con = Console(file=io.StringIO(), force_terminal=True, color_system="truecolor" if color == "truecolor" else "256",
                           no_color=self.mono, width=100, highlight=False, markup=False, emoji=False, soft_wrap=False,
                           legacy_windows=False)
        self.boxes = {"round": self.box.ROUNDED if uni else self.box.ASCII,
                      "double": self.box.DOUBLE if uni else self.box.ASCII_DOUBLE_HEAD,
                      "heavy": self.box.HEAVY if uni else self.box.ASCII2}

    # one character in, one character out: the frame was laid out in cells, a wider replacement would overflow it
    ASCII_MAP = str.maketrans({"·": "|", "…": ".", "—": "-", "–": "-", "→": ">", "←": "<", "×": "x", "’": "'",
                               "‘": "'", "“": '"', "”": '"', "•": "*", "≥": ">", "≤": "<", "°": "o"})

    def lines(self, renderable, width):
        """gnoc's Look.lines, plus a final ASCII pass on non-UTF-8 terminals: collector text (gnoc's own
        'prog · vector' rows, model output) may carry any character, and mojibake is worse than '?'."""
        out = super().lines(renderable, width)
        if self.uni:
            return out
        return ["".join(ch if ord(ch) < 128 else "?" for ch in ln.translate(self.ASCII_MAP)) for ln in out]

    # ----- styles -----
    def S(self, level="text", bold=False, italic=False, reverse=False):
        parts = (["bold"] if bold else []) + (["italic"] if italic else []) + (["reverse"] if reverse else [])
        if not self.mono:
            parts.append(self.th.get(level, level) if level in LEVELS or level == "edge" else level)
        return " ".join(parts) or "none"

    def col(self, level):
        return None if self.mono else self.th.get(level)

    def mix(self, level, white=0.0, dimf=1.0):
        if self.mono:
            return "none"
        return g._hex(_rgb(self.th[level]), mix_white=white, dimf=dimf)

    def chip(self, label, level, pulse=None):
        """A filled badge. pulse in [0,1] breathes the fill; mono uses reverse video."""
        if self.mono:
            return (f" {label} ", "bold reverse")
        bg = self.th[level] if pulse is None else g._hex(_rgb(self.th[level]), dimf=0.55 + 0.45 * pulse)
        return (f" {label} ", f"bold {self.th['ink']} on {bg}")

    def T(self, *parts):
        t = self.Text(no_wrap=True, overflow="ellipsis" if self.uni else "crop")
        for p in parts:
            if isinstance(p, tuple):
                t.append(str(p[0]), style=p[1] or "none")
            elif isinstance(p, self.Text):
                t.append_text(p)
            elif p:
                t.append(str(p))
        return t

    # ----- primitives -----
    def bar(self, frac, width, level="info", grad=False):
        frac = min(1.0, max(0.0, frac or 0.0))
        width = max(1, width)
        t = self.Text(no_wrap=True)
        if not self.uni or self.mono:
            full = int(round(frac * width))
            t.append(self.G["full"] * full, style=self.S(level, bold=True))
            t.append(("-" if not self.uni else "░") * (width - full), style=self.S("faint"))
            return t
        eighths = int(round(frac * width * 8))
        full, part = divmod(eighths, 8)
        grad_rgb = self.th["grad"]
        for i in range(full):
            if grad:
                x = (0.25 + 0.75 * i / max(1, width)) * (len(grad_rgb) - 1)
                k = min(len(grad_rgb) - 2, int(x))
                f = x - k
                a, b = grad_rgb[k], grad_rgb[k + 1]
                t.append("█", style=g._hex(tuple(int(a[j] + (b[j] - a[j]) * f) for j in range(3))))
            else:
                t.append("█", style=self.th[level])
        if full < width:
            t.append(self.G["part"][part] if part else " ", style=f"{self.th[level]} on {self.th['faint']}")
            t.append(" " * (width - full - 1), style=f"on {self.th['faint']}")
        return t

    def spark(self, vals, width):
        vals = list(vals or [])[-max(1, width):]
        if not vals:
            return ""
        hi = max(vals)
        sp = self.G["spark"]
        top = len(sp) - 1
        return "".join(sp[0] if v <= 0 or hi <= 0 else sp[min(top, max(1, round(v / hi * top)))] for v in vals)

    def spark_text(self, vals, width, level):
        """A sparkline whose empty hours show as a faint baseline, so a quiet day still reads as a line."""
        vals = list(vals or [])[-max(1, width):]
        t = self.Text(no_wrap=True)
        hi = max(vals) if vals else 0
        sp = self.G["spark"]
        for v in vals:
            if v <= 0 or hi <= 0:
                t.append(sp[1], style=self.S("faint"))
            else:
                t.append(sp[min(len(sp) - 1, max(1, round(v / hi * (len(sp) - 1))))], style=self.S(level, bold=True))
        return t

    def chart(self, vals, cols, rows, level, lo=None, hi=None, label=None, label_style=None):
        """Braille line chart (2x4 dots per cell); on an ASCII terminal a row-quantised '*' plot."""
        cols, rows = max(4, cols), max(1, rows)
        if self.uni:
            rws = g.braille_lines(list(vals or [0]), cols, rows, lo, hi)
        else:
            vs = list(vals or [0])
            lo_ = min(vs) if lo is None else lo
            hi_ = max(vs) if hi is None else hi
            span = (hi_ - lo_) or 1
            grid = [[" "] * cols for _ in range(rows)]
            for x in range(cols):
                v = vs[min(len(vs) - 1, round(x / max(1, cols - 1) * (len(vs) - 1)))]
                y = rows - 1 - min(rows - 1, max(0, int((v - lo_) / span * rows - 1e-9)))
                grid[y][x] = "*"
            rws = ["".join(r) for r in grid]
        out = [self.T((r, self.S(level))) for r in rws]
        if label:
            out[-1] = self.T((rws[-1], self.S(level)), ("  " + label, label_style or self.S("muted")))
        return out

    def frame(self, title, body, width, height=None, level="info", subtitle=None, kind="round", key=None):
        """A panel: rounded (or double when focused) frame whose EDGE carries the section's level colour."""
        head = self.Text(no_wrap=True)
        if key:
            head.append(f" {key}", style=self.S("muted"))
        head.append(f" {self.G['diamond']} ", style=self.S(level, bold=True))
        head.append(title + " ", style=self.S("text", bold=True))
        sub = self.Text(f" {subtitle} ", style=self.S("muted")) if subtitle else None
        edge = "none" if self.mono else g._hex(_rgb(self.th[level]), dimf=0.62 if self.theme_name == "neon" else 1.0)
        return self.Panel(self.Group(*body) if body else self.Text(""), title=head, title_align="left", subtitle=sub,
                          subtitle_align="right", box=self.boxes[kind], border_style=edge, width=width, height=height,
                          padding=(0, 1))

    def block(self, title, body, width, height, level="info", subtitle=None, kind="round", key=None, mode="head"):
        """frame() rendered to exactly `height` ANSI lines of `width` columns, body fitted with a cut marker."""
        inner = max(1, height - 2)
        body = self.fit(body, inner, mode, key)
        out = self.lines(self.frame(title, body, width, height, level, subtitle, kind, key), width)[:height]
        return out + [" " * width] * (height - len(out))

    def fit(self, lines, h, mode="head", key=None):
        """Never a silent cut: when content is longer than h rows, the last (or first) row says how much is hidden."""
        if len(lines) <= h:
            return list(lines)
        if h <= 1:
            return [self.T((f"{self.G['more']} {len(lines)} rows" + (f", {key} zooms" if key else ""), self.S("muted", italic=True)))]
        more = len(lines) - (h - 1)
        tip = f"  {self.G['more']} +{more} {'more' if mode == 'head' else 'earlier'}" + (f" {self.G['sep']} press {key} to zoom" if key else "")
        marker = self.T((tip, self.S("muted", italic=True)))
        return lines[:h - 1] + [marker] if mode == "head" else [marker] + lines[-(h - 1):]

    def bigdigits(self, s, level, bold=True):
        """A count drawn in gnoc's 3-row seven-segment face (Unicode) or as plain bold text (ASCII)."""
        if not self.uni:
            return [self.T(""), self.T((s, self.S(level, bold=True))), self.T("")]
        rows = []
        for r in range(3):
            line = self.Text(no_wrap=True)
            for k, ch in enumerate(s):
                gap = " " if k < len(s) - 1 else ""
                line.append(g.DIGITS.get(ch, g.DIGITS[" "])[r] + gap, style=self.S(level, bold=bold))
            rows.append(line)
        return rows

    def wordmark(self, t, shimmer=True, scan=True):
        """gnoc's GREYNOC wordmark, extended: the theme's gradient, the same diagonal glint, plus a slow CRT
        scanline that walks down the letters. ASCII terminals get the spaced small mark instead."""
        if not self.uni:
            return [self.small_mark(t)]
        lw = len(g.LOGO[0])
        glint = (t * 1.6) % (lw + 50) - 25
        scan_row = (t / 3.0) % (len(g.LOGO) + 6) - 3
        grad = self.th["grad"]
        rows = []
        for r, text in enumerate(g.LOGO):
            line = self.Text(no_wrap=True)
            sl = max(0.0, 1 - abs(r - scan_row)) * 0.35 if scan else 0.0
            for colno, ch in enumerate(text):
                if ch == " ":
                    line.append(" ")
                    continue
                if self.mono:
                    line.append(ch, style="bold" if ch == "█" else "none")
                    continue
                x = colno / lw * (len(grad) - 1)
                k = min(len(grad) - 2, int(x))
                f = x - k
                base = tuple(int(grad[k][j] + (grad[k + 1][j] - grad[k][j]) * f) for j in range(3))
                d = abs(colno - r * 1.5 - glint) if shimmer else 99
                if ch == "█":
                    w = max(0.0, 1 - d / 5) ** 2 * 0.85
                    line.append(ch, style=g._hex(base, mix_white=min(1.0, w + sl)))
                else:
                    line.append(ch, style=g._hex(base, dimf=0.42 + 0.25 * max(0.0, 1 - d / 6) + sl * 0.5))
            rows.append(line)
        return rows

    def small_mark(self, t):
        word = "G R E Y N O C"
        line = self.Text(no_wrap=True)
        glint = (t * 0.8) % (len(word) + 14) - 7
        grad = self.th["grad"]
        for i, ch in enumerate(word):
            if self.mono:
                line.append(ch, style="bold")
                continue
            x = i / len(word) * (len(grad) - 1)
            k = min(len(grad) - 2, int(x))
            base = tuple(int(grad[k][j] + (grad[k + 1][j] - grad[k][j]) * (x - k)) for j in range(3))
            line.append(ch, style="bold " + g._hex(base, mix_white=max(0.0, 1 - abs(i - glint) / 3) * 0.8))
        return line

    def scan_rule(self, t, width):
        line = self.Text(no_wrap=True)
        ch = self.G["heavy"]
        if self.mono:
            line.append(ch * width, style="none")
            return line
        head = (t * 2.2) % (width + 30) - 15
        rgb = _rgb(self.th["info"])
        for i in range(width):
            d = head - i
            line.append(ch, style=g._hex(rgb, mix_white=0.75 * (1 - d / 14)) if 0 <= d < 14 else g._hex(rgb, dimf=0.32))
        return line

    def radar(self, cols, rows, t, blips, live):
        """The OSS-BOT sonar: a sweeping beam with a phosphor-fade trail over a ring, a half ring and a dotted
        crosshair; blips are scanner jobs (magenta = running, amber = found leads, red = audit failure) placed by
        a hash of their name and lit when the beam passes. Braille (2x4 dots per cell, so the scope is round),
        or a character-density scope on ASCII terminals. Paused/stopped = a dim scope with no beam."""
        sub_x, sub_y = (2, 4) if self.uni else (1, 1)
        aspect = 1.0 if self.uni else 2.0  # an ASCII cell is twice as tall as it is wide
        W, H = cols * sub_x, rows * sub_y
        cx, cy = (W - 1) / 2, (H - 1) / 2
        R = min(cx, cy * aspect)
        beam = (time.time() * 1.7) % (2 * math.pi) if t else 0.0  # time-based: smooth at any redraw cadence
        inten = [[0.0] * cols for _ in range(rows)]
        bits = [[0] * cols for _ in range(rows)]
        hot = [[None] * cols for _ in range(rows)]
        for y in range(H):
            for x in range(W):
                dx, dy = x - cx, (y - cy) * aspect
                r = math.hypot(dx, dy)
                if r > R + 0.35:
                    continue
                a = math.atan2(dy, dx) % (2 * math.pi)
                behind = (beam - a) % (2 * math.pi)
                v = 0.0
                if abs(r - R) < 0.6:
                    v = 0.42
                elif abs(r - R * 0.5) < 0.45 and (x + y) % 2 == 0:
                    v = 0.2
                elif (abs(dx) < 0.5 or abs(dy) < 0.5 * aspect) and (x + y) % 3 == 0:
                    v = 0.16
                if live:
                    if behind < 0.12 and r <= R:
                        v = 1.0
                    elif behind < 1.7:
                        f = (1 - behind / 1.7) ** 2
                        if ((x * 73856093 ^ y * 19349663) % 97) / 97 < f * 0.8:
                            v = max(v, 0.25 + 0.65 * f)
                if v <= 0:
                    continue
                cxl, cyl = x // sub_x, y // sub_y
                if self.uni:
                    bits[cyl][cxl] |= g._BRAILLE_BITS[y % 4][x % 2]
                inten[cyl][cxl] = max(inten[cyl][cxl], v)
        for ang, rf, level in blips:
            bx, by = cx + math.cos(ang) * rf * R, cy + math.sin(ang) * rf * R / aspect
            glow = math.exp(-((beam - ang) % (2 * math.pi)) / 2.2) if live else 0.45
            for ox in (0, 1) if self.uni else (0,):
                for oy in (0, 1) if self.uni else (0,):
                    x, y = int(round(bx)) + ox, int(round(by)) + oy
                    if 0 <= x < W and 0 <= y < H:
                        cxl, cyl = x // sub_x, y // sub_y
                        if self.uni:
                            bits[cyl][cxl] |= g._BRAILLE_BITS[y % 4][x % 2]
                        hot[cyl][cxl] = (level, glow)
        out = []
        dens = " .:-=+*#%@"
        for ry in range(rows):
            line = self.Text(no_wrap=True)
            for rx in range(cols):
                v, h_ = inten[ry][rx], hot[ry][rx]
                if self.uni:
                    ch = chr(0x2800 + bits[ry][rx]) if bits[ry][rx] else " "
                else:
                    ch = "@" if h_ else (dens[min(len(dens) - 1, int(v * (len(dens) - 1) + 0.5))] if v else " ")
                if h_:
                    level, glow = h_
                    st = "bold" if self.mono else "bold " + self.mix(level, white=0.55 * glow, dimf=0.6 + 0.4 * glow)
                elif self.mono:
                    st = "bold" if v >= 0.9 else "none"
                elif self.theme_name == "contrast":
                    st = self.th["info"] if v >= 0.5 else self.th["faint"]
                else:
                    st = self.mix("info", white=0.5 if v >= 0.99 else 0.0, dimf=0.18 + 0.82 * v)
                line.append(ch, style=st)
            out.append(line)
        return out


def hjoin(blocks, widths):
    """Side-by-side ANSI line blocks (each already exactly its width), padded to the tallest."""
    h = max(len(b) for b in blocks)
    return ["".join(b[i] if i < len(b) else " " * w for b, w in zip(blocks, widths)) for i in range(h)]


def split_w(width, fracs):
    ws = [int(width * f) for f in fracs]
    ws[-1] = width - sum(ws[:-1])
    return ws


def _ago(ts, now=None):
    if not ts:
        return ""
    return g._dur((now or time.time()) - ts) + " ago"


def _when(ts, now=None):
    """A 5-cell local time for a table column: HH:MM today, MM-DD on any earlier day (a bare 01:31 from
    yesterday read as later than now). Always the viewer's local timezone."""
    if not ts:
        return "--:--"
    d = datetime.fromtimestamp(ts).astimezone()
    today = datetime.fromtimestamp(now or time.time()).astimezone().date()
    return d.strftime("%H:%M") if d.date() == today else d.strftime("%m-%d")


ISO_LEAD_RE = re.compile(r"^\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\]")


def local_log_line(ln, now=None):
    """orch.log stores '[2026-10-22T04:18:14Z] ...'; show that stamp in local time, keep the rest verbatim."""
    m = ISO_LEAD_RE.match(ln)
    ts = g._ts(m.group(1)) if m else None
    if not ts:
        return ln
    d = datetime.fromtimestamp(ts).astimezone()
    today = datetime.fromtimestamp(now or time.time()).astimezone().date()
    return "[" + d.strftime("%H:%M:%S" if d.date() == today else "%m-%d %H:%M:%S") + "]" + ln[m.end():]


def _run_when(run):
    """Model Lab run ids start with a UTC stamp (lab.py: 20261021T015951-<model>); render it local."""
    try:
        ts = datetime.strptime(str(run)[:15], "%Y%m%dT%H%M%S").replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return ""
    return datetime.fromtimestamp(ts).astimezone().strftime("%m-%d %H:%M")


def _clip(s, n, lk=None):
    """Cut to n cells with an ellipsis (ASCII '~' on a non-UTF-8 terminal), never a silent crop."""
    s = str(s)
    if len(s) <= n:
        return s
    return s[:max(0, n - 1)] + ("…" if lk is None or lk.uni else "~")


# ======================================================================================================
# shared header pieces
# ======================================================================================================

def clock_ribbon(lk, snap, t, compact=False):
    local = datetime.now().astimezone()  # the whole dashboard renders in the viewer's local time; disk/logs stay UTC
    blink = ":" if (t // 10) % 2 == 0 or lk.mono else " "  # frame-driven (10 fps): a --once frame (t=0) always shows colons
    if compact:
        return lk.T((lk.G["clock"] + " ", lk.S("info")), (local.strftime(f"%H{blink}%M{blink}%S"), lk.S("info", bold=True)),
                    (f" {local:%Z}", lk.S("muted")))
    return lk.T((lk.G["clock"] + " ", lk.S("info")), (local.strftime(f"%H{blink}%M{blink}%S"), lk.S("info", bold=True)),
                (f"  {local:%a %d %b %Y}", lk.S("text")), (f"  {lk.G['sep']} {local:%Z}", lk.S("muted")))


def uptime_ribbon(lk, snap):
    sv = snap["data"].get("services") or {}
    bot = next((p[2] for p in sv.get("pm2") or [] if p[0] == "orch-bot" and p[1] == "online" and p[2]), None)
    parts = []
    if sv.get("host_up"):
        parts += [("host up ", lk.S("muted")), (g._dur(sv["host_up"]), lk.S("text"))]
    if bot:
        parts += [(f"  {lk.G['sep']} bot up ", lk.S("muted")), (g._dur(time.time() - bot / 1000), lk.S("text"))]
    parts += [(f"  {lk.G['sep']} watching ", lk.S("muted")), (g._dur(time.time() - snap["started"]), lk.S("text"))]
    return lk.T(*parts)


def state_badge(lk, S, t, flash):
    glyph = lk.G["dot"] if (t // 5) % 2 == 0 or not lk.mono else lk.G["ring"]
    pulse = 0.5 + 0.5 * math.sin(t * 0.35) if S["state"] == "HUNTING" else None
    parts = [lk.chip(f"{glyph} {S['state']}", S["level"], pulse)]
    if flash:
        on = (t // 3) % 2 == 0
        parts += [" ", lk.chip(f"{lk.G['star']} NEW {flash}", "act" if on else "hilite")]
    return parts


# ======================================================================================================
# SIMPLE view
# ======================================================================================================

FOUND_ORDER = (("leads", "hilite"), ("drafts", "info"), ("reviewed", "watch"), ("filed", "ok"), ("exploits", "act"))
TEAM_SHORT = {"AI brain": "brain", "Hunt bot": "bot", "Scanner": "scanner", "Tunnels": "tunnels", "Local AI": "local AI",
              "Desktop GPU": "desktop", "This computer": "computer"}


class Simple:
    def __init__(self, app):
        self.app = app

    def header(self, lk, snap, width, big, t):
        S = snap["simple"]
        flash = self.app.flash_text()
        if big and lk.uni and width >= len(g.LOGO[0]) + 50:
            lw0 = len(g.LOGO[0])
            phase = (int(((t * 1.6) % (lw0 + 50)) * 2), int(((t / 3.0) % (len(g.LOGO) + 6)) * 4))
            mark = self.app.cached(("mark", phase), (id(lk), phase),
                                   lambda: [lk.lines(r, lw0)[0] for r in lk.wordmark(t)], keep=True)
            lw = len(g.LOGO[0])
            iw = width - lw - 6
            sent = S["sentence"]
            cut = sent if len(sent) <= iw else sent[:sent.rfind(" ", 0, iw) if " " in sent[:iw] else iw]
            rest = sent[len(cut):].strip()
            meta = [(f"view simple {lk.G['sep']} theme {THEMES[lk.theme_name]['label']}", lk.S("faint" if not lk.mono else "muted"))]
            if snap["demo"]:
                meta = [lk.chip("DEMO", "hilite"), ("  ", "")] + meta
            info = [lk.T(*state_badge(lk, S, t, flash)),
                    lk.T((cut, lk.S("text", bold=True))),
                    lk.T((rest, lk.S("text", bold=True))),
                    clock_ribbon(lk, snap, t),
                    uptime_ribbon(lk, snap),
                    lk.T(*meta)]
            infow = max(x.cell_len for x in info)
            lead = max(2, (width - lw - 4 - infow) // 2) if width >= 150 else 2
            iw = max(1, width - lead - lw - 4)
            rows = [" " * lead + m + "    " + lk.lines(info[r], iw)[0] for r, m in enumerate(mark)]
            return rows + [lk.lines(lk.scan_rule(t, width), width)[0]]
        demo = [lk.chip("DEMO", "hilite"), " "] if snap["demo"] else []  # first line: never cut off a narrow screen
        top = lk.T(" ", lk.small_mark(t), "  ", *demo, *state_badge(lk, S, t, flash), ("  " + S["sentence"], lk.S("text", bold=True)))
        second = lk.T(" ", clock_ribbon(lk, snap, t, compact=width < 100), ("   ", ""), uptime_ribbon(lk, snap))
        return [lk.lines(top, width)[0], lk.lines(second, width)[0], lk.lines(lk.scan_rule(t, width), width)[0]]

    def now(self, lk, S, w, t):
        mode = {"target": "the bot picks targets by itself", "program": "pinned to this target",
                "off": "automatic hunting is off"}.get(S["mode"], "")
        out = [lk.T(("Target   ", lk.S("muted")), (S["focus"] or "none yet", lk.S("info", bold=True) if S["focus"] else lk.S("muted")),
                    ("  parked" if S.get("parked") else "", lk.S("watch")), (f"   {mode}", lk.S("muted")))]
        spin = lk.G["spin"][t // 3 % len(lk.G["spin"])]
        out.append(lk.T(("Doing    ", lk.S("muted")), (spin + " ", lk.S("ok")), (S["step"], lk.S("text")),
                        (f"   started {_ago(S['since'])}" if S.get("since") else "", lk.S("muted"))))
        if S.get("total"):
            frac = self.app.ease("progress", S["progress"] or 0)
            eta = f" {lk.G['sep']} about {g._dur(S['eta'])} left" if S.get("eta") else ""
            label = f"  {S['swept']} of {S['total']} hosts {lk.G['sep']} {S['progress'] * 100:.0f}% done{eta}"
            out.append(lk.T(("Progress ", lk.S("muted")), lk.bar(frac, max(8, w - 9 - len(label)), "info", grad=True),
                            (label, lk.S("text", bold=True))))
        else:
            out.append(lk.T(("Progress ", lk.S("muted")), ("measuring how many hosts this target has...", lk.S("muted"))))
        return out

    def found(self, lk, S, w, big, t):
        cw = max(8, w // len(FOUND_ORDER))
        flash = self.app.flash_until > time.time()
        cells = []
        for key, level in FOUND_ORDER:
            f = S["found"][key]
            n = f["n"]
            lv = level if n else "muted"
            s = "…" if n is None else str(n)
            lit = flash and key == "exploits" and (t // 3) % 2 == 0
            if big and lk.uni and len(s) * 4 - 1 <= cw - 1:
                digits = lk.bigdigits(s, "act" if lit else lv)
                cells.append([lk.T((f["label"], lk.S("muted")))] + digits + [lk.spark_text(f["spark"], cw - 2, level)])
            elif big:  # same row order as the big cell (label, three digit rows, spark) so the row reads level
                cells.append([lk.T((f["label"], lk.S("muted"))), lk.T(""), lk.T((s, lk.S(lv, bold=True, reverse=lit))), lk.T(""),
                              lk.spark_text(f["spark"], cw - 2, level)])
            else:
                cells.append([lk.T((s, lk.S(lv, bold=True, reverse=lit))), lk.T((f["label"], lk.S("muted")))])
        rows = []
        for i in range(max(len(c) for c in cells)):
            line = lk.Text(no_wrap=True)
            for c in cells:
                cell = c[i] if i < len(c) else lk.T("")
                pad = max(0, cw - cell.cell_len)
                line.append(" " * (pad // 2))
                line.append_text(cell)
                line.append(" " * (pad - pad // 2))
            rows.append(line)
        nr = S["needs_review"]
        # the total mixes two queues with two different doors; name both so "approve" is never shown for leaked keys
        rd, keys = S.get("review_split") or [nr, 0]
        how = [f"{rd} to file: type approve"] if rd else []
        how += [f"{keys} key{'s' * (keys != 1)}: chair, r"] if keys else []
        rows.append(lk.T(*([lk.chip(f"needs your review: {nr}", "hilite"), ("  " + f" {lk.G['sep']} ".join(how), lk.S("muted"))]
                           if nr else [(lk.G["ok"] + " nothing is waiting for your review", lk.S("ok"))])))
        return rows

    def team(self, lk, S, w, compact):
        if compact:
            parts = []
            for name, level, _ in S["team"]:
                parts += [(lk.G["dot"] + " ", lk.S(level, bold=True)), (TEAM_SHORT.get(name, name) + "  ", lk.S("text" if level == "ok" else level))]
            bad = [(n, lv, why) for n, lv, why in S["team"] if lv in ("act", "watch")]
            line = lk.T(*parts) if parts else lk.T(("checking...", lk.S("muted")))
            out = [line]
            for n, lv, why in bad[:1]:
                note = lk.T((f"{lk.G['sep']} {why}", lk.S(lv)))
                if line.cell_len + note.cell_len <= w:
                    line.append_text(note)
                else:
                    out.append(lk.T((f"  {n}: {why}", lk.S(lv))))
            return out
        out = []
        nw = max((len(n) for n, _, _ in S["team"]), default=8) + 2
        for name, level, why in S["team"]:
            out.append(lk.T((lk.G["dot"] + " ", lk.S(level, bold=True)), (f"{name:<{nw}}", lk.S("text", bold=True)),
                            ("ok  " if level == "ok" else "", lk.S("ok")),
                            (why, lk.S("muted") if level in ("ok", "muted") else lk.S(level))))
        return out or [lk.T(("checking on everyone...", lk.S("muted")))]

    def activity(self, lk, S, w):
        out, prev, count = [], None, 0
        rows = []
        for a in S["activity"]:
            key = (a["text"], a["who"])
            if rows and key == prev:
                rows[-1][1] += 1
                continue
            rows.append([a, 1])
            prev = key
        for a, n in rows:
            out.append(lk.T((f"{_ago(a['ts']):>9}  " if a["ts"] else " " * 11, lk.S("muted")),
                            (lk.G["dot"] + " ", lk.S(a["level"], bold=True)),
                            (a["text"], lk.S("text" if a["level"] in ("muted", "info") else a["level"])),
                            (f"  {a['who']}" if a["who"] else "", lk.S("info")),
                            (f"  x{n}" if n > 1 else "", lk.S("muted", bold=True))))
        return out or [lk.T(("nothing has happened yet", lk.S("muted")))]

    def next(self, lk, S, w):
        """Returns (rows, clicks): clicks maps a row index (into `rows`, before any block-height
        truncation) to the exact command a click on that row should fill into the input box - the
        same string the row's own 'type <cmd> then Enter' hint already names."""
        out, clicks = [], {}
        import textwrap
        for cmd, text, level in S["next"]:
            for k, part in enumerate(textwrap.wrap(text, max(10, w - 2))[:2]):
                out.append(lk.T((lk.G["arrow"] + " " if k == 0 else "  ", lk.S(level, bold=True)), (part, lk.S("text"))))
            clicks[len(out)] = cmd
            out.append(lk.T(("    type ", lk.S("muted")), (cmd, lk.S("info", bold=True)), ("  then Enter", lk.S("muted"))))
        if not out:
            out.append(lk.T((lk.G["ok"] + " Nothing needs you right now.", lk.S("ok", bold=True))))
        out.append(lk.T(("    Tab ", lk.S("info", bold=True)), ("technical view   ", lk.S("muted")),
                        ("t ", lk.S("info", bold=True)), ("theme   ", lk.S("muted")),
                        ("Ctrl-D ", lk.S("info", bold=True)), ("demo", lk.S("muted"))))
        return out, clicks

    @staticmethod
    def _next_hits(row0, x0, w, h, clicks):
        """Hit regions for one placed next()/NEEDS block: row0 is the block's own first screen row
        (its top border), x0/w the CONTENT column range already passed to next(), h the block's
        full height (border included). Mirrors DashLook.fit()'s head-mode truncation so a hit is
        only registered for a row that is actually still visible once the panel cuts overflow."""
        inner = max(0, h - 2)
        return [(row0 + 1 + idx, x0, x0 + w, cmd) for idx, cmd in clicks.items() if idx < inner]

    def render(self, lk, snap, width, height, t):
        big = width >= 110 and height >= 34
        head = self.header(lk, snap, width, big, t)
        key = ("simple", id(lk), self.app.snap_key, width, height, len(head), bool(self.app.flash_text()), t // 3)
        body, hits = self.app.cached("simple-body", key, lambda: self.body(lk, snap, width, height - len(head), big, t))
        self.app.hits = [(row0 + len(head), x0, x1, cmd) for row0, x0, x1, cmd in hits]
        return (head + body + [""] * height)[:height]

    def body(self, lk, snap, width, room, big, t):
        S = snap["simple"]
        out, hits = [], []
        tl = lk.S("act") if S["level"] == "act" else None
        team_level = "act" if any(lv == "act" for _, lv, _ in S["team"]) else "watch" if any(lv == "watch" for _, lv, _ in S["team"]) else "ok"
        now_h = 5
        if width >= 100:
            found_h = 9 if room >= now_h + 9 + 8 else 6
            fw, tw = split_w(width, (0.56, 0.44))
            team_h = max(found_h, min(len(S["team"]) + 2, room - now_h - 6))
            rest = room - now_h - team_h
            out += lk.block("WHAT IT IS DOING NOW", self.now(lk, S, width - 4, t), width, now_h, "info",
                            subtitle=S["focus"] or "")
            out += hjoin([lk.block("WHAT WE HAVE FOUND", self.found(lk, S, fw - 4, found_h >= 9, t), fw, team_h, "hilite"),
                          lk.block("IS THE TEAM OK", self.team(lk, S, tw - 4, False), tw, team_h, team_level)], [fw, tw])
            if rest >= 3:
                row0 = len(out)
                next_rows, next_clicks = self.next(lk, S, tw - 4)
                out += hjoin([lk.block("RECENT ACTIVITY", self.activity(lk, S, fw - 4), fw, rest, "info", subtitle="plain English"),
                              lk.block("WHAT'S NEXT / NEEDS YOU", next_rows, tw, rest,
                                       "act" if tl else "hilite", kind="double" if S["next"] else "round")], [fw, tw])
                hits += self._next_hits(row0, fw + 2, tw - 4, rest, next_clicks)
        else:
            found_h = 5
            team_h = 2 + len(self.team(lk, S, width - 4, True))
            rest = room - now_h - found_h - team_h
            out += lk.block("DOING NOW", self.now(lk, S, width - 4, t), width, now_h, "info")
            out += lk.block("FOUND", self.found(lk, S, width - 4, False, t), width, found_h, "hilite")
            out += lk.block("TEAM", self.team(lk, S, width - 4, True), width, team_h, team_level)
            if rest >= 3:
                row0 = len(out)
                if width >= 70:
                    aw, nw = split_w(width, (0.52, 0.48))
                    next_rows, next_clicks = self.next(lk, S, nw - 4)
                    out += hjoin([lk.block("RECENT", self.activity(lk, S, aw - 4), aw, rest, "info"),
                                  lk.block("NEEDS YOU", next_rows, nw, rest, "act" if tl else "hilite")], [aw, nw])
                    hits += self._next_hits(row0, aw + 2, nw - 4, rest, next_clicks)
                else:
                    next_rows, next_clicks = self.next(lk, S, width - 4)
                    out += lk.block("NEEDS YOU", next_rows, width, rest, "act" if tl else "hilite")
                    hits += self._next_hits(row0, 2, width - 4, rest, next_clicks)
        return out[:room], hits


# ======================================================================================================
# TECHNICAL view
# ======================================================================================================

STATUS_MARK = {"ok": "ok", "rejected": "bad", "fallback": "fb", "wait": "wait", "error": "bad"}
STATUS_LEVEL = {"ok": "ok", "wait": "info", "rejected": "act", "fallback": "watch", "error": "act", "skip": "muted"}
VERDICT_LEVEL = {"CRITICAL-CANDIDATE": "act", "MEDIUM-CANDIDATE": "watch", "LEAD": "hilite", "NEEDS": "watch"}


TAB_NAMES = {"hunt": "hunt", "brain": "brain", "scanner": "scan", "inbox": "inbox", "procs": "procs", "res": "res",
             "lab": "lab", "feed": "feed", "log": "log"}
# the visual-flow framework the tab bar groups by: FLOW is the hunt pipeline itself, INFRA is what
# powers it, AUDIT is the trail of what the pipeline just did. Keep in sync with Technical.PANELS order.
PANEL_GROUP = {"scanner": "flow", "hunt": "flow", "brain": "flow", "inbox": "flow",
               "lab": "infra", "res": "infra", "procs": "infra",
               "feed": "audit", "log": "audit"}


class Technical:
    # Order is the ORGANIZING FRAMEWORK, not raw priority: reading left-to-right / top-to-bottom tells
    # the story of one hunt cycle. FLOW is the pipeline itself (scan for surface -> hunt it -> the
    # brain decides/pivots/ships -> the report lands); INFRA is what powers that pipeline; AUDIT is
    # the trail of everything the pipeline just did. See PANEL_GROUP below (drives the grouped tab bar).
    PANELS = [("scanner", "OSS-BOT SCANNER", "watch", "head"), ("hunt", "HUNT", "info", "head"),
              ("brain", "ORCH BRAIN", "hilite", "head"), ("inbox", "INBOX / REPORTS", "ok", "head"),
              ("lab", "MODEL LAB", "hilite", "head"), ("res", "RESOURCES / MODELS", "info", "head"),
              ("procs", "PROCESSES / LOCKS", "info", "head"), ("feed", "ACTIVITY FEED", "watch", "head"),
              ("log", "RAW LOG TAIL", "muted", "tail")]

    def __init__(self, app):
        self.app = app
        self.room = 9  # content rows the panel being built will get (set by grid() / render())

    # ----- panel builders: (lk, snap, w, t) -> list[Text], full length (the frame fitter cuts with a marker) -----
    def err(self, lk, snap, *names):
        return [lk.T((f"! {n}: {snap['err'][n]}", lk.S("act"))) for n in names if snap["err"].get(n)]

    def p_hunt(self, lk, snap, w, t):
        h = snap["data"].get("hunt")
        if not h:
            return [lk.T(("loading...", lk.S("muted")))]
        out = self.err(lk, snap, "hunt", "totals")
        mode = {"target": "target mode (bot picks)", "program": "pinned program", "off": "auto-hunt off"}.get(h.get("mode"), "?")
        out.append(lk.T(("focus   ", lk.S("muted")), (h.get("focus") or "none", lk.S("info", bold=True)),
                        ("  PARKED" if h.get("parked") else "", lk.S("watch", bold=True)), (f"  {mode}", lk.S("muted")),
                        (f"  AUTO-HUNT='{h.get('auto_raw', '')}'", lk.S("faint"))))
        tot, sw = h.get("total"), h.get("swept", 0)
        frac = self.app.ease("tprog", sw / tot if tot else 0)
        label = f" {sw}/{tot if tot is not None else '?'}" + (f" {sw / tot * 100:5.1f}%" if tot else "")
        out.append(lk.T(("plan    ", lk.S("muted")), lk.bar(frac, max(6, w - 8 - len(label)), "info", grad=True), (label, lk.S("text", bold=True))))
        hb = h.get("hb_age")
        out.append(lk.T(("hits    ", lk.S("muted")), (f"{h.get('hits', 0):<5}", lk.S("act" if h.get("hits") else "text", bold=True)),
                        ("leads ", lk.S("muted")), (f"{h.get('leads', 0):<5}", lk.S("hilite" if h.get("leads") else "text", bold=True)),
                        ("queue ", lk.S("muted")), (f"{h.get('queue', 0):<4}", lk.S("text", bold=True)),
                        ("heartbeat ", lk.S("muted")),
                        (f"{g._dur(hb)} ago" if hb is not None else "none", lk.S("act" if hb is None or hb > 300 else "text"))))
        cur = h.get("cur")
        if cur:
            el = g._dur(time.time() - h["cur_start"]) if h.get("cur_start") else "?"
            qt = h.get("quiet")
            out.append(lk.T(("job     ", lk.S("muted")), (lk.G["spin"][t // 3 % len(lk.G["spin"])] + " " if h.get("alive") else lk.G["ring"] + " ",
                                                         lk.S("ok" if h.get("alive") else "muted")),
                            (f"{cur.get('program')}/{cur.get('lane')}", lk.S("text", bold=True))))
            out.append(lk.T(("        ", ""), (f"pid {cur.get('pid')}  elapsed {el}", lk.S("muted")),
                            (f"  log quiet {g._dur(qt)}" if qt and qt > 600 else "", lk.S("act" if qt and qt > 900 else "watch", bold=True)),
                            ("" if h.get("alive") else "  finished, collected next tick", lk.S("faint"))))
        else:
            out.append(lk.T(("job     ", lk.S("muted")), (lk.G["ring"] + " idle", lk.S("muted"))))
        ph = h.get("per_hour") or []
        if ph:
            out.append(lk.T(("swept/h ", lk.S("muted")), (f"now {ph[-1]}  peak {max(ph)}  24h {sum(ph)}", lk.S("text"))))
            out += lk.chart(ph, max(8, w - 12), 2, "info", 0, None, "/h, 24h")
        return out

    def p_brain(self, lk, snap, w, t):
        b = snap["data"].get("brain")
        if not b:
            return [lk.T(("loading...", lk.S("muted")))]
        out = self.err(lk, snap, "brain")
        rate = b["acc"] / b["acc_n"] if b.get("acc_n") else 0
        out.append(lk.T(("ON " if b.get("on") else "OFF ", lk.S("ok" if b.get("on") else "muted", bold=True)),
                        (f"{b.get('n_hour', 0)}/h", lk.S("text", bold=True)), ("  accept ", lk.S("muted")),
                        (f"{rate * 100:.0f}%", lk.S("ok" if rate >= .6 else "watch" if rate >= .3 else "act", bold=True)),
                        (f" of {b.get('acc_n', 0)}", lk.S("muted")), ("  avg ", lk.S("muted")),
                        (f"{b['avg_secs']:.1f}s" if b.get("avg_secs") else "-", lk.S("text")),
                        ("  12h ", lk.S("muted")), (lk.spark(b.get("per_hour"), 12), lk.S("hilite")),
                        (f"  {b.get('model') or ''}", lk.S("faint"))))
        aw = 15
        if self.room >= 6:  # in a 4-row grid cell the column header pushed out the rows it labels
            out.append(lk.T((f"{'time':<7}  {'action':<{aw}} {'status':<9}{'secs':>4}  reason", lk.S("faint"))))
        for r in reversed(b.get("rows") or []):
            st = r.get("status", "?")
            lv = STATUS_LEVEL.get(st, "text")
            ts = g._ts(r.get("ts"))
            secs = f"{r['secs']:.0f}" if isinstance(r.get("secs"), (int, float)) else ""
            why = (r.get("reason") or r.get("detail") or "").replace("\n", " ")
            ts_s = _when(ts)
            out.append(lk.T((f"{ts_s:<6}", lk.S("muted")), " ",
                            (lk.G[STATUS_MARK.get(st, "wait")] + " ", lk.S(lv, bold=True)),
                            (f"{(r.get('action') or '?')[:aw]:<{aw}}", lk.S("text", bold=True)), " ",
                            (f"{st[:8]:<9}", lk.S(lv)), (f"{secs:>4}  ", lk.S("muted")), (why, lk.S("muted"))))
        return out

    def p_scanner(self, lk, snap, w, t):
        o = snap["data"].get("oss")
        if o is None:
            return [lk.T(("loading...", lk.S("muted")))]
        ost = g.oss_state(o, (snap["data"].get("services") or {}).get("pm2"))
        word, lv = {"live": ("LIVE sending real traffic", "watch"), "dry": ("DRY fires nothing", "info"),
                    "paused": ("PAUSED", "muted"), "stopped": ("pm2 stopped", "muted"),
                    "incident": ("SCOPE INCIDENT, resume --ack-incident", "act"), "draining": ("DRAINING", "muted"),
                    "stale": ("heartbeat stale", "act"), "down": ("not running", "muted")}[ost]
        hb = o.get("hb_age")
        rv = o.get("review") or {}
        tri = o.get("triage")
        side = self.err(lk, snap, "oss") + [
            lk.T((lk.G["dot"] + " ", lk.S(lv, bold=True)), (word, lk.S(lv, bold=True))),
            lk.T(("tick ", lk.S("muted")), (f"{g._dur(hb)} ago" if hb is not None else "-", lk.S("text")),
                 ("  runs/h ", lk.S("muted")), (str(o.get("runs_1h", 0)), lk.S("text", bold=True))),
            lk.T(("24h  ", lk.S("muted")), (f"{o.get('runs_24h', 0)} runs", lk.S("text", bold=True)),
                 ("  ok ", lk.S("muted")), (str(o.get("ok_24h", 0)), lk.S("ok", bold=True)),
                 ("  FAIL ", lk.S("muted")), (str(o.get("fail_24h", 0)), lk.S("act" if o.get("fail_24h") else "text", bold=True)),
                 ("  err ", lk.S("muted")), (str(o.get("err_24h", 0)), lk.S("watch" if o.get("err_24h") else "text"))),
            lk.T(("leads", lk.S("muted")), (f" {o.get('open', 0)} open", lk.S("watch" if o.get("open") else "ok", bold=True)),
                 (f"  {o.get('open_net', 0)} net {lk.G['sep']} {o.get('open', 0) - o.get('open_net', 0)} secret", lk.S("text")),
                 (f"  +{o.get('leads_24h', 0)} 24h", lk.S("muted"))),
            lk.T(("review ", lk.S("muted")), (f"{rv.get('rule', 0)} rule {lk.G['sep']} {rv.get('model', 0)} model", lk.S("text")),
                 ("  live? ", lk.S("muted")), (str(rv.get("live_open", 0)), lk.S("act" if rv.get("live_open") else "text", bold=True)),
                 (f"  waiting {rv.get('waiting', 0)}", lk.S("watch" if rv.get("waiting") else "muted"))),
            lk.T(("triage ", lk.S("muted")), (f"{_when(tri['ts'])} culled {tri.get('culled')}" if tri and tri.get("ts")
                                             else "never", lk.S("muted")))]
        for r in (o.get("running") or []):
            side.append(lk.T((lk.G["spin"][t // 3 % len(lk.G["spin"])] + " ", lk.S("hilite")),
                             (f"{r.get('program')}/{r.get('job')}", lk.S("text", bold=True)), (f"  pid {r.get('pid')}", lk.S("muted"))))
        blips = []
        for r in (o.get("running") or [])[:6]:
            k = f"{r.get('program')}/{r.get('job')}"
            blips.append((2 * math.pi * (_h(k) % 360) / 360, 0.3 + 0.55 * ((_h(k[::-1]) % 100) / 100), "hilite"))
        for prog, job, ended, rc, audit, leads in (o.get("last") or [])[:6]:
            if leads or str(audit or "").startswith("AUDIT FAIL"):
                k = f"{prog}/{job}/{ended}"
                blips.append((2 * math.pi * (_h(k) % 360) / 360, 0.75, "act" if str(audit).startswith("AUDIT FAIL") else "watch"))
        rows = []
        for prog, job, ended, rc, audit, leads in (o.get("last") or []):
            a = str(audit or "-")
            rows.append(lk.T((_when(ended) + " " if ended else "", lk.S("muted")), (_clip(f"{prog}/{job}", 28, lk).ljust(29), lk.S("text")),
                             (f"rc {rc:<3}", lk.S("muted" if rc in (0, 1) else "watch")),
                             (a[:22].ljust(23), lk.S("act" if a.startswith("AUDIT FAIL") else "ok" if a.startswith("AUDIT OK") else "muted")),
                             (f"+{leads} leads" if leads else "", lk.S("watch"))))
        rc_rows = max(4, min(9, self.room, (w - 36) // 2))  # capped so the last-runs list stays on screen
        rc_cols = rc_rows * 2
        if w >= rc_cols + 34:
            scope = lk.radar(rc_cols, rc_rows, t if ost in ("live", "dry") else 0, blips, ost in ("live", "dry"))
            sw_ = w - rc_cols - 2
            body = []
            for i in range(max(len(scope), len(side))):
                line = lk.Text(no_wrap=True)
                line.append_text(scope[i] if i < len(scope) else lk.T(" " * rc_cols))
                line.append("  ")
                s = side[i] if i < len(side) else lk.T("")
                s.truncate(sw_, overflow="ellipsis" if lk.uni else "crop")
                line.append_text(s)
                body.append(line)
            return body + ([lk.T(("last runs", lk.S("faint")))] if rows else []) + rows
        return side + rows

    def p_inbox(self, lk, snap, w, t):
        ib = snap["data"].get("inbox")
        rp = snap["data"].get("reports") or {}
        if not ib:
            return [lk.T(("loading...", lk.S("muted")))]
        q = lambda v: "..." if v is None else v  # noqa: E731
        out = self.err(lk, snap, "inbox", "reports")
        out.append(lk.T(("unread ", lk.S("muted")), (str(ib["unread"]), lk.S("watch" if ib["unread"] else "text", bold=True)),
                        (f" ({ib.get('distinct', ib['unread'])} distinct) of {ib['total']}", lk.S("muted")),
                        (f"   exploit {ib['exploit']}" if ib.get("exploit") else "", lk.S("act", bold=True))))
        out.append(lk.T(("READY ", lk.S("muted")), (str(q(rp.get("ready"))), lk.S("ok", bold=True)), ("  HELD ", lk.S("muted")),
                        (str(q(rp.get("held"))), lk.S("watch", bold=True)), ("  drafts ", lk.S("muted")), (str(q(rp.get("drafts"))), lk.S("text")),
                        ("  filed ", lk.S("muted")), (str(q(rp.get("submitted"))), lk.S("text")), ("  leads ", lk.S("muted")),
                        (str(q(rp.get("leads"))), lk.S("text"))))
        if ib.get("kinds"):
            kt = lk.Text(no_wrap=True, overflow="ellipsis" if lk.uni else "crop")
            for i, (kind, c) in enumerate(ib["kinds"]):
                if i:
                    kt.append(f" {lk.G['sep']} ", style=lk.S("faint"))
                r = g._inbox_rank(kind)
                kt.append(f"{kind} {c}", style=lk.S("act" if r == 0 else "watch" if r <= 2 else "faint" if r >= 9 else "muted", bold=r == 0))
            out.append(kt)
        for it in ib.get("newest") or []:
            kl = "act" if "EXPLOIT" in it["kind"] or "HIT" in it["kind"] else "hilite" if "LEAD" in it["kind"] else "info"
            out.append(lk.T((lk.G["dot"] + " " if it["unread"] else "  ", lk.S("watch")),
                            (f"x{it['count']:<3}" if it.get("count", 1) > 1 else "    ", lk.S("muted", bold=True)),
                            (_when(it["ts"]) + " " if it["ts"] else "      ", lk.S("muted")),
                            (f"{it['kind'][:18]:<19}", lk.S(kl, bold=True)), (it["text"], lk.S("text" if it["unread"] else "muted"))))
        return out

    def p_procs(self, lk, snap, w, t):
        s = snap["data"].get("system")
        sv = snap["data"].get("services") or {}
        if not s:
            return [lk.T(("loading...", lk.S("muted")))]
        out = self.err(lk, snap, "system", "services")
        out.append(lk.T(("STOP  ", lk.S("muted")), (f"SET {g.ago(s['stop'])}, type resume" if s.get("stop") else "clear",
                                                     lk.S("act" if s.get("stop") else "ok", bold=True)),
                        ("   critical ", lk.S("muted")), (str(s.get("critical")), lk.S("text", bold=True))))
        gl_ = s.get("glock")
        bad = gl_ and (s.get("glock_policy") == "BANNED" or not s.get("glock_ok"))
        out.append(lk.T(("LOCK  ", lk.S("muted")), (gl_ or "none (rotate)", lk.S("act" if bad else "watch" if gl_ else "muted")),
                        ("  BANNED" if s.get("glock_policy") == "BANNED" else "", lk.S("act", bold=True)),
                        (f"  auto sweeps {s['glock_vs_auto']}" if s.get("glock_vs_auto") else "", lk.S("muted"))))
        for mt, hnd, sid in s.get("sessions") or []:
            out.append(lk.T(("  sess ", lk.S("faint")), (f"{sid:<9}", lk.S("muted")), (str(hnd), lk.S("text")),
                            (f"  {g.ago(mt)}", lk.S("faint")),
                            ("  BANNED" if hnd in (s.get("sess_banned") or []) else "", lk.S("act", bold=True))))
        if s.get("hunt_target"):
            out.append(lk.T(("HUNT_TARGET ", lk.S("muted")), (s["hunt_target"], lk.S("watch"))))
        procs = sv.get("pm2") or []
        on = sum(1 for p in procs if p[1] == "online")
        out.append(lk.T(("pm2   ", lk.S("muted")), (f"{on}/{len(procs)} online", lk.S("ok" if on == len(procs) else "watch", bold=True)),
                        ("   burp mcp ", lk.S("muted")), (lk.G["dot"] if sv.get("burp") else lk.G["ring"], lk.S("ok" if sv.get("burp") else "muted")),
                        ("   lanes ", lk.S("muted")), (str(len(s.get("lanes") or [])), lk.S("text", bold=True))))
        out.append(lk.T((f"  {'process':<16} {'status':<8} {'cpu':<13}{'cpu%':>6} {'mem':>7}  up", lk.S("faint"))))
        cw = 12
        for name, st, up, cpu, mem in sorted(procs, key=lambda p: -(p[3] or 0)):
            upt = g._dur(time.time() - up / 1000) if up else "-"
            out.append(lk.T((lk.G["dot"] + " " if st == "online" else lk.G["ring"] + " ", lk.S("ok" if st == "online" else "act")),
                            (f"{str(name)[:16]:<16} ", lk.S("text")), (f"{str(st)[:8]:<8} ", lk.S("muted" if st == "online" else "act")),
                            lk.bar((cpu or 0) / 100, cw, "watch" if (cpu or 0) > 60 else "info"),
                            (f" {cpu or 0:5.1f}", lk.S("muted")), (f" {mem or 0:5.0f}MB", lk.S("faint")), (f"  {upt}", lk.S("faint"))))
        for pid, prog, lane in s.get("lanes") or []:
            out.append(lk.T(("  lane ", lk.S("faint")), (f"pid {pid:<8}", lk.S("muted")), (f"{prog}/{lane}", lk.S("text"))))
        return out

    def p_res(self, lk, snap, w, t):
        m = snap["data"].get("metrics") or {}
        gp = snap["data"].get("gpu")
        dk = snap["data"].get("desktop") or {}
        out = self.err(lk, snap, "metrics", "gpu", "desktop")
        hist = m.get("history") or []
        lvl = lambda pct: {"bad": "act", "warn": "watch", "ok": "muted"}[g.heat(pct)]  # noqa: E731
        if hist:
            _, cpus, rams, lvs, dvs = zip(*hist)
            cw = max(8, w - 24)
            ld = f" load {m['load']:.1f}/{m['ncpu']}" if m.get("load") is not None else ""
            ch = 2 if self.room >= 20 else 1  # 2-row charts only when zoomed: a grid cell showed a blank row over a flat line
            out += lk.chart(list(cpus), cw, ch, "info", 0, 100, f"cpu {m.get('cpu', 0):3.0f}%{ld}", lk.S(lvl(m.get("cpu")), bold=True))
            out += lk.chart(list(rams), cw, ch, "hilite", 0, 100, f"ram {m.get('ram', 0):3.0f}%", lk.S(lvl(m.get("ram")), bold=True))
            for vals, lv_, name, key in ((lvs, "ok", "laptop", "local_vram"), (dvs, "watch", "desk", "desktop_vram")):
                if any(vals):  # an all-zero history is an empty chart; say it in words instead
                    out += lk.chart(list(vals), cw, 1, lv_, 0, 100, f"vram {name:<6} {m.get(key, 0):3.0f}%", lk.S(lvl(m.get(key))))
                else:
                    out.append(lk.T((f"vram {name:<6}   0%", lk.S("muted")), ("  nothing loaded in this window", lk.S("faint"))))
        else:
            out.append(lk.T(("collecting samples...", lk.S("muted"))))

        def host(label, data, cap):
            if data is None:
                return
            if not data.get("up", True):
                out.append(lk.T((f"{lk.G['ring']} {label} ", lk.S("muted")), ("not reachable", lk.S("muted"))))
                return
            ms = data.get("models") or []
            if not ms:
                out.append(lk.T((f"{lk.G['dot']} {label} ", lk.S("ok", bold=True)), ("idle, loads on first call", lk.S("faint"))))
            for mm in ms:
                vram, size = (mm.get("size_vram") or 0) / 1e9, (mm.get("size") or 0) / 1e9
                lab = f" {vram:4.1f}/{cap:.0f}GB" + (f" +{size - vram:.1f} cpu" if size - vram > 0.1 else "")
                out.append(lk.T((f"{lk.G['dot']} {label:<8}", lk.S("ok", bold=True)), (_clip(mm.get("name", "?"), max(12, w - 12), lk), lk.S("text", bold=True))))
                out.append(lk.T(("  ", ""), lk.bar(vram / cap if cap else 0, max(6, w - len(lab) - 3), "watch" if cap and vram / cap > .9 else "info"),
                                (lab, lk.S("text"))))
        host("laptop", gp, g.VRAM_GB)
        host("desktop", dk if dk else None, dk.get("vram_gb") or g.VRAM_GB)
        roles = (gp or {}).get("roles") or {}
        for role in ("brain", "chat", "hunter"):
            if roles.get(role):
                out.append(lk.T((f"  role {role:<7}", lk.S("muted")), (roles[role], lk.S("hilite"))))
        if dk.get("up"):
            out.append(lk.T(("  desktop link ", lk.S("muted")), (lk.spark(dk.get("spark"), max(6, w - 40)), lk.S("info")),
                            (f" {dk.get('bytes_5m', 0) / 1e3:.0f} KB {dk.get('req_5m', 0)} req/5m", lk.S("text"))))
        return out

    def p_lab(self, lk, snap, w, t):
        lab = snap["data"].get("lab")
        if lab is None:
            return [lk.T(("loading...", lk.S("muted")))]
        out = self.err(lk, snap, "lab")
        if lab.get("live"):
            i, of = lab.get("i") or 0, lab.get("of")
            out.append(lk.T((lk.G["dot"] + " LIVE ", lk.S("hilite", bold=True)), (str(lab.get("model")), lk.S("text", bold=True)),
                            (f"  {lab.get('suite', '')}", lk.S("muted"))))
            lab_l = f" {i}/{of or '?'}"
            out.append(lk.T(lk.bar(self.app.ease("lab", i / of if of else 0), max(6, w - len(lab_l)), "hilite"), (lab_l, lk.S("text", bold=True))))
            out.append(lk.T(("task ", lk.S("muted")), (lab.get("task") or "-", lk.S("text")), (f"  [{lab.get('category')}]", lk.S("hilite"))))
            toks = lab.get("toks") or []
            pr = lab["ok"] / lab["n"] if lab.get("n") else 0
            out.append(lk.T(("pass ", lk.S("muted")), (f"{pr * 100:.0f}%", lk.S("ok" if pr >= .7 else "watch", bold=True)),
                            (f" {lab.get('ok')}/{lab.get('n')}", lk.S("muted")), ("  errors ", lk.S("muted")), (str(lab.get("errors", 0)), lk.S("act" if lab.get("errors") else "muted"))))
            out += lk.chart(toks or [0], max(8, w - 14), 2, "hilite", label=f"{toks[-1]:.1f} tok/s" if toks else "-")
            for cat, (ok, tot) in sorted((lab.get("cats") or {}).items()):
                f = ok / tot if tot else 0
                out.append(lk.T((f"  {cat[:14]:<14} ", lk.S("muted")), lk.bar(f, max(4, w - 24), "ok" if f >= .7 else "watch"), (f" {f * 100:3.0f}%", lk.S("text"))))
            return out
        board = lab.get("board") or []
        if not board:
            out.append(lk.T(("idle, no finished runs yet (lab bench <model>)", lk.S("muted"))))
            return out
        out.append(lk.T((lk.G["ring"] + " idle", lk.S("muted")), (f"  leaderboard of {lab.get('runs', len(board))} run(s)", lk.S("muted"))))
        # the run time (local) tells two runs of one model apart; the same model is benched more than once
        out.append(lk.T((f"   {'model':<18} {'run':<11} {'score':>6}  {'':<10} {'tok/s':>6} {'p50':>6}", lk.S("faint"))))
        hi = max(b[0] for b in board) or 1
        for k, (score, model, toks, p50, run) in enumerate(board):
            out.append(lk.T((f"{k + 1}  ", lk.S("hilite" if k == 0 else "muted", bold=True)), (f"{_clip(model, 18, lk):<18} ", lk.S("text", bold=True)),
                            (f"{_run_when(run):<11} ", lk.S("muted")),
                            (f"{score:6.1f}  ", lk.S("info", bold=True)), lk.bar(score / hi, 10, "info", grad=True),
                            (f" {toks:6.1f}" if toks else "      -", lk.S("muted")), (f" {p50:5.1f}s" if p50 else "      -", lk.S("muted"))))
        return out

    def feed_rows(self, snap):
        rows = snap["data"].get("changes") or []
        act = snap["simple"].get("activity") or []
        out = []
        for i, r in enumerate(rows):
            who = act[i]["who"] if i < len(act) else ""
            out.append((r, who))
        return out

    def filters(self, snap):
        rows = self.feed_rows(snap)
        kinds = ["all"] + sorted({r.get("kind", "?") for r, _ in rows})
        progs = ["all"] + sorted({w for _, w in rows if w})
        return kinds, progs

    def p_feed(self, lk, snap, w, t):
        rows = self.feed_rows(snap)
        if not rows and snap["data"].get("changes") is None:
            return [lk.T(("loading...", lk.S("muted")))]
        kinds, progs = self.filters(snap)
        kf = kinds[self.app.kind_f % len(kinds)]
        pf = progs[self.app.prog_f % len(progs)]
        out = self.err(lk, snap, "changes")
        shown = [(r, wh) for r, wh in rows if (kf == "all" or r.get("kind") == kf) and (pf == "all" or wh == pf)]
        out.append(lk.T(("kind ", lk.S("muted")), (kf, lk.S("info", bold=True)), ("  , cycles   program ", lk.S("muted")),
                        (pf, lk.S("info", bold=True)), ("  . cycles   ", lk.S("muted")), (f"{len(shown)}/{len(rows)} rows", lk.S("faint"))))
        for r, wh in shown:
            tt = g._ts(r.get("ts"))
            tag = f"{r.get('kind', '?')}/{r['tag']}" if r.get("tag") and r["tag"] != r.get("kind") else r.get("kind", "?")
            cn = r.get("colname", "")
            lv = (VERDICT_LEVEL.get(cn[8:], "muted") if cn.startswith("VERDICT:") else
                  STATUS_LEVEL.get(cn[7:], "muted") if cn.startswith("STATUS:") else
                  {"C_BAD": "act", "C_OK": "ok", "C_WARN": "watch", "C_VIO": "hilite", "C_BLUE": "info", "C_ACC": "info",
                   "C_PINK": "hilite"}.get(cn, "muted"))
            out.append(lk.T((g._local(tt, "%m-%d %H:%M ") if tt else "--          ", lk.S("muted")),
                            (f"{str(tag)[:20]:<21}", lk.S(lv, bold=True)), (str(r.get("text", "")), lk.S("text"))))
        return out

    def p_log(self, lk, snap, w, t):
        log = (snap["data"].get("hunt") or {}).get("log") or []
        return [lk.T((local_log_line(ln), lk.S("muted"))) for ln in log] or [lk.T(("orch.log is empty", lk.S("muted")))]

    # ----- layout -----
    def builders(self):
        return {"hunt": self.p_hunt, "brain": self.p_brain, "scanner": self.p_scanner, "inbox": self.p_inbox,
                "procs": self.p_procs, "res": self.p_res, "lab": self.p_lab, "feed": self.p_feed, "log": self.p_log}

    def subtitle(self, key, snap):
        d = snap["data"]
        return {"hunt": (d.get("hunt") or {}).get("focus") or "", "brain": (d.get("brain") or {}).get("model") or "",
                "scanner": g.oss_state(d.get("oss"), (d.get("services") or {}).get("pm2")) if d.get("oss") is not None else "",
                "res": g.OLLAMA.split("//")[-1], "log": "orch.log"}.get(key, "")

    def header(self, lk, snap, width, t, hidden, zoom):
        S = snap["simple"]
        d = snap["data"]
        h, b = d.get("hunt") or {}, d.get("brain") or {}
        left = lk.T(" ", lk.small_mark(t), ("  hunt control ", lk.S("muted")), (lk.G["sep"] + " technical", lk.S("info")))
        right = lk.T(clock_ribbon(lk, snap, t, compact=width < 110), " ")
        top = lk.T(left, " " * max(1, width - left.cell_len - right.cell_len), right)
        chips = state_badge(lk, S, t, self.app.flash_text())
        mode = h.get("mode", "off")
        chips += [" ", lk.chip("AUTO off" if mode == "off" else f"AUTO {h.get('focus') or 'picking'}" + (" target" if mode == "target" else ""),
                                "muted" if mode == "off" else "info")]
        chips += [" ", lk.chip("BRAIN on" if b.get("on") else "BRAIN off", "hilite" if b.get("on") else "muted")]
        o = d.get("oss")
        if o is not None:
            ost = g.oss_state(o, (d.get("services") or {}).get("pm2"))
            chips += [" ", lk.chip("OSS AUDIT FAIL" if o.get("fail_24h") else f"OSS {ost}", "act" if o.get("fail_24h") or ost in ("incident", "stale")
                                   else "watch" if ost == "live" else "muted")]
        if (d.get("lab") or {}).get("live"):
            chips += [" ", lk.chip("LAB live", "hilite")]
        if snap["demo"]:
            chips += [" ", lk.chip("DEMO", "hilite")]
        sub = lk.T(" ", *chips, *((("   ", ""), uptime_ribbon(lk, snap)) if width >= 110 else ()))  # narrow: uptime was cut mid-word
        tabs = lk.Text(no_wrap=True)
        tabs.append(" ")
        prev_grp = None
        narrow = width < 130  # the group labels cost ~25 cells; below this the tip (which panels are hidden) got cropped
        for i, (key, title, level, _) in enumerate(self.PANELS, 1):
            grp = PANEL_GROUP.get(key)
            if narrow:
                pass
            elif grp != prev_grp:
                if prev_grp is not None:
                    tabs.append("]  ", style=lk.S("faint"))
                tabs.append(f"{grp}[", style=lk.S("faint", italic=True))
                prev_grp = grp
            st = lk.S(level, bold=True, reverse=True) if zoom == i else lk.S("faint") if key in hidden else lk.S("text")
            tabs.append(f" {i} ", style=lk.S("info", bold=True) if zoom != i else st)
            tabs.append(TAB_NAMES[key] + " ", style=st)
        if not narrow:
            tabs.append("]", style=lk.S("faint"))
        hid = " ".join(str(i) for i, (k, *_r) in enumerate(self.PANELS, 1) if k in hidden)
        if zoom:
            tip = "0/Esc back  PgUp/PgDn scroll"
        elif hidden:
            tip = f"{hid} off-screen, press its number" if not narrow else f"{hid} off-screen"
        else:
            tip = "1-9 zoom a panel"
        if narrow and tabs.cell_len + 2 + len(tip) > width:
            tip = ""  # a cropped "7 8 9" reads as noise; the off-screen tabs are already drawn faint
        tabs.append("  " + tip, style=lk.S("muted", italic=True))
        return [lk.lines(x, width)[0] for x in (top, sub, tabs)] + [lk.lines(lk.scan_rule(t, width), width)[0]]

    def grid(self, lk, snap, width, height, t):
        cols = 3 if width >= 150 else 2 if width >= 80 else 1
        min_h = 7 if height >= 21 else 5
        items = list(self.PANELS)
        nrows = max(0, min(-(-len(items) // cols), height // min_h))
        if nrows == 0:
            return [""] * height, [k for k, *_ in items]
        shown, hidden = items[:nrows * cols], [k for k, *_ in items[nrows * cols:]]
        per = [len(shown) // nrows + (1 if r < len(shown) % nrows else 0) for r in range(nrows)]
        bl = self.builders()
        self.room = max(4, height // nrows - 2)
        bodies, k = [], 0
        for r in range(nrows):
            row = shown[k:k + per[r]]
            k += per[r]
            widths = [width // len(row) + (1 if i < width % len(row) else 0) for i in range(len(row))]
            bodies.append([(it, wd, bl[it[0]](lk, snap, wd - 4, t)) for it, wd in zip(row, widths)])
        dem = [max(min_h, min(16, max(len(b) + 2 for _, _, b in row))) for row in bodies]
        if sum(dem) <= height:
            heights = list(dem)
            spare = height - sum(dem)
            for r in range(nrows):
                heights[r] += spare // nrows + (1 if r < spare % nrows else 0)
        else:
            room = height - min_h * nrows
            want = [d - min_h for d in dem]
            tw = sum(want) or 1
            heights = [min_h + room * w_ // tw for w_ in want]
            heights[0] += height - sum(heights)
        out = []
        idx = {key: i for i, (key, *_r) in enumerate(self.PANELS, 1)}
        for row, rh in zip(bodies, heights):
            blocks = [lk.block(title, body, wd, rh, level, self.subtitle(key, snap), key=str(idx[key]), mode=mode)
                      for (key, title, level, mode), wd, body in row]
            out += hjoin(blocks, [wd for _, wd, _ in row])
        return (out + [""] * height)[:height], hidden

    def render(self, lk, snap, width, height, t):
        zoom = self.app.zoom
        if zoom:
            key, title, level, mode = self.PANELS[zoom - 1]
            head = self.header(lk, snap, width, t, [], zoom)
            bh = height - len(head)
            inner = max(1, bh - 2)
            self.room = inner
            ck = ("zoom", id(lk), self.app.snap_key, width, height, zoom, t if key == "scanner" else t // 3)
            body = self.app.cached("tech-zoom", ck, lambda: self.builders()[key](lk, snap, width - 4, t))
            maxs = max(0, len(body) - inner)
            self.app.zscroll = min(self.app.zscroll, maxs)
            start = max(0, len(body) - inner - self.app.zscroll) if mode == "tail" else self.app.zscroll
            view = body[start:start + inner]
            sub = f"rows {start + 1}-{start + len(view)} of {len(body)}" if len(body) > inner else self.subtitle(key, snap)
            blk = lk.lines(lk.frame(title, view, width, bh, level, sub, kind="double", key=str(zoom)), width)[:bh]
            return (head + blk + [""] * height)[:height]
        # one pass for the grid; the header needs to know which panels did not fit
        short = height < 30  # a short terminal drops the decorative scan rule: one more row for the panels
        probe_h = height - (3 if short else 4)
        key = ("tech", id(lk), self.app.snap_key, width, height, self.app.kind_f, self.app.prog_f, t // 2)
        body, hidden = self.app.cached("tech-grid", key, lambda: self.grid(lk, snap, width, probe_h, t))
        head = self.header(lk, snap, width, t, hidden, 0)
        head = head[:3] if short else head
        return (head + body + [""] * height)[:height]


# ======================================================================================================
# the app: prefs, animation state, the command box (mirrors gnoc watch), the frame loop
# ======================================================================================================

def load_prefs(path=PREFS):
    words = g.read(path).split()
    view = words[0] if words and words[0] in VIEWS else "simple"
    theme = words[1] if len(words) > 1 and words[1] in THEMES else "neon"
    return view, theme


def save_prefs(view, theme, path=PREFS):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as fh:
            fh.write(f"{view} {theme}\n")
        os.replace(tmp, path)
    except OSError:
        pass


MOUSE_RE = re.compile(r"\x1b\[<(\d+);(\d+);(\d+)([Mm])")  # SGR mouse report: button;col;row;(M=press, m=release)


class App:
    def __init__(self, view=None, theme=None, demo=None, caps=None, persist=True):
        pv, pt = load_prefs()
        self.persist = persist
        self.view = view or pv
        self.theme = theme or pt
        self.caps = caps or detect_caps()
        self.demo = bool(demo if demo is not None else os.environ.get("GNOC_DEMO") == "1")
        self.feed = g.Feed()
        self.gl = Glossary()
        self._scrub = None
        self.look = DashLook(self.theme, self.caps)
        self.simple, self.tech = Simple(self), Technical(self)
        self.zoom, self.zscroll, self.kind_f, self.prog_f = 0, 0, 0, 0
        self.anim, self.flash_until, self.flash_msg, self.prev_hv = {}, 0.0, "", None
        self.snap, self.snap_key = None, None
        self._memo = {}
        self.note = ""
        self.box = {"buf": "", "cur": 0, "hist": [], "hidx": 0, "out": [], "busy": None, "scroll": 0}
        self.hits = []  # [(row, x0, x1, cmd)] clickable NEEDS/next-step regions, rebuilt every body()

    @property
    def scrub(self):
        if self._scrub is None:
            self._scrub = Scrubber()
        return self._scrub

    # ----- state -----
    def snapshot(self):
        # at most one rebuild per 1.5 s: collectors bump feed.ver ~3x a second, and every rebuild also
        # invalidates the render caches below, so rebuilding on every bump cost more than drawing
        key = (self.demo, int(time.time() / 1.5))
        if self.snap is None or (key != self.snap_key and self.feed.ver != self.snap["ver"]) or key[0] != self.snap_key[0]:
            self.snap = build_snapshot(self.feed, self.gl, self.demo, self.scrub if self.demo else None)
            self.snap_key = key
            hv = self.snap["simple"]["high_value"]
            if self.prev_hv is not None and hv > self.prev_hv:
                self.flash_until = time.time() + 6
                self.flash_msg = f"+{hv - self.prev_hv} high-value event"
            self.prev_hv = hv
        return self.snap

    def cached(self, slot, key, fn, keep=False):
        """Memo for render pieces: recompute only when key changes. keep=True memoises every key (bounded)."""
        if keep:
            store = self._memo.setdefault("__keep__", {})
            if key not in store:
                if len(store) > 600:
                    store.clear()
                store[key] = fn()
            return store[key]
        hit = self._memo.get(slot)
        if hit is None or hit[0] != key:
            hit = (key, fn())
            self._memo[slot] = hit
        return hit[1]

    def flash_text(self):
        return self.flash_msg if time.time() < self.flash_until else ""

    def ease(self, key, target):
        """Bars glide to a new value instead of jumping (a quarter of the gap per frame)."""
        target = float(target or 0)
        v = self.anim.get(key, target)
        v += (target - v) * 0.25
        if abs(target - v) < 0.002:
            v = target
        self.anim[key] = v
        return v

    def set_view(self, v=None):
        self.view = v if v in VIEWS else ("technical" if self.view == "simple" else "simple")
        self.zoom = self.zscroll = 0
        if self.persist:
            save_prefs(self.view, self.theme)

    def set_theme(self, name=None):
        if self.caps[0] == "mono":
            self.note = "NO_COLOR or TERM=dumb is set: staying mono"
            return
        self.theme = name if name in THEMES else THEME_ORDER[(THEME_ORDER.index(self.theme) + 1) % len(THEME_ORDER)] \
            if self.theme in THEME_ORDER else "neon"
        self.look = DashLook(self.theme, self.caps)
        self.note = f"theme {THEMES[self.look.theme_name]['label']}"
        if self.persist:
            save_prefs(self.view, self.theme)

    def set_demo(self, on=None):
        self.demo = (not self.demo) if on is None else on
        self.snap = None
        self.note = "demo mode ON: names are fake" if self.demo else "demo mode off"

    # ----- drawing -----
    def body(self, width, height, t):
        snap = self.snapshot()
        self.hits = []  # Technical.render() does not populate hits; clearing here drops stale Simple-view ones
        r = self.simple if self.view == "simple" else self.tech
        return r.render(self.look, snap, width, height, t)

    def click(self, x, y):
        """A left click on a NEEDS/next-step row fills its exact command into the input box - it
        does not run it. The row's own on-screen hint already says 'type <cmd> then Enter'; this is
        the mouse doing the typing, never the Enter, so nothing fires without the deliberate keypress."""
        row = y - 1
        hit = next(((y0, x0, x1, cmd) for y0, x0, x1, cmd in self.hits if y0 == row and x0 <= x - 1 < x1), None)
        if not hit:
            return
        cmd = hit[3]
        self.box["buf"], self.box["cur"] = cmd, len(cmd)
        self.note = f'filled from click: press Enter to run "{cmd}"'

    def hints(self, width):
        lk = self.look
        cmds = ["chair", "pivot", "orch auto target", "orch brain why", "models", "dchat <q>", "lab bench <model>",
                "inbox", "chat <q>", "help"]
        t = lk.Text(no_wrap=True, overflow="ellipsis" if lk.uni else "crop")
        t.append(f" {lk.G['arrow']} ", style=lk.S("info", bold=True))
        for i, cmd in enumerate(cmds):
            if i:
                t.append(f" {lk.G['sep']} ", style=lk.S("faint"))
            head, _, rest = cmd.partition(" ")
            t.append(head, style=lk.S("text", bold=True))
            if rest:
                t.append(" " + rest, style=lk.S("muted"))
        if self.note:
            t.append(f"   {self.note}", style=lk.S("hilite"))
        return lk.lines(t, width)[0]

    def input_box(self, width, t):
        from rich.cells import cell_len
        lk = self.look
        box = self.box
        bw = max(20, width)
        hr = lk.G["hr"]
        corner = ("╭", "╮", "╰", "╯", "│") if lk.uni else ("+", "+", "+", "+", "|")
        spin = lk.G["spin"][t // 3 % len(lk.G["spin"])] + " " if box["busy"] else ""
        label = f" {spin}gnoc "
        room = bw - 6
        start = max(0, box["cur"] - room + 1)
        shown = box["buf"][start:start + room]
        while cell_len(shown) > room and shown:
            shown = shown[:-1]
        cpos = box["cur"] - start
        hint = " Enter run " + lk.G["sep"] + " Tab view " + lk.G["sep"] + " t theme " + lk.G["sep"] + " ^D demo " + lk.G["sep"] + " q quit "
        if cell_len(label) + cell_len(hint) + 6 > bw:
            hint = " Tab view " + lk.G["sep"] + " q quit "
        if cell_len(label) + cell_len(hint) + 6 > bw:
            hint = " q quit "
        fill = max(0, bw - cell_len(label) - cell_len(hint) - 4)
        edge = lk.S("info")
        top = lk.T((corner[0] + hr, edge), (label, lk.S("info", bold=True)), (hr * fill, edge), (hint, lk.S("muted")), (hr + corner[1], edge))
        mid = lk.T((corner[4] + " ", edge), ("> " if not lk.uni else "❯ ", lk.S("info", bold=True)), (shown[:cpos], lk.S("text")),
                   (shown[cpos] if cpos < len(shown) else " ", "reverse"), (shown[cpos + 1:], lk.S("text")),
                   (" " * max(0, room - max(cell_len(shown), cpos + 1)), ""), (" " + corner[4], edge))
        bot = lk.T((corner[2] + hr * (bw - 2) + corner[3], edge))
        return [lk.lines(x, width)[0] for x in (top, mid, bot)]

    def output_pane(self, width, height, t):
        lk = self.look
        box = self.box
        body_lines = box["out"][1:] if box["out"] else []
        n = max(1, height - 2)
        end = max(n, len(body_lines) - box["scroll"])
        shown = body_lines[max(0, end - n):end]
        if self.demo:
            plain = [g.ANSI_RE.sub("", ln) for ln in shown]
            body = [lk.T((self.scrub.text(ln), lk.S("text"))) for ln in plain]
        else:
            body = [lk.Text.from_ansi(ln, no_wrap=True, overflow="ellipsis") for ln in shown]
        title = g.ANSI_RE.sub("", box["out"][0]) if box["out"] else "output"
        if self.demo:
            title = self.scrub.text(title)
        if box["busy"]:
            title = lk.G["spin"][t // 3 % len(lk.G["spin"])] + " " + title
        more = f"lines {max(1, end - n + 1)}-{min(end, len(body_lines))} of {len(body_lines)}  PgUp/PgDn  " if len(body_lines) > n else ""
        out = lk.lines(lk.frame(title, body, width, height, "info", more + "clear or Ctrl-L"), width)[:height]
        return out + [" " * width] * (height - len(out))

    def frame(self, width, height, t):
        hint = [self.hints(width)] if height >= 30 else []
        tail = self.input_box(width, t)
        free = height - len(hint) - len(tail)
        pane_h = 0
        if self.box["out"]:
            want = len(self.box["out"]) + 1
            pane_h = min(want, max(5, free * 2 // 5 if free >= 18 else free // 2), free)
            pane_h = max(3, pane_h) if free >= 3 else 0
        body_h = max(0, free - pane_h)
        rows = self.body(width, body_h, t) if body_h else []
        if pane_h:
            rows += self.output_pane(width, pane_h, t)
        tail_block = hint + tail
        return (rows[:max(0, height - len(tail_block))] + tail_block)[:height]

    # ----- the command box: the same dispatch as gnoc watch -----
    GNOC = os.path.join(WS, "scripts/gnoc")

    def child_cmd(self, line):
        return ["bash", "-lc", line[1:]] if line.startswith("!") else [sys.executable, self.GNOC] + line.split()

    def run_captured(self, line):
        box = self.box
        box["busy"] = line
        env = dict(os.environ, GNOC_IN_WATCH="1")
        if self.look.mono:
            env.pop("GNOC_FORCE_COLOR", None)
        else:
            env["GNOC_FORCE_COLOR"] = "1"
        try:
            r = subprocess.run(self.child_cmd(line), cwd=WS, env=env, capture_output=True, text=True, timeout=300,
                               stdin=subprocess.DEVNULL)
            text = (r.stdout + r.stderr).rstrip("\n")
            tail = "" if r.returncode == 0 else g.red(f"[exit {r.returncode}]")
        except subprocess.TimeoutExpired:
            text, tail = "", g.red("[timed out after 300s]")
        box["out"] = [g.bold(f"gnoc> {line}")] + (text.expandtabs().splitlines() or [g.dim("(no output)")]) + ([tail] if tail else [])
        box["scroll"] = 0
        box["busy"] = None
        self.feed.poke()

    def interactive(self, line):
        w = line.split()
        if not w:
            return False
        if w[0] in ("menu", "watch", "code", "chair", "dash") or w[0].startswith("!vi") or w[0] in ("!less", "!top", "!htop"):
            return True
        if w in (["chat"], ["dchat"]):
            return True
        return ("--send" in w) or ("--attach" in w)

    def submit_line(self, run_fullscreen):
        box = self.box
        line = box["buf"].strip()
        box["buf"], box["cur"] = "", 0
        if not line:
            return True
        if not box["hist"] or box["hist"][-1] != line:
            box["hist"].append(line)
        box["hidx"] = len(box["hist"])
        w = line.split()
        if line in ("q", "quit", "exit"):
            return False
        if line == "clear":
            box["out"] = []
        elif w[0] == "view":
            self.set_view(w[1] if len(w) > 1 else None)
        elif w[0] == "theme":
            self.set_theme(w[1] if len(w) > 1 else None)
        elif w[0] == "demo":
            self.set_demo({"on": True, "off": False}.get(w[1]) if len(w) > 1 else None)
        elif line in ("help", "?"):
            box["out"] = [g.bold("gnoc> help")] + __doc__.strip().splitlines() + [""] + g.__doc__.strip().splitlines() + [
                "", "  In the box: any gnoc command without the word gnoc, !<shell> for a shell line, clear, q.",
                "  Up/Down history, Tab completes (Tab on an empty box switches the view), PgUp/PgDn scroll, Ctrl-L clears."]
            box["scroll"] = len(box["out"])
        elif box["busy"]:
            box["out"] = [box["out"][0] if box["out"] else g.bold("gnoc>"), g.yellow(f"still running: {box['busy']}")] + box["out"][1:]
        elif w[0] == "lab" and len(w) > 1 and w[1] in ("bench", "serve") and os.path.isfile(g.LAB_PY):
            import contextlib
            import io
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                g.do_lab(w[1:], background=True)
            box["out"] = [g.bold(f"gnoc> {line}")] + buf.getvalue().splitlines()
            box["scroll"] = 0
            self.feed.poke()
        elif self.interactive(line):
            run_fullscreen(line)
        else:
            threading.Thread(target=self.run_captured, args=(line,), daemon=True).start()
        return True

    def handle(self, data, run_fullscreen, term_h):
        box = self.box
        names = sorted(g.COMMANDS) + ["clear", "quit", "help", "view", "theme", "demo"]
        i = 0
        while i < len(data):
            ch = data[i]
            empty = not box["buf"]
            if ch in "\r\n":
                if not self.submit_line(run_fullscreen):
                    return False
            elif ch == "\x04":  # Ctrl-D: demo mode (gnoc watch used it to leave; here q / Ctrl-C leave)
                self.set_demo()
            elif ch == "\x14":  # Ctrl-T
                self.set_theme()
            elif ch in ("\x7f", "\b"):
                if box["cur"]:
                    box["buf"] = box["buf"][:box["cur"] - 1] + box["buf"][box["cur"]:]
                    box["cur"] -= 1
            elif ch == "\x15":
                box["buf"], box["cur"] = "", 0
            elif ch == "\x0c":
                box["out"] = []
            elif ch == "\t":
                if empty:
                    self.set_view()
                else:
                    head, _, rest = box["buf"].partition(" ")
                    if not rest:
                        hits = [n for n in names if n.startswith(head)]
                        if len(hits) == 1:
                            box["buf"] = hits[0] + " "
                        elif hits:
                            box["out"] = [g.bold("gnoc> complete"), g.dim("  ".join(hits))]
                        box["cur"] = len(box["buf"])
            elif empty and ch in "qQ":  # the hint bar promises "q quit"; no gnoc command starts with q
                return False
            elif empty and ch in "vV":
                self.set_view()
            elif empty and ch in "tT":
                self.set_theme()
            elif empty and ch.isdigit() and self.view == "technical":
                self.zoom = 0 if ch == "0" or int(ch) == self.zoom else int(ch)
                self.zscroll = 0
            elif empty and ch == "," and self.view == "technical":
                self.kind_f += 1
            elif empty and ch == "." and self.view == "technical":
                self.prog_f += 1
            elif ch == "\x1b":
                seq4, seq = data[i:i + 4], data[i:i + 3]
                if seq4 in ("\x1b[5~", "\x1b[6~"):
                    step = max(1, term_h // 3 - 2)
                    up = seq4[2] == "5"
                    if self.zoom and not box["out"]:
                        tail = self.tech.PANELS[self.zoom - 1][3] == "tail"  # tail panels scroll from the bottom
                        self.zscroll = max(0, self.zscroll + (step if up == tail else -step))
                    else:
                        box["scroll"] = max(0, min(max(0, len(box["out"]) - 2), box["scroll"] + (step if up else -step)))
                    i += 4
                    continue
                if len(seq) < 2 or seq[1] not in "[O":  # a lone Esc
                    self.zoom, self.zscroll = 0, 0
                    i += 1
                    continue
                if seq in ("\x1b[A", "\x1b[B") and box["hist"]:
                    box["hidx"] = max(0, min(len(box["hist"]), box["hidx"] + (-1 if seq[2] == "A" else 1)))
                    box["buf"] = box["hist"][box["hidx"]] if box["hidx"] < len(box["hist"]) else ""
                    box["cur"] = len(box["buf"])
                elif seq == "\x1b[C":
                    box["cur"] = min(len(box["buf"]), box["cur"] + 1)
                elif seq == "\x1b[D":
                    box["cur"] = max(0, box["cur"] - 1)
                elif seq in ("\x1b[H", "\x1bOH"):
                    box["cur"] = 0
                elif seq in ("\x1b[F", "\x1bOF"):
                    box["cur"] = len(box["buf"])
                i += 3 if len(seq) == 3 else 1
                continue
            elif ch >= " ":
                box["buf"] = box["buf"][:box["cur"]] + ch + box["buf"][box["cur"]:]
                box["cur"] += 1
            i += 1
        return True

    def run(self, fps=10):
        import select
        import shutil
        import termios
        import tty
        term = sys.__stdout__
        # Keys are read from a private dup of the tty and fd 0 becomes /dev/null: gnoc's collectors run
        # children (pm2 jlist every 5 s) with an inherited stdin, and a child holding the tty could swallow
        # a keypress (measured: 2 of 4 single-key test runs lost the key before this).
        fd = os.dup(sys.stdin.fileno())
        devnull = os.open(os.devnull, os.O_RDONLY)
        os.dup2(devnull, 0)
        os.close(devnull)
        saved = termios.tcgetattr(fd)
        self.feed.start()

        def run_fullscreen(line):
            termios.tcsetattr(fd, termios.TCSADRAIN, saved)
            term.write("\033[?1006l\033[?1000l\033[?1049l\033[?25h\033[2J\033[H")
            term.flush()
            try:
                subprocess.call(self.child_cmd(line), cwd=WS, stdin=fd)  # interactive children get the real tty
                term.write(g.dim("\n[Enter] back to the dashboard "))
                term.flush()
                while os.read(fd, 1) not in (b"\n", b"\r", b""):
                    pass
            except (KeyboardInterrupt, EOFError, OSError):
                pass
            tty.setcbreak(fd)
            term.write("\033[?1049h\033[?25l\033[2J\033[?1000h\033[?1006h")
            self.feed.poke()

        t = 0
        note_t = 0
        tty.setcbreak(fd)
        term.write("\033[?1049h\033[?25l\033[2J\033[?1000h\033[?1006h")  # + SGR mouse click reporting
        try:
            while True:
                size = shutil.get_terminal_size((100, 40))
                width, height = max(40, size.columns), max(12, size.lines)
                rows = self.frame(width, height, t)
                term.write("\033[?2026h\033[H" + "\033[K\n".join(rows) + "\033[K\033[0m\033[0J\033[?2026l")
                term.flush()
                r, _, _ = select.select([fd], [], [], 1 / fps)
                if r:
                    before = self.note
                    data = os.read(fd, 64).decode("utf-8", "ignore")
                    for m in MOUSE_RE.finditer(data):
                        btn, mx, my, kind = int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4)
                        if kind == "M" and btn == 0:  # plain left press only
                            self.click(mx, my)
                    data = MOUSE_RE.sub("", data)
                    if not self.handle(data, run_fullscreen, height):
                        break
                    if self.note != before:
                        note_t = t
                if self.note and t - note_t > fps * 4:
                    self.note = ""
                t += 1
        except KeyboardInterrupt:
            pass
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, saved)
            term.write("\033[?1006l\033[?1000l\033[0m\033[?25h\033[?1049l")
            term.flush()


def render_once(app, width, height, t=0, budget=4.0):
    """One complete frame (header, body, hints, command box) as ANSI lines - what the live loop draws."""
    app.feed.once(budget=budget)
    return app.frame(width, height, t)


def main(argv):
    if "--classic" in argv:
        rest = [a for a in argv if a != "--classic"]
        os.execv(sys.executable, [sys.executable, os.path.join(WS, "scripts/gnoc"), "watch"] + rest)

    def opt(name, default=None):
        if name in argv:
            i = argv.index(name)
            return argv[i + 1] if i + 1 < len(argv) else default
        return default

    if any(a in ("-h", "--help", "help") for a in argv):
        print(__doc__)
        return 0
    view, theme = opt("--view"), opt("--theme")
    if view and view not in VIEWS or theme and theme not in THEMES:
        print(f"--view is one of {', '.join(VIEWS)}; --theme is one of {', '.join(THEMES)}", file=sys.stderr)
        return 2
    demo = True if "--demo" in argv else None
    if "--snapshot" in argv:
        app = App(view, theme, demo, persist=False)
        app.feed.once(4.0)
        json.dump(app.snapshot(), sys.stdout, indent=1, default=str)
        print()
        return 0
    if "--once" in argv or not (sys.stdin.isatty() and sys.__stdout__.isatty()):
        import shutil
        size = opt("--size")
        if size:
            width, height = (int(v) for v in size.lower().split("x"))
        else:
            ts = shutil.get_terminal_size((120, 40))
            width, height = ts.columns, ts.lines
        app = App(view, theme, demo, persist=False)
        rows = render_once(app, width, height, t=int(opt("--t", "0")))
        sys.stdout.write("\n".join(rows) + "\033[0m\n")
        return 0
    App(view, theme, demo, persist=os.environ.get("GNOC_DASH_NOPERSIST") != "1").run(fps=int(opt("--fps", "10")))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

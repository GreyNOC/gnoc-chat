"""gnoc_trajectories.py - export the trajectories gnoc chat logged, and run a batch of prompts headless to make more.

    gnoc export trajectories --format sharegpt|openai [--since YYYY-MM-DD] [--out PATH] [--good-only]
                             [--allow host,...] [--from PATH] [--no-redact]
    gnoc export batch <prompts.jsonl> --out DIR [--workers N] [--timeout SECONDS] [--steps N]

gnoc_learn.log_trajectory appends every tool turn with its measured outcome to trajectories.jsonl, unredacted (the
tool RESULTS were scrubbed at dispatch; the user's own words and the tool-call arguments were not). That file never
leaves the machine. An export is a file people share or train on, so redaction is ON by default, in layers:

    1. known secret values (gnoc_secrets: the ~/.config/gnoc store, every encoding of each value)
    2. secret shapes (gnoc_distill's patterns, a few more token shapes, PEM private keys, secret-named dict keys)
    3. $HOME -> ~, the user name inside paths, other users' home folders -> /home/user
    4. IPv4/IPv6 addresses and hostnames that are not on the allowlist -> one stable placeholder per value per
       export (host-1.invalid, 198.51.100.1, 2001:db8::1), so the structure of a trajectory survives; loopback,
       the RFC 2606/5737/3849 documentation names and ranges, and the placeholders themselves stay
    5. program handles (hunt mode) -> program-1 ...

The allowlist is ~/.gnoc/export-allowlist.txt (one host, IP or CIDR per line, # comments) plus --allow; an entry
also allows its subdomains. `--redact` is accepted and changes nothing (it is the default); `--no-redact` turns every
layer off and says so on stderr. Nothing is uploaded anywhere: the export goes to stdout or to --out (mode 0600).

The batch runner runs each prompt in its own child process: a fresh Agent(interactive=False) with skip-perms forced
off, so every action that needs approval is HELD - recorded in the trajectory's "held" list and never executed. A
child is the unit of isolation (the agent keeps per-process globals) and of the wall-clock cap (a thread cannot be
killed; a process group can). Ctrl-C kills every child.
"""
import argparse
import contextlib
import getpass
import ipaddress
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

ALLOWLIST = os.path.join("~", ".gnoc", "export-allowlist.txt")
FORMATS = ("sharegpt", "openai")
MAX_WORKERS = 8
MAX_STEPS = 200
MAX_PROMPTS = 10000
MAX_PROMPT_CHARS = 100_000

# ---------------------------------------------------------------- redaction

# token shapes gnoc_distill's list does not carry: a bare bearer value (no "authorization:" before it), Google, Hugging
# Face, Stripe, GitLab, npm and Slack webhook secrets. Over-redacting a lookalike costs one word; missing one leaks it.
_EXTRA_PATTERNS = [re.compile(p) for p in (
    r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]{16,}",
    r"\bAIza[0-9A-Za-z_-]{35}\b",
    r"\bhf_[A-Za-z0-9]{30,}\b",
    r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b",
    r"\bglpat-[A-Za-z0-9_-]{20,}\b",
    r"\bnpm_[A-Za-z0-9]{36}\b",
    r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",
)]
# a dict value under one of these keys is a credential whatever it looks like ({"password": "hunter22"} has no shape)
_SECRET_KEY = re.compile(r"(?i)^(?:.*[_-])?(?:password|passwd|pass|secret|token|api[_-]?key|apikey|authorization|"
                         r"cookie|private[_-]?key|client[_-]?secret|access[_-]?key|session[_-]?id|otp)$")

# Real TLDs that a bare word.word is trusted to be a host by. Deliberately NOT here: the TLDs that are also file
# extensions or code attributes (py md sh rs pl so ps ml am pm cc mk sc js ts info app dev me is it in to at be no
# do go ...): `gnoc_learn.py`, `logger.info` and `self.app` are code, and redacting them would wreck the data.
# Those still count as hosts inside a URL, an email address or host:port, where the context says so.
_STRONG_TLDS = frozenset((
    "com net org edu gov mil int io co ai us uk de fr jp cn ru br au ca nl es se ch eu kr nz ie dk fi pl at mx ar za "
    "xyz cloud tech online site store shop biz name pro asia global host space website digital systems network "
    "services solutions agency company email live news blog media world zone").split())
# names that only ever mean an internal host (a LAN or cluster), never a file
_INTERNAL_TLDS = frozenset("internal corp lan local home intranet svc cluster private localdomain".split())
_FILE_EXT = frozenset((
    "py pyc pyi md txt json jsonl yaml yml toml ini cfg conf sh bash zsh ps1 bat cmd js mjs cjs ts tsx jsx vue css "
    "scss html htm xml csv tsv log lock rs go rb pl pm java kt c h cc cpp hpp cs swift m mm sql db sqlite gz tgz zip "
    "tar bz2 xz png jpg jpeg gif svg webp ico pdf doc docx xls xlsx ppt pptx so dll exe bin o a whl egg gguf env "
    "pem key crt der p12 out err tmp bak orig diff patch rst tex ipynb mk make cmake gradle properties").split())
# stays as it is: documentation names (RFC 2606/6761), loopback, and the placeholders this module writes
_KEEP_HOSTS = frozenset(("localhost", "example.com", "example.net", "example.org"))
_KEEP_SUFFIXES = (".example", ".invalid", ".test", ".localhost", ".example.com", ".example.net", ".example.org")
_KEEP_NETS = tuple(ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "0.0.0.0/32", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "::1/128", "::/128",
    "2001:db8::/32"))

_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_URL = re.compile(r"(?i)\b([a-z][a-z0-9+.-]{1,15}://)(?:([^\s/@'\"<>]+)@)?(\[[0-9a-f:.%]+\]|[^\s/:?#\[\]'\"<>@]+)")
_EMAIL = re.compile(r"(?<![\w.+-])([A-Za-z0-9._%+-]{1,64})@(" + _LABEL + r"(?:\." + _LABEL + r")+)\b")
_HOSTPORT = re.compile(r"(?<![\w.@-])(" + _LABEL + r"(?:\." + _LABEL + r")+):(\d{1,5})\b")
_HOST = re.compile(r"(?<![\w.@-])(" + _LABEL + r"(?:\." + _LABEL + r")+)(?![\w-]|\.[A-Za-z0-9])")
_IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w]|\.\d)")
_IPV6 = re.compile(r"(?i)(?<![\w:.])((?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?:%[\w.]+)?)(?![\w:])")


def load_allowlist(path=None, extra=()):
    """(hosts, networks) from the allowlist file plus --allow entries. A missing file is an empty list."""
    hosts, nets = set(), []
    lines = list(extra)
    with contextlib.suppress(OSError):
        with open(os.path.expanduser(path or ALLOWLIST), encoding="utf-8", errors="replace") as f:
            lines += f.read().splitlines()
    for ln in lines:
        e = ln.split("#", 1)[0].strip().lower().rstrip(".")
        if not e:
            continue
        try:
            nets.append(ipaddress.ip_network(e, strict=False))
        except ValueError:
            hosts.add(e.lstrip("*."))
    return hosts, nets


class Redactor:
    """One export's redaction state: the same host gets the same placeholder in every line of one export, so a
    trajectory still says "fetched host-3.invalid twice" instead of losing its structure."""

    def __init__(self, allow_hosts=(), allow_nets=(), home=None, user=None, terms=()):
        self.allow_hosts = {h.lower() for h in allow_hosts}
        self.allow_nets = list(allow_nets)
        self.home = home if home is not None else os.path.expanduser("~")
        self.user = user if user is not None else _username()
        self.maps = {"host": {}, "ip4": {}, "ip6": {}, "user": {}, "term": {}}
        self.terms = []
        for t in terms:
            self.add_term(t)
        homes = {self.home, os.path.realpath(self.home)} if self.home and self.home not in ("/", "~") else set()
        self._homes = sorted((h.rstrip("/\\") for h in homes if len(h.rstrip("/\\")) > 1), key=len, reverse=True)
        self._distill = _distill_patterns()

    # ---- placeholders
    def _ph(self, kind, value, fmt):
        m = self.maps[kind]
        if value not in m:
            m[value] = fmt(len(m) + 1)
        return m[value]

    def add_term(self, term):
        """A word redacted everywhere (a program handle). Short or empty terms are ignored: 'ab' is in every word."""
        t = str(term or "").strip()
        if len(t) >= 3 and t.lower() not in (x.lower() for x in self.terms):
            self.terms.append(t)

    def term_placeholder(self, term):
        return self._ph("term", str(term).lower(), lambda n: f"program-{n}")

    def _keep_host(self, host):
        h = host.lower().rstrip(".")
        if h in _KEEP_HOSTS or h.endswith(_KEEP_SUFFIXES):
            return True
        return any(h == a or h.endswith("." + a) for a in self.allow_hosts)

    def _keep_ip(self, ip):
        return any(ip.version == n.version and ip in n for n in (*_KEEP_NETS, *self.allow_nets))

    def host(self, host):
        if self._keep_host(host):
            return host
        return self._ph("host", host.lower().rstrip("."), lambda n: f"host-{n}.invalid")

    def _ip(self, text):
        try:
            ip = ipaddress.ip_address(text.split("%", 1)[0])
        except ValueError:
            return None
        if self._keep_ip(ip):
            return text
        if ip.version == 4:
            return self._ph("ip4", str(ip), lambda n: f"198.51.100.{n}" if n < 255 else f"ip4-{n}.invalid")
        return self._ph("ip6", str(ip), lambda n: f"2001:db8::{n:x}")

    # ---- layers
    def text(self, s):
        if not isinstance(s, str) or not s:
            return s
        s = _known_secrets(s)
        for p in self._distill + _EXTRA_PATTERNS:
            s = p.sub(lambda m: (m.group(1) if m.groups() and m.group(1) else "") + "[REDACTED]", s)
        s = self._paths(s)
        s = self._urls(s)
        s = _EMAIL.sub(self._email, s)
        s = _HOSTPORT.sub(self._hostport, s)
        s = _HOST.sub(self._bare_host, s)
        s = _IPV4.sub(lambda m: self._ip(m.group(1)) or m.group(0), s)
        s = _IPV6.sub(self._ipv6, s)
        for t in self.terms:
            s = re.sub(r"(?i)(?<![A-Za-z0-9])" + re.escape(t) + r"(?![A-Za-z0-9])",
                       lambda m, t=t: self.term_placeholder(t), s)
        return s

    def _paths(self, s):
        for h in self._homes:
            s = re.sub(re.escape(h) + r"(?=[/\\]|$|[^\w.-])", "~", s)
        u = re.escape(self.user) if self.user and len(self.user) >= 2 else None
        if u:
            s = re.sub(r"(?i)(?:/home/|/Users/|[A-Za-z]:\\Users\\)" + u + r"(?=[/\\]|$|[^\w.-])", "~", s)
            # the user name as a path segment anywhere else (/var/mail/<user>, /tmp/<user>-cache stays: not a segment)
            s = re.sub(r"(?<=[/\\])" + u + r"(?=[/\\]|$|[^\w.-])", "user", s)
        return re.sub(r"(/home/|/Users/)(?!user(?:[/\\]|$|[^\w.-]))[A-Za-z0-9_][\w.-]*", r"\1user", s)

    def _urls(self, s):
        def sub(m):
            scheme, userinfo, host = m.group(1), m.group(2), m.group(3)
            if host.startswith("["):
                inner = host[1:-1]
                rep = "[" + (self._ip(inner) or inner) + "]"
            else:
                rep = self._ip(host) or self.host(host)
            return scheme + ("[REDACTED]@" if userinfo else "") + rep
        return _URL.sub(sub, s)

    def _email(self, m):
        local, dom = m.group(1), m.group(2)
        if dom.lower().rsplit(".", 1)[-1] in _FILE_EXT:
            return m.group(0)   # name@2x.png is a file, not an address
        # an allowlisted domain keeps the domain, never the person: alice@mail.example stays a placeholder even when mail.example is allowed
        who = local if local.lower() in ("git", "noreply", "no-reply") else \
            self._ph("user", local.lower(), lambda n: f"user-{n}")
        return f"{who}@{self.host(dom)}"

    def _hostport(self, m):
        host, port = m.group(1), m.group(2)
        tld = host.lower().rsplit(".", 1)[-1]
        if tld in _FILE_EXT or tld.isdigit():
            return m.group(0)   # gnoc_learn.py:817 is a line number; 10.0.0.1:80 is left to the IPv4 pass
        if tld in _STRONG_TLDS or tld in _INTERNAL_TLDS or host.count(".") >= 2:
            return f"{self.host(host)}:{port}"
        return m.group(0)

    def _bare_host(self, m):
        host = m.group(1)
        tld = host.lower().rsplit(".", 1)[-1]
        if tld in _FILE_EXT or not (tld in _STRONG_TLDS or tld in _INTERNAL_TLDS):
            return host
        return self.host(host)

    def _ipv6(self, m):
        t = m.group(1)
        if t.count(":") < 2 or ("::" not in t and t.count(":") != 7):
            return t   # 12:30:45 is a time, not an address
        groups = [g for g in t.split("%", 1)[0].split(":") if g]
        if not any(len(g) >= 3 for g in groups) and len(groups) < 4:
            return t   # x[1::2] and x[::2] are Python slices that happen to parse as IPv6
        return self._ip(t) or t

    def obj(self, o, key=None):
        """Every string inside o redacted; a value under a secret-named key is replaced outright. Keys stay."""
        if isinstance(o, str):
            if key is not None and _SECRET_KEY.match(str(key)) and len(o) >= 4:
                return "[REDACTED]"
            return self.text(o)
        if isinstance(o, dict):
            return {k: self.obj(v, k) for k, v in o.items()}
        if isinstance(o, (list, tuple)):
            return [self.obj(v) for v in o]
        return o


def _username():
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001 - no passwd entry (a container): fall back to the environment
        return os.environ.get("USER") or os.environ.get("USERNAME") or ""


def _known_secrets(s):
    try:
        import gnoc_secrets
        return gnoc_secrets.redact(s)
    except Exception:  # noqa: BLE001 - the store failed to load: the shape layers below still run
        return s


def _distill_patterns():
    """gnoc_distill already carries the secret shapes we redact training data with; reuse them, never a copy."""
    try:
        import gnoc_distill
        return list(gnoc_distill._PATTERNS)
    except Exception:  # noqa: BLE001
        return []


# ---------------------------------------------------------------- conversion and schema


class Invalid(ValueError):
    pass


def _args_obj(a):
    """Tool-call arguments as a dict: history keeps dicts, the OpenAI wire keeps JSON strings, and a malformed model
    output is a bare string - kept, under _raw, so the arguments string is always valid JSON."""
    if isinstance(a, dict):
        return a
    if isinstance(a, str):
        try:
            v = json.loads(a)
        except ValueError:
            return {"_raw": a}
        return v if isinstance(v, dict) else {"_raw": a}
    return {} if a is None else {"_raw": str(a)}


def normalize(messages):
    """History messages (Ollama shape) -> [{role, content, calls?: [{name, args}]}], roles checked."""
    out = []
    for m in messages or []:
        if not isinstance(m, dict):
            raise Invalid("a message is not an object")
        role = m.get("role")
        if role not in ("user", "assistant", "tool", "system"):
            raise Invalid(f"unknown role {role!r}")
        r = {"role": role, "content": str(m.get("content") or "")}
        if role == "assistant" and m.get("tool_calls"):
            calls = []
            for c in m["tool_calls"]:
                fn = (c.get("function") if isinstance(c, dict) else None) or {}
                name = fn.get("name")
                if not isinstance(name, str) or not name:
                    raise Invalid("a tool call has no name")
                calls.append({"name": name, "args": _args_obj(fn.get("arguments"))})
            r["calls"] = calls
        if role == "tool" and m.get("tool_name"):
            r["tool_name"] = str(m["tool_name"])
        out.append(r)
    return out


def redact_messages(msgs, red):
    for m in msgs:
        m["content"] = red.text(m["content"])
        if "tool_name" in m:
            m["tool_name"] = red.text(m["tool_name"])
        for c in m.get("calls") or []:
            c["name"] = red.text(c["name"])
            c["args"] = red.obj(c["args"])
    return msgs


def to_openai(msgs):
    """The OpenAI chat fine-tuning shape. Ids are generated here and paired strictly: a tool result with no open call,
    or a call left unanswered, makes the record Invalid rather than a line a trainer rejects."""
    out, pending, n = [], [], 0
    for m in msgs:
        role = m["role"]
        if role == "tool":
            if not pending:
                raise Invalid("a tool result with no tool call before it")
            out.append({"role": "tool", "tool_call_id": pending.pop(0), "content": m["content"]})
            continue
        if pending:
            raise Invalid("a tool call was never answered")
        r = {"role": role, "content": m["content"]}
        if m.get("calls"):
            calls = []
            for c in m["calls"]:
                n += 1
                calls.append({"id": f"call_{n}", "type": "function",
                              "function": {"name": c["name"], "arguments": json.dumps(c["args"], default=str)}})
            r["tool_calls"] = calls
            pending = [c["id"] for c in calls]
        out.append(r)
    if pending:
        raise Invalid("a tool call was never answered")
    return {"messages": out}


def to_sharegpt(msgs, meta):
    conv, pending = [], 0
    for m in msgs:
        role = m["role"]
        if role == "tool":
            if not pending:
                raise Invalid("a tool result with no tool call before it")
            pending -= 1
            conv.append({"from": "observation", "value": m["content"]})
            continue
        if pending:
            raise Invalid("a tool call was never answered")
        if role == "user":
            conv.append({"from": "human", "value": m["content"]})
        elif role == "system":
            conv.append({"from": "system", "value": m["content"]})
        else:
            if m["content"] or not m.get("calls"):
                conv.append({"from": "gpt", "value": m["content"]})
            for c in m.get("calls") or []:
                conv.append({"from": "function_call",
                             "value": json.dumps({"name": c["name"], "arguments": c["args"]}, default=str)})
                pending += 1
    if pending:
        raise Invalid("a tool call was never answered")
    return {"conversations": conv, **meta}


_OPENAI_ROLES = ("system", "user", "assistant", "tool")
_SHAREGPT_FROM = ("system", "human", "gpt", "function_call", "observation")
_SHAREGPT_META = ("id", "ts", "program", "outcome", "held")


def validate_openai(rec):
    """Raise Invalid unless rec is one valid OpenAI chat fine-tuning line."""
    if not isinstance(rec, dict) or set(rec) != {"messages"}:
        raise Invalid("an OpenAI line holds exactly one key, messages")
    msgs = rec["messages"]
    if not isinstance(msgs, list) or not msgs:
        raise Invalid("messages is empty")
    open_ids, seen = [], set()
    for m in msgs:
        if not isinstance(m, dict) or m.get("role") not in _OPENAI_ROLES:
            raise Invalid(f"bad role in {m!r:.80}")
        role = m["role"]
        if role == "tool":
            if set(m) != {"role", "tool_call_id", "content"} or not isinstance(m["content"], str):
                raise Invalid("a tool message is role, tool_call_id and a string content")
            if m["tool_call_id"] not in open_ids:
                raise Invalid(f"tool_call_id {m['tool_call_id']!r} answers no open call")
            open_ids.remove(m["tool_call_id"])
            continue
        if open_ids:
            raise Invalid("a tool call was never answered")
        allowed = {"role", "content", "tool_calls"} if role == "assistant" else {"role", "content"}
        if not set(m) <= allowed or "content" not in m:
            raise Invalid(f"unexpected keys in a {role} message")
        if not (isinstance(m["content"], str) or (m["content"] is None and m.get("tool_calls"))):
            raise Invalid("content is not a string")
        for c in m.get("tool_calls") or []:
            fn = c.get("function") if isinstance(c, dict) else None
            if not isinstance(c, dict) or c.get("type") != "function" or not isinstance(c.get("id"), str) \
                    or not isinstance(fn, dict) or not isinstance(fn.get("name"), str) or not fn["name"] \
                    or not isinstance(fn.get("arguments"), str):
                raise Invalid("a tool call is {id, type: function, function: {name, arguments: str}}")
            try:
                if not isinstance(json.loads(fn["arguments"]), dict):
                    raise Invalid("tool-call arguments are not a JSON object")
            except ValueError as e:
                raise Invalid("tool-call arguments are not JSON") from e
            if c["id"] in seen:
                raise Invalid(f"duplicate tool call id {c['id']!r}")
            seen.add(c["id"])
            open_ids.append(c["id"])
    if open_ids:
        raise Invalid("a tool call was never answered")
    roles = [m["role"] for m in msgs]
    if "user" not in roles or "assistant" not in roles:
        raise Invalid("a trajectory needs a user and an assistant message")


def validate_sharegpt(rec):
    if not isinstance(rec, dict) or "conversations" not in rec:
        raise Invalid("a ShareGPT line holds conversations")
    extra = set(rec) - {"conversations", *_SHAREGPT_META}
    if extra:
        raise Invalid(f"unexpected keys {sorted(extra)}")
    conv = rec["conversations"]
    if not isinstance(conv, list) or not conv:
        raise Invalid("conversations is empty")
    pending = 0
    for t in conv:
        if not isinstance(t, dict) or set(t) != {"from", "value"} or t["from"] not in _SHAREGPT_FROM \
                or not isinstance(t["value"], str):
            raise Invalid(f"a turn is {{from, value}} with a known from: {t!r:.80}")
        if t["from"] == "function_call":
            try:
                v = json.loads(t["value"])
            except ValueError as e:
                raise Invalid("a function_call value is not JSON") from e
            if not isinstance(v, dict) or not isinstance(v.get("name"), str) or not isinstance(v.get("arguments"), dict):
                raise Invalid("a function_call value is {name, arguments}")
            pending += 1
        elif t["from"] == "observation":
            if not pending:
                raise Invalid("an observation with no function_call before it")
            pending -= 1
        elif pending:
            raise Invalid("a function_call was never answered")
    if pending:
        raise Invalid("a function_call was never answered")
    froms = {t["from"] for t in conv}
    if "human" not in froms or not froms & {"gpt", "function_call"}:
        raise Invalid("a trajectory needs a human turn and a model turn")


VALIDATORS = {"openai": validate_openai, "sharegpt": validate_sharegpt}

# ---------------------------------------------------------------- export


def parse_since(s):
    """YYYY-MM-DD, as midnight UTC. Anything else is refused: a silently ignored typo exports everything."""
    if not isinstance(s, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", s):
        raise ValueError(f"--since takes a date as YYYY-MM-DD, not {s!r}")
    try:
        return datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError as e:
        raise ValueError(f"--since {s!r} is not a real date") from e


def _ts(rec):
    t = rec.get("ts")
    if not isinstance(t, str):
        return None
    try:
        d = datetime.fromisoformat(t.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _outcome(o):
    """Only the measured numbers and flags; anything else a record carries stays home."""
    if not isinstance(o, dict):
        return {}
    return {k: o[k] for k in ("ok", "failed", "verdict", "receipt", "good", "timeout", "error")
            if k in o and isinstance(o[k], (bool, int, float, type(None)))}


def _read_records(path, counts):
    with open(path, encoding="utf-8", errors="replace") as f:
        for ln in f:
            if not ln.strip():
                continue
            try:
                rec = json.loads(ln)
            except ValueError:
                counts["unreadable"] += 1
                continue
            if not isinstance(rec, dict):
                counts["unreadable"] += 1
                continue
            yield rec


def export(src, fmt, since=None, redact=True, allow_hosts=(), allow_nets=(), good_only=False, home=None,
           user=None):
    """(lines, counts): one validated JSON line per exported trajectory. Pure: reads src, writes nothing."""
    if fmt not in FORMATS:
        raise ValueError(f"--format is one of {', '.join(FORMATS)}")
    counts = {"exported": 0, "unreadable": 0, "before_since": 0, "empty": 0, "not_good": 0, "invalid": 0}
    red = None
    if redact:
        # program handles first, over the whole file: a handle seen only in line 9 must be gone from line 1 too
        programs = {r.get("program") for r in _read_records(src, dict(counts)) if isinstance(r.get("program"), str)}
        red = Redactor(allow_hosts, allow_nets, home=home, user=user, terms=sorted(p for p in programs if p))
    lines = []
    for n, rec in enumerate(_read_records(src, counts), 1):
        if since is not None:
            t = _ts(rec)
            if t is None or t < since:
                counts["before_since"] += 1
                continue
        if not rec.get("messages"):
            counts["empty"] += 1
            continue
        if good_only and (rec.get("outcome") or {}).get("good") is not True:
            counts["not_good"] += 1
            continue
        try:
            msgs = normalize(rec["messages"])
            if red is not None:
                msgs = redact_messages(msgs, red)
            if fmt == "openai":
                out = to_openai(msgs)
            else:
                meta = {"id": str(rec.get("id") or f"t{n}"), "ts": str(rec.get("ts") or ""),
                        "outcome": _outcome(rec.get("outcome"))}
                prog = rec.get("program")
                if isinstance(prog, str) and prog:
                    meta["program"] = red.term_placeholder(prog) if red is not None else prog
                if isinstance(rec.get("held"), list):
                    held = [{"tool": str(h.get("tool") or ""), "args": str(h.get("args") or "")}
                            for h in rec["held"] if isinstance(h, dict)]
                    meta["held"] = red.obj(held) if red is not None else held
                if red is not None:
                    meta["id"] = red.text(meta["id"])
                out = to_sharegpt(msgs, meta)
            VALIDATORS[fmt](out)
        except Invalid:
            counts["invalid"] += 1
            continue
        lines.append(json.dumps(out, ensure_ascii=False))
        counts["exported"] += 1
    return lines, counts


def _write_private(path, data):
    """Atomic, mode 0600: an export can hold what redaction missed, so it is never world-readable, and a crash
    never leaves half a file under the real name."""
    path = os.path.abspath(os.path.expanduser(path))
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".gnoc-export-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    return path


def default_source():
    import gnoc_learn
    return gnoc_learn.TRAJ


def cmd_trajectories(argv, out=None, err=None):
    out, err = out or sys.stdout, err or sys.stderr
    ap = argparse.ArgumentParser(prog="gnoc export trajectories", description="export logged trajectories")
    ap.add_argument("--format", choices=FORMATS, required=True)
    ap.add_argument("--since", help="only trajectories on or after this date (YYYY-MM-DD, UTC)")
    ap.add_argument("--out", help="write here (mode 0600) instead of stdout")
    ap.add_argument("--from", dest="src", help="the trajectories file (default: the one gnoc chat logs to)")
    ap.add_argument("--allow", action="append", default=[], help="host, IP or CIDR to keep (comma-separated)")
    ap.add_argument("--good-only", action="store_true", help="only turns whose measured outcome was good")
    ap.add_argument("--redact", action="store_true", help="the default; accepted and ignored")
    ap.add_argument("--no-redact", action="store_true", help="turn redaction off (prints a warning)")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return int(e.code or 0)
    if a.redact and a.no_redact:
        print("--redact and --no-redact contradict each other", file=err)
        return 2
    try:
        since = parse_since(a.since) if a.since else None
    except ValueError as e:
        print(str(e), file=err)
        return 2
    src = os.path.expanduser(a.src) if a.src else default_source()
    if not os.path.isfile(src):
        print(f"no trajectories yet: {src} does not exist (gnoc chat logs one per turn that used tools)", file=err)
        return 1
    hosts, nets = load_allowlist(extra=[h for x in a.allow for h in x.split(",")])
    if a.no_redact:
        print("WARNING: --no-redact: secrets, paths, IP addresses and hostnames are exported as logged. Do not share "
              "this file.", file=err)
    lines, counts = export(src, a.format, since=since, redact=not a.no_redact, allow_hosts=hosts, allow_nets=nets,
                           good_only=a.good_only)
    data = "".join(ln + "\n" for ln in lines)
    where = "stdout"
    if a.out:
        where = _write_private(a.out, data)
    else:
        out.write(data)
        out.flush()
    skipped = ", ".join(f"{v} {k.replace('_', ' ')}" for k, v in counts.items() if k != "exported" and v)
    print(f"exported {counts['exported']} trajectories ({a.format}, redaction {'OFF' if a.no_redact else 'on'}) "
          f"to {where}" + (f"; skipped: {skipped}" if skipped else ""), file=err)
    return 0

# ---------------------------------------------------------------- batch


def load_prompts(path):
    """[{id, prompt}] from a JSONL file. Any bad line refuses the whole batch, naming the line: a batch that ran 999
    prompts and silently dropped the thousandth is worse than one that did not start."""
    items, ids = [], set()
    with open(path, encoding="utf-8") as f:
        for n, ln in enumerate(f, 1):
            if not ln.strip():
                continue
            try:
                o = json.loads(ln)
            except ValueError as e:
                raise ValueError(f"line {n}: not JSON ({e.msg})") from e
            if not isinstance(o, dict):
                raise ValueError(f"line {n}: each line is an object like {{\"prompt\": \"...\"}}")
            p = o.get("prompt")
            if not isinstance(p, str) or not p.strip():
                raise ValueError(f"line {n}: \"prompt\" must be a non-empty string")
            if len(p) > MAX_PROMPT_CHARS:
                raise ValueError(f"line {n}: the prompt is over {MAX_PROMPT_CHARS} characters")
            pid = o.get("id", f"p{len(items) + 1}")
            if isinstance(pid, bool) or not isinstance(pid, (str, int)) or not str(pid).strip():
                raise ValueError(f"line {n}: \"id\" must be a string or a number")
            pid = str(pid)
            if pid in ids:
                raise ValueError(f"line {n}: duplicate id {pid!r}")
            ids.add(pid)
            items.append({"id": pid, "prompt": p})
            if len(items) > MAX_PROMPTS:
                raise ValueError(f"more than {MAX_PROMPTS} prompts; split the file")
    if not items:
        raise ValueError("no prompts in the file")
    return items


def _args_summary(args):
    try:
        s = json.dumps(args, default=str, sort_keys=True)
    except (TypeError, ValueError):
        s = repr(args)
    return s if len(s) <= 300 else s[:300] + "..."


def _isolate(G):
    """A private session, history, checkpoints and goal for one batch prompt (the shape gnoc_train uses), plus the
    function that puts the real paths back. The lesson book is not touched: learning is off in a batch."""
    import gnoc_goal
    d = tempfile.mkdtemp(prefix="gnoc-batch-")
    agent = os.path.join(d, "agent")
    os.makedirs(agent)
    names = {"AGENT_DIR": agent, "SESSION": os.path.join(agent, "session.json"), "OUT_DIR": os.path.join(agent, "out"),
             "JOBS_DIR": os.path.join(agent, "jobs"), "SESSIONS_DIR": os.path.join(agent, "sessions")}
    saved = {k: getattr(G, k) for k in names if hasattr(G, k)}
    saved_goal = gnoc_goal.PATH
    for k, v in names.items():
        if k in saved:
            setattr(G, k, v)
    gnoc_goal.PATH = os.path.join(agent, "goal.json")

    def restore():
        for k, v in saved.items():
            setattr(G, k, v)
        gnoc_goal.PATH = saved_goal
        import shutil
        shutil.rmtree(d, ignore_errors=True)
    return restore


def run_one(item, steps=24):
    """One prompt through a fresh non-interactive Agent; returns the trajectory record (log_trajectory's schema plus
    id, held and source). Every call that needs approval goes to `hold` instead of a prompt: it is recorded and
    refused, so the dispatcher answers the model "not run" and nothing is executed."""
    import gnoc_agent as G
    import gnoc_learn as L
    held = []

    def hold(name, args, interactive):
        held.append({"tool": str(name), "args": _args_summary(args)})
        return False   # nobody can answer in a headless batch: every gated action is held, never run

    restore = _isolate(G)
    saved = (G.SKIP_PERMS[0], G.STEPS_OVERRIDE[0], G._approve, os.environ.get("GNOC_NO_LEARN"))
    G.SKIP_PERMS[0] = False   # a batch never inherits skip-perms: "everything gated is held" is the contract
    G._approve = hold
    os.environ["GNOC_NO_LEARN"] = "1"   # a batch writes its own output, never the user's lesson book
    try:
        agent = G.Agent(interactive=False)
        agent.s["learn"] = False
        agent.s["auto"] = False
        agent.s["steps_override"] = steps
        G.STEPS_OVERRIDE[0] = steps
        agent.turn(item["prompt"])
        hist = list(agent.s.get("history") or [])
        rec = L.trajectory_record(hist, agent.ctx.program, L.turn_outcome(hist))
    finally:
        G.SKIP_PERMS[0], G.STEPS_OVERRIDE[0], G._approve = saved[0], saved[1], saved[2]
        if saved[3] is None:
            os.environ.pop("GNOC_NO_LEARN", None)
        else:
            os.environ["GNOC_NO_LEARN"] = saved[3]
        restore()
    rec.update({"id": item["id"], "source": "batch", "held": held})
    try:   # known secret values, as log_trajectory's caller scrubbed tool results; the export redacts the rest
        import gnoc_secrets
        rec = json.loads(gnoc_secrets.redact(json.dumps(rec)))
    except Exception:  # noqa: BLE001
        pass
    return rec


def _child_main(argv):
    """`gnoc_trajectories.py _batch-one IN OUT STEPS`: the child side of one batch prompt."""
    in_path, out_path, steps = argv[0], argv[1], int(argv[2])
    with open(in_path, encoding="utf-8") as f:
        item = json.load(f)
    import gnoc_agent as G
    G._ACTIVE_ROOT[0] = os.getcwd()   # the folder `gnoc export batch` ran in, as `gnoc chat` would use
    rec = run_one(item, steps=steps)
    _write_private(out_path, json.dumps(rec))
    return 0


def _child_cmd(in_path, out_path, steps):
    return [sys.executable, os.path.abspath(__file__), "_batch-one", in_path, out_path, str(steps)]


def _kill(proc):
    """The whole process group: a turn may have started a shell, a worker or a browser under the child."""
    with contextlib.suppress(OSError, ProcessLookupError):
        if os.name == "posix":
            os.killpg(proc.pid, signal.SIGTERM)
        else:
            proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(OSError, ProcessLookupError):
            if os.name == "posix":
                os.killpg(proc.pid, signal.SIGKILL)
            else:
                proc.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=3)


def _stub(item, error):
    return {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "program": None, "id": item["id"],
            "source": "batch", "outcome": {"good": None, "error": True}, "error": error, "messages": [], "held": []}


def run_batch(items, out_dir, workers=2, timeout=600.0, steps=24, cmd_for=None, tick=time.sleep, err=None):
    """Run every item in a bounded pool of child processes. Returns (exit code, summary dict). Writes
    out_dir/trajectories.jsonl (input order, one line per prompt; a failed prompt is a line with "error" and no
    messages) and out_dir/logs/<n>.log. cmd_for and tick exist for tests (a fake child, a fake Ctrl-C)."""
    err = err or sys.stderr
    if not 1 <= int(workers) <= MAX_WORKERS:
        raise ValueError(f"--workers is 1 to {MAX_WORKERS}")
    if not 1 <= int(steps) <= MAX_STEPS:
        raise ValueError(f"--steps is 1 to {MAX_STEPS}")
    cmd_for = cmd_for or (lambda i, o: _child_cmd(i, o, steps))
    out_dir = os.path.abspath(os.path.expanduser(out_dir))
    final = os.path.join(out_dir, "trajectories.jsonl")
    if os.path.exists(final):
        raise ValueError(f"{final} already exists; pick a new --out folder")
    for sub in ("", "items", "logs"):
        os.makedirs(os.path.join(out_dir, sub), mode=0o700, exist_ok=True)
    results = {}
    queue = list(enumerate(items))
    running = {}   # n -> (proc, started, log file)
    group = {"start_new_session": True} if os.name == "posix" else \
        {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
    interrupted = False
    try:
        while queue or running:
            while queue and len(running) < int(workers):
                n, item = queue.pop(0)
                in_path = os.path.join(out_dir, "items", f"{n:05d}.in.json")
                rec_path = os.path.join(out_dir, "items", f"{n:05d}.json")
                _write_private(in_path, json.dumps(item))
                # 0600 from the first byte: a turn's log can print what redaction is there to catch
                log = os.fdopen(os.open(os.path.join(out_dir, "logs", f"{n:05d}.log"),
                                        os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w", encoding="utf-8")
                proc = subprocess.Popen(cmd_for(in_path, rec_path), stdin=subprocess.DEVNULL, stdout=log,
                                        stderr=subprocess.STDOUT, cwd=os.getcwd(), **group)
                running[n] = (proc, time.monotonic(), log, rec_path)
            for n in list(running):
                proc, t0, log, rec_path = running[n]
                code = proc.poll()
                if code is None and time.monotonic() - t0 > timeout:
                    _kill(proc)
                    results[n] = _stub(items[n], f"timed out after {timeout:g}s")
                    results[n]["outcome"]["timeout"] = True
                elif code is None:
                    continue
                else:
                    try:
                        with open(rec_path, encoding="utf-8") as f:
                            results[n] = json.load(f)
                    except (OSError, ValueError):
                        results[n] = _stub(items[n], f"the run ended (exit {code}) without a trajectory; see "
                                                     f"logs/{n:05d}.log")
                log.close()
                del running[n]
                print(f"[{len(results)}/{len(items)}] {items[n]['id']}: "
                      + (results[n].get("error") or f"{len(results[n].get('held') or [])} held"), file=err)
            if running:
                tick(0.1)
    except KeyboardInterrupt:
        interrupted = True
        for n, (proc, _, log, _) in list(running.items()):
            _kill(proc)
            log.close()
            results[n] = _stub(items[n], "interrupted (Ctrl-C)")
        running.clear()
        print("interrupted: every running prompt was stopped", file=err)
    for n, item in enumerate(items):
        results.setdefault(n, _stub(item, "not run (interrupted before it started)"))
    _write_private(final, "".join(json.dumps(results[n]) + "\n" for n in range(len(items))))
    summary = {"prompts": len(items), "ok": sum(1 for r in results.values() if not r.get("error")),
               "failed": sum(1 for r in results.values() if r.get("error")),
               "held": sum(len(r.get("held") or []) for r in results.values()), "out": final}
    print(f"batch done: {summary['ok']} ran, {summary['failed']} failed or stopped, {summary['held']} actions held "
          f"for approval (never run). Trajectories: {final}  (export them: gnoc export trajectories --from {final} "
          "--format sharegpt)", file=err)
    return (130 if interrupted else 0), summary


def cmd_batch(argv, err=None):
    err = err or sys.stderr
    ap = argparse.ArgumentParser(prog="gnoc export batch", description="run a JSONL of prompts headless")
    ap.add_argument("prompts", help='JSONL, one {"prompt": "...", "id": "..."} per line')
    ap.add_argument("--out", required=True, help="a new folder for trajectories.jsonl and the logs")
    ap.add_argument("--workers", type=int, default=2, help=f"prompts at once (1-{MAX_WORKERS}, default 2)")
    ap.add_argument("--timeout", type=float, default=600.0, help="wall-clock seconds per prompt (default 600)")
    ap.add_argument("--steps", type=int, default=24, help=f"tool-loop steps per prompt (1-{MAX_STEPS}, default 24)")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return int(e.code or 0)
    if not 1 <= a.workers <= MAX_WORKERS or not 1 <= a.steps <= MAX_STEPS or not 5 <= a.timeout <= 86400:
        print(f"--workers is 1-{MAX_WORKERS}, --steps 1-{MAX_STEPS}, --timeout 5-86400 seconds", file=err)
        return 2
    try:
        items = load_prompts(a.prompts)
    except (OSError, ValueError) as e:
        print(f"refused: {a.prompts}: {e}", file=err)
        return 2
    try:
        code, _ = run_batch(items, a.out, workers=a.workers, timeout=a.timeout, steps=a.steps, err=err)
    except ValueError as e:
        print(f"refused: {e}", file=err)
        return 2
    return code


USAGE = """gnoc export - trajectories for training, redacted by default

  gnoc export trajectories --format sharegpt|openai [--since YYYY-MM-DD] [--out PATH] [--good-only]
                           [--allow host,...] [--from PATH] [--no-redact]
  gnoc export batch <prompts.jsonl> --out DIR [--workers N] [--timeout SECONDS] [--steps N]
"""


def main(argv):
    if argv and argv[0] == "_batch-one":
        return _child_main(argv[1:])
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE)
        return 0 if argv else 2
    if argv[0] == "trajectories":
        return cmd_trajectories(argv[1:])
    if argv[0] == "batch":
        return cmd_batch(argv[1:])
    print(f"unknown: gnoc export {argv[0]}\n\n{USAGE}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

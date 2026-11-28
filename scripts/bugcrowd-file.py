#!/usr/bin/env /usr/bin/python3
"""bugcrowd-file.py - fill (prepare) and, on explicit confirmation, submit a Bugcrowd report
from a draft folder, driving the user's live authenticated Chrome over CDP.

    bugcrowd-file.py prepare <program>/<slug> [--engagement <code>] [--cdp-port 9222]
    bugcrowd-file.py submit  <program>/<slug> --confirm "<exact SUBMIT-TITLE.txt text>"

Draft layout read (reports/drafts/<program>/<slug>/):
    SUBMIT-TITLE.txt   the title; compared byte for byte with --confirm (one trailing newline ignored)
    SUBMIT-BODY.txt    the description, pasted verbatim
    FORM.md            Engagement:, Target: (or Asset:), VRT: <leaf id>, CVSS: (empty or vector),
                       Terms: accept
    upload-bundle/     every file is attached except MANIFEST.md

Written into the draft folder: filing-preview-<ts>.png, filing-result-<ts>.png,
.bugcrowd-filing.json (the prepared tab id and edit URL), SUBMITTED.md (on a confirmed submit).

prepare NEVER clicks submit. submit never retries. Neither ever navigates a tab it did not create.

Mechanics, all measured on real filings (memory killrule-bugcrowd-vrt-picker-rejects-a-programmatic-
hidden-input-2026-11-04):
  - The VRT widget ignores a programmatically set hidden input; submit then silently no-ops. It is
    driven by KEYBOARD: focus .vrt-dropdown__select, Enter, then per level focus the item's
    role=option node with JS (the <li> on a category row, the inner <span> on a subcategory row)
    and press Enter. Verified by BOTH .bc-badge-label AND the hidden original_vrt_id.
  - Input.dispatchMouseEvent does not land on the cdp-chrome browser; key events do.
  - Input.dispatchKeyEvent takes ONE char per event; type-ahead picks the wrong leaf, so none here.
  - Turnstile renders in invisible/execute mode on this form and does NOT self-solve; the driver
    calls turnstile.execute() on #cf-turnstile once the tab is foregrounded (token in ~4 s).
  - Filling /submissions/new autosaves a DRAFT and redirects to /submissions/<uuid>/edit.
  - A url_match on "bugcrowd.com" once navigated the already-FILED report tab, so every call here
    goes to a FRESH target from Target.createTarget, addressed by its target id.

Exit codes: 0 ok, 2 NEEDS Bugcrowd session, 3 prepared but Turnstile pending, 4 NEEDS/refused,
5 FAILED-SILENT (submit did not leave /edit), 6 page state does not match the draft.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
LOCAL_VRT = SCRIPTS / "bbtools" / "data" / "vrt.json"
MAX_BYTES = 50 * 1024 * 1024
STATE_NAME = ".bugcrowd-filing.json"
BASE = "https://bugcrowd.com"
UUID_RE = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


def drafts_root():
    """Overridable for tests; production is reports/drafts."""
    return Path(os.environ.get("BUGCROWD_FILE_DRAFTS") or (ROOT / "reports" / "drafts"))


class Needs(Exception):
    """A stop with a NEEDS line and a non-zero exit code."""

    def __init__(self, msg, code=4):
        super().__init__(msg)
        self.code = code


# --------------------------------------------------------------------------------------------
# PURE HELPERS (unit-tested in scripts/test_bugcrowd_file.py)
# --------------------------------------------------------------------------------------------

def _line(text, pattern):
    m = re.search(pattern, text, flags=re.I | re.M)
    return m.group(1).strip() if m else None


def parse_form(text):
    """Parse FORM.md. Returns engagement, target, vrt_id, cvss_mode ('empty'|'vector'|None),
    cvss_vector, terms (True|False|None when FORM.md does not say)."""
    out = {"engagement": None, "target": None, "vrt_id": None, "cvss_mode": None,
           "cvss_vector": None, "terms": None}
    eng = _line(text, r"^\s*[*_]*Engagement[*_]*\s*:[*_]*\s*`?([A-Za-z0-9_.-]+)`?")
    out["engagement"] = eng
    # "Target:" wins over "Asset:"; "Target group:" must not match.
    tgt = _line(text, r"^\s*[*_]*Target[*_]*\s*:[*_]*\s*(.+)$") or _line(text, r"^\s*[*_]*Asset[*_]*\s*:[*_]*\s*(.+)$")
    if tgt:
        out["target"] = tgt.strip("` ")
    out["vrt_id"] = _line(text, r"^\s*[*_]*VRT[*_]*\s*:[*_]*\s*`?([a-z0-9_]+(?:\.[a-z0-9_]+)+)")
    cvss = _line(text, r"^(\s*[*_]*CVSS[*_]*\s*:.*)$")
    if cvss is not None:
        vec = re.search(r"CVSS:3\.[01]/[A-Z:/]+", cvss)
        if re.search(r"\b(leave\b.*\bempty|empty|blank|none|n/a)\b", cvss, flags=re.I) and not vec:
            out["cvss_mode"] = "empty"
        elif vec:
            out["cvss_mode"] = "vector"
            out["cvss_vector"] = vec.group(0)
    terms = _line(text, r"^\s*[*_]*Terms(?:\s+and\s+conditions)?[*_]*\s*:[*_]*\s*(.*)$")
    if terms is not None:
        if re.search(r"\b(do not|don't|never|no|false|leave unchecked)\b", terms, flags=re.I):
            out["terms"] = False
        elif re.search(r"\b(accept|agree|yes|true|check|tick)\w*", terms, flags=re.I):
            out["terms"] = True
    return out


def resolve_vrt_path(taxonomy, leaf_id):
    """Map a dotted VRT leaf id to its keyboard path of display labels.
    Raises ValueError if the id is unknown or names a parent node."""
    nodes = taxonomy.get("content") if isinstance(taxonomy, dict) else taxonomy
    parts = (leaf_id or "").split(".")
    path, prio, level = [], None, nodes or []
    for i, part in enumerate(parts):
        node = next((n for n in level if n.get("id") == part), None)
        if node is None:
            raise ValueError("VRT id not in taxonomy: %s (failed at %r)" % (leaf_id, part))
        path.append(node.get("name") or "")
        prio = node.get("priority")
        level = node.get("children") or []
        if i == len(parts) - 1 and level:
            raise ValueError("VRT id is a parent node, not a leaf: %s" % leaf_id)
    if not path:
        raise ValueError("empty VRT id")
    return {"id": leaf_id, "path": path, "badge": " > ".join(path), "priority": prio}


ALLOW_VARIES = False  # set by --allow-varies: GreyNOC's explicit per-filing override for a "varies" (null) leaf


def vrt_floor_ok(priority):
    """Bugcrowd P3 floor (2026-11-05): only P1-P3 are filed. null (varies) is refused too,
    unless the operator passes --allow-varies for this one filing (the user 2026-11-10: the leaf's band
    is set by the programme; the floor's intent is never to file a P4/P5)."""
    if priority is None and ALLOW_VARIES:
        print("NOTE: VRT leaf priority is varies (null); filed under the user's explicit --allow-varies override")
        return True
    return priority in (1, 2, 3)


def _md5(path):
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_attachments(bundle_dir, max_bytes=MAX_BYTES):
    """List the files to attach from upload-bundle/. Excludes MANIFEST.md. Raises ValueError on a
    missing dir, a subdirectory, a dotfile, an empty file, a file over max_bytes, or two files with
    the same md5 (the byte-identical-panels-under-different-names defect)."""
    d = Path(bundle_dir)
    if not d.is_dir():
        raise ValueError("upload-bundle/ missing: %s" % d)
    out, seen = [], {}
    for p in sorted(d.iterdir(), key=lambda x: x.name):
        if p.name == "MANIFEST.md":
            continue
        if p.name.startswith("."):
            raise ValueError("unexpected dotfile in upload-bundle: %s" % p.name)
        if p.is_dir() or not p.is_file():
            raise ValueError("unexpected non-file in upload-bundle: %s" % p.name)
        size = p.stat().st_size
        if size == 0:
            raise ValueError("zero-byte file in upload-bundle: %s" % p.name)
        if size > max_bytes:
            raise ValueError("file over %d bytes: %s (%d)" % (max_bytes, p.name, size))
        md5 = _md5(p)
        if md5 in seen:
            raise ValueError("duplicate md5 %s: %s and %s" % (md5, seen[md5], p.name))
        seen[md5] = p.name
        out.append({"name": p.name, "path": str(p.resolve()), "size": size, "md5": md5})
    return out


def title_from_file(raw):
    """SUBMIT-TITLE.txt bytes -> title str. One trailing newline is ignored; anything else odd refuses."""
    if raw.endswith(b"\r\n"):
        raw = raw[:-2]
    elif raw.endswith(b"\n"):
        raw = raw[:-1]
    t = raw.decode("utf-8")
    if not t.strip():
        raise ValueError("SUBMIT-TITLE.txt is empty")
    if "\n" in t or "\r" in t:
        raise ValueError("SUBMIT-TITLE.txt has more than one line")
    if t.lstrip().startswith("#"):
        raise ValueError("SUBMIT-TITLE.txt starts with '#' (stray markdown heading)")
    if t != t.strip():
        raise ValueError("SUBMIT-TITLE.txt has leading or trailing whitespace")
    return t


def confirm_matches(confirm, title_raw):
    """--confirm must equal SUBMIT-TITLE.txt byte for byte (one trailing newline ignored)."""
    if confirm is None:
        return False
    body = title_raw[:-2] if title_raw.endswith(b"\r\n") else (
        title_raw[:-1] if title_raw.endswith(b"\n") else title_raw)
    return confirm.encode("utf-8") == body


def body_digest(raw):
    """sha256 and UTF-16 length (what JS .length reports) of SUBMIT-BODY.txt."""
    text = raw.decode("utf-8")
    return {"sha256": hashlib.sha256(raw).hexdigest(), "len": len(text.encode("utf-16-le")) // 2}


def classify_page(url, title, text, has_form):
    """'form' | 'login' | 'forbidden' | 'other' for the page a fresh tab landed on."""
    if has_form:
        return "form"
    u = (url or "").lower()
    if re.search(r"sign_in|/login|identity\.bugcrowd|/sessions/new|/auth/", u):
        return "login"
    blob = ((title or "") + " " + (text or "")[:2000]).lower()
    if re.search(r"\b(log in|sign in)\b", blob) and "submission" not in blob:
        return "login"
    if re.search(r"\b403\b|forbidden|access denied|not authorized|you need to sign in", blob):
        return "forbidden"
    return "other"


def form_url_ok(url, engagement):
    pat = r"^%s/engagements/%s/submissions/(new|%s/edit)(\?.*)?$" % (
        re.escape(BASE), re.escape(engagement), UUID_RE)
    return bool(re.match(pat, url or ""))


def edit_uuid(url):
    m = re.search(r"/submissions/(%s)/edit" % UUID_RE, url or "")
    return m.group(1) if m else None


def extract_submission(url):
    """After submit: the submission id and URL, or None while still on a form page."""
    if not url or re.search(r"/edit(\?|#|$)|/submissions/new", url):
        return None
    m = re.search(r"/submissions/(%s)" % UUID_RE, url)
    return {"id": m.group(1), "url": url} if m else None


def verification_diff(expected, observed, phase="prepare"):
    """Compare what the draft says with what the page holds. Returns rows
    (field, expected, observed, ok, blocking). phase 'submit' makes Turnstile and terms blocking."""
    rows = []

    def row(field, exp, obs, ok, blocking=True):
        rows.append({"field": field, "expected": exp, "observed": obs, "ok": bool(ok),
                     "blocking": blocking})

    eng = expected["engagement"]
    row("url", "%s/engagements/%s/submissions/<new|uuid/edit>" % (BASE, eng), observed.get("url"),
        form_url_ok(observed.get("url"), eng))
    row("title", expected["title"], observed.get("title"), observed.get("title") == expected["title"])
    row("target", expected["target"], observed.get("target"), observed.get("target") == expected["target"])
    row("vrt_label", expected["vrt_badge"], observed.get("vrt_label"),
        observed.get("vrt_label") == expected["vrt_badge"])
    row("vrt_id", expected["vrt_id"], observed.get("vrt_id"), observed.get("vrt_id") == expected["vrt_id"])
    row("desc_sha256", expected["desc_sha256"], observed.get("desc_sha256"),
        observed.get("desc_sha256") == expected["desc_sha256"])
    row("desc_len", expected["desc_len"], observed.get("desc_len"),
        observed.get("desc_len") == expected["desc_len"])
    exp_names = sorted(a["name"] for a in expected["attachments"])
    got = sorted(observed.get("attachments") or [])
    extras = sorted(set(observed.get("attachment_extras") or []) - set(exp_names))
    row("attachments", exp_names, got, got == exp_names)
    row("attachment_count", len(exp_names), len(got), len(got) == len(exp_names))
    row("attachment_extras", [], extras, not extras)
    vals = [v for v in (observed.get("cvss_values") or []) if (v or "").strip()]
    if expected.get("cvss_mode") == "vector":
        row("cvss", expected.get("cvss_vector"), vals,
            any(expected["cvss_vector"] in v for v in vals))
    else:
        row("cvss", "empty", vals, not vals)
    terms_obs = observed.get("terms")
    if expected.get("terms") is True:
        row("terms", True, terms_obs, terms_obs is True)
    elif phase == "submit" and terms_obs is False:
        row("terms", "FORM.md has no 'Terms: accept' line", terms_obs, False)
    else:
        row("terms", expected.get("terms"), terms_obs, True, blocking=False)
    tl = observed.get("turnstile_len") or 0
    row("turnstile", "solved (non-empty)", "len=%d" % tl, tl > 0, blocking=(phase == "submit"))
    return rows


def blocking_failures(rows):
    return [r for r in rows if r["blocking"] and not r["ok"]]


def format_rows(rows):
    out = []
    for r in rows:
        flag = "OK  " if r["ok"] else ("FAIL" if r["blocking"] else "WARN")
        obs = r["observed"]
        exp = r["expected"]
        if isinstance(obs, list) and len(obs) > 6:
            obs = "%d items" % len(obs)
        if isinstance(exp, list) and len(exp) > 6:
            exp = "%d items" % len(exp)
        out.append("  %s %-18s observed=%s" % (flag, r["field"], json.dumps(obs, ensure_ascii=True)))
        if not r["ok"]:
            out.append("       %-18s expected=%s" % ("", json.dumps(exp, ensure_ascii=True)))
    return "\n".join(out)


def ship_row(program, slug, submitted_md, submission, engagement, ts):
    """The ships.jsonl row. hunt-state.py only accepts kind draft|submission, so a filing is
    kind=submission with status=submitted (the existing Bugcrowd row uses the same kind)."""
    return {"ts": ts, "program": program, "kind": "submission", "status": "submitted",
            "target": engagement, "slug": slug, "path": str(submitted_md),
            "notes": "filed by scripts/bugcrowd-file.py submit; bugcrowd submission %s %s"
                     % (submission["id"], submission["url"])}


def submitted_line(ts, engagement, submission, expected, shot_name):
    return ("- %s SUBMITTED via scripts/bugcrowd-file.py: engagement %s, submission %s, url %s, "
            "vrt %s, desc sha256 %s, %d attachment(s), screenshot %s\n"
            % (ts, engagement, submission["id"], submission["url"], expected["vrt_id"],
               expected["desc_sha256"], len(expected["attachments"]), shot_name))


def draft_dir(spec):
    if not re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", spec or "") or ".." in spec:
        raise Needs("NEEDS: draft must be <program>/<slug>, got %r" % spec)
    d = drafts_root() / spec
    if not d.is_dir():
        raise Needs("NEEDS: no draft folder %s" % d)
    return d


def load_expected(d, engagement_override=None):
    """Everything the page must end up holding, computed from disk only."""
    for f in ("SUBMIT-TITLE.txt", "SUBMIT-BODY.txt", "FORM.md"):
        if not (d / f).is_file():
            raise Needs("NEEDS: draft is missing %s" % f)
    title_raw = (d / "SUBMIT-TITLE.txt").read_bytes()
    body_raw = (d / "SUBMIT-BODY.txt").read_bytes()
    try:
        title = title_from_file(title_raw)
        body = body_raw.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as e:
        raise Needs("NEEDS: %s" % e)
    if not body.strip():
        raise Needs("NEEDS: SUBMIT-BODY.txt is empty")
    form = parse_form((d / "FORM.md").read_text(encoding="utf-8"))
    engagement = engagement_override or form["engagement"]
    if not engagement:
        raise Needs("NEEDS: FORM.md has no 'Engagement:' line and --engagement was not given")
    if form["engagement"] and engagement_override and form["engagement"] != engagement_override:
        raise Needs("NEEDS: --engagement %s disagrees with FORM.md Engagement: %s"
                    % (engagement_override, form["engagement"]))
    if not form["target"]:
        raise Needs("NEEDS: FORM.md has no 'Target:' or 'Asset:' line")
    if not form["vrt_id"]:
        raise Needs("NEEDS: FORM.md has no 'VRT: <leaf id>' line")
    if form["cvss_mode"] is None:
        raise Needs("NEEDS: FORM.md must say CVSS: empty, or give a CVSS:3.1/ vector")
    try:
        atts = build_attachments(d / "upload-bundle")
    except ValueError as e:
        raise Needs("NEEDS: %s" % e)
    dg = body_digest(body_raw)
    return {"engagement": engagement, "title": title, "title_raw": title_raw, "body": body,
            "desc_sha256": dg["sha256"], "desc_len": dg["len"], "target": form["target"],
            "vrt_id": form["vrt_id"], "vrt_badge": None, "vrt_path": None,
            "cvss_mode": form["cvss_mode"], "cvss_vector": form["cvss_vector"],
            "terms": form["terms"], "attachments": atts}


def apply_vrt(expected, taxonomy, source):
    try:
        v = resolve_vrt_path(taxonomy, expected["vrt_id"])
    except ValueError as e:
        raise Needs("NEEDS: %s (%s taxonomy)" % (e, source))
    if not vrt_floor_ok(v["priority"]):
        raise Needs("REFUSED: VRT %s is %s in the %s taxonomy; Bugcrowd floor is P3 or above"
                    % (v["id"], "P%s" % v["priority"] if v["priority"] else "varies (null)", source))
    expected["vrt_path"] = v["path"]
    expected["vrt_badge"] = v["badge"]
    expected["vrt_priority"] = v["priority"]
    return expected


def now_ts():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def iso_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------------------------
# CDP LAYER (live only; never exercised by the unit tests)
# --------------------------------------------------------------------------------------------

class Tab:
    """A persistent CDP session to ONE page target, addressed by target id (never by URL match).
    Persistent because DOM.setFileInputFiles needs a RemoteObject id from the same session.
    Connection shape mirrors lib_browser.cdp_ws_call: literal loopback IPs, no Origin header."""

    def __init__(self, target_id, port):
        import websocket
        self.target_id, self.port, self.ws, self._id = target_id, port, None, 0
        last = None
        for ip in ("[::1]", "127.0.0.1"):
            try:
                tabs = json.load(urllib.request.urlopen("http://%s:%s/json" % (ip, port), timeout=5))
            except Exception as e:
                last = e
                continue
            t = next((x for x in tabs if x.get("id") == target_id and x.get("type") == "page"), None)
            if not t:
                raise Needs("NEEDS: the prepared tab %s is gone (closed?). Run prepare again." % target_id)
            path = t["webSocketDebuggerUrl"].split("://", 1)[1].split("/", 1)[1]
            self.ws = websocket.create_connection("ws://%s:%s/%s" % (ip, port, path),
                                                  timeout=60, suppress_origin=True)
            return
        raise Needs("NEEDS: CDP not reachable on port %s (%s). Run scripts/cdp-chrome.sh." % (port, last))

    def send(self, method, params=None):
        self._id += 1
        my = self._id
        self.ws.send(json.dumps({"id": my, "method": method, "params": params or {}}))
        while True:
            m = json.loads(self.ws.recv())
            if m.get("id") == my:
                if "error" in m:
                    raise RuntimeError("CDP %s error: %s" % (method, m["error"]))
                return m.get("result", {})

    def ev(self, expr, by_value=True):
        r = self.send("Runtime.evaluate", {"expression": expr, "returnByValue": by_value,
                                           "awaitPromise": True, "userGesture": True})
        if r.get("exceptionDetails"):
            d = r["exceptionDetails"]
            raise RuntimeError("page JS exception: %s" % ((d.get("exception") or {}).get("description")
                                                          or d.get("text"))[:300])
        return r.get("result", {}).get("value") if by_value else r.get("result", {})

    def enter(self, with_text=False):
        for t in ("keyDown", "keyUp"):
            p = {"type": t, "key": "Enter", "code": "Enter",
                 "windowsVirtualKeyCode": 13, "nativeVirtualKeyCode": 13}
            if with_text and t == "keyDown":
                p["text"] = "\r"
                p["unmodifiedText"] = "\r"
            self.send("Input.dispatchKeyEvent", p)

    def front(self):
        self.send("Page.bringToFront")

    def screenshot(self, path):
        m = self.send("Page.getLayoutMetrics")
        size = m.get("cssContentSize") or m.get("contentSize") or {}
        w = max(1, int(size.get("width", 1280)))
        h = max(1, min(int(size.get("height", 2000)), 16000))
        r = self.send("Page.captureScreenshot", {"format": "png", "captureBeyondViewport": True,
                                                 "clip": {"x": 0, "y": 0, "width": w, "height": h,
                                                          "scale": 1}})
        Path(path).write_bytes(base64.b64decode(r["data"]))
        return path

    def close(self):
        try:
            self.ws.close()
        except Exception:
            pass


def browser_call(method, params, port):
    sys.path.insert(0, str(SCRIPTS))
    from bbtools.lib_browser import cdp_ws_call
    return cdp_ws_call(method, params, url_match=None, cdp_url="http://localhost:%s" % port)


SETTER = r"""
function gnocSet(el, v){
  const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype
              : el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto,'value').set.call(el, v);
  el.dispatchEvent(new Event('input',{bubbles:true}));
  el.dispatchEvent(new Event('change',{bubbles:true}));
}
"""

READBACK = r"""
(async () => {
  const q = s => document.querySelector(s);
  const names = %s;
  const sel = q('#submission_target_id');
  const ta = q('#submission_description');
  const d = ta ? ta.value : null;
  let sha = null;
  if (d !== null) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(d));
    sha = [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2,'0')).join('');
  }
  const w = q('.vrt-dropdown__select');
  let badge = null;
  for (let n = w, i = 0; n && i < 4 && !badge; n = n.parentElement, i++) badge = n.querySelector('.bc-badge-label');
  badge = badge || q('.bc-badge-label') || q('.vrt-dropdown__selection');  /* a 'varies' leaf renders no P badge; the picker's own selection text carries the same label */
  const hid = q('[name="submission[original_vrt_id]"]') || q('#vrt-form-input');
  // Only attachment containers count: the description body and any markdown preview name the
  // same files, so a whole-page text search would pass before a single byte was uploaded.
  const boxes = [...document.querySelectorAll('[class*=attachment i],[class*=upload i],[class*=dropzone i],[class*=file-list i],[class*=filelist i]')]
    .filter(el => !el.querySelector('textarea') && !el.closest('[class*=preview i],[class*=markdown i]'));
  const text = boxes.map(el => el.innerText || '').join('\n');
  const present = names.filter(n => text.includes(n));
  const fileRe = /^[\w .()\-]+\.[A-Za-z0-9]{1,6}$/;
  const extras = new Set();
  boxes.forEach(el => {
    (el.innerText || '').split('\n').map(s => s.trim()).filter(s => fileRe.test(s)).forEach(s => extras.add(s));
  });
  const cvss = [...document.querySelectorAll('input[name*=cvss i],input[id*=cvss i],select[name*=cvss i],textarea[name*=cvss i]')]
    .filter(e => (e.type !== 'radio' && e.type !== 'checkbox') || e.checked).map(e => e.value || '');
  const cb = q('#submission_terms_and_conditions');
  const ts = q('[name="cf-turnstile-response"]');
  return {
    url: location.href,
    title: (q('#submission_caption') || {}).value ?? null,
    target: sel && sel.selectedIndex >= 0 ? sel.options[sel.selectedIndex].text.trim() : null,
    vrt_label: badge ? badge.innerText.trim() : null,
    vrt_id: hid ? hid.value : null,
    desc_len: d === null ? null : d.length,
    desc_sha256: sha,
    attachments: present,
    attachment_extras: [...extras],
    cvss_values: cvss,
    terms: cb ? cb.checked : null,
    turnstile_len: ts ? (ts.value || '').length : 0,
    bug_url: (q('#submission_bug_url') || {}).value ?? null
  };
})()
"""


def readback(tab, expected):
    names = [a["name"] for a in expected["attachments"]]
    return tab.ev(READBACK % json.dumps(names))


def wait_form(tab, timeout=45):
    end = time.time() + timeout
    st = {}
    while time.time() < end:
        try:
            st = tab.ev("({url: location.href, title: document.title, ready: document.readyState,"
                        " text: document.body ? document.body.innerText.slice(0, 2000) : '',"
                        " form: !!document.querySelector('#submission_caption')})")
        except RuntimeError:
            st = {}
        if st.get("form") and st.get("ready") == "complete":
            return st
        time.sleep(1)
    kind = classify_page(st.get("url"), st.get("title"), st.get("text"), bool(st.get("form")))
    if kind in ("login", "forbidden"):
        raise Needs("NEEDS: Bugcrowd session (the form page answered %s at %s)" % (kind, st.get("url")),
                    code=2)
    raise Needs("NEEDS: the submission form did not render (page %r at %s)"
                % ((st.get("title") or "")[:80], st.get("url")))


def fetch_taxonomy(tab):
    txt = tab.ev("fetch('/vulnerability-rating-taxonomy.json',{credentials:'same-origin'})"
                 ".then(r => r.ok ? r.text() : Promise.reject(new Error('HTTP ' + r.status)))")
    try:
        return json.loads(txt)
    except Exception:
        raise Needs("NEEDS: same-origin VRT taxonomy did not parse as JSON")


def fill_fields(tab, expected):
    r = tab.ev(SETTER + r"""
    (() => {
      const q = s => document.querySelector(s), r = {};
      const sel = q('#submission_target_id');
      if (!sel) return {err: 'no target select'};
      const want = %s;
      const opts = [...sel.options].filter(o => o.text.trim() === want);
      if (opts.length !== 1) return {err: 'target option matches=' + opts.length + ' of ' + sel.options.length};
      gnocSet(sel, opts[0].value);
      const ta = q('#submission_description');
      if (!ta) return {err: 'no description textarea'};
      gnocSet(ta, %s);
      if (%s) {
        const cb = q('#submission_terms_and_conditions');
        if (!cb) return {err: 'FORM.md asks for terms but the page has no terms checkbox'};
        if (!cb.checked) cb.click();
      }
      return {ok: true};
    })()""" % (json.dumps(expected["target"]), json.dumps(expected["body"]),
               "true" if expected["terms"] is True else "false"))
    if not r or r.get("err"):
        raise Needs("NEEDS: form fill failed: %s" % (r or {}).get("err"))


VRT_STEP = r"""
(() => {
  const want = %s;
  const vis = e => !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length);
  const all = [...document.querySelectorAll('li[role=option], li.vrt-dropdown__opt')].filter((e, i, a) => a.indexOf(e) === i).filter(vis);
  const norm = s => (s || '').replace(/\s+/g, ' ').trim();
  const own = e => { const c = e.cloneNode(true); c.querySelectorAll('li,ul,[role=listbox]').forEach(x => x.remove());
                     return norm(c.textContent).replace(/^(P[1-5]|Varies)\s+|\s+(P[1-5]|Varies)$/g, ''); };
  const lab = e => norm(e.getAttribute('aria-label'));
  const first = e => norm((e.innerText || '').split('\n')[0]);
  const sub = e => /subcategory/.test(e.className) && norm(e.textContent).startsWith(want);
  const hit = all.filter(e => lab(e) === want || first(e) === want || own(e) === want || sub(e));
  const seen = window.__gnocSeen || new WeakSet();
  const fresh = hit.filter(e => !seen.has(e));
  const pick = fresh.length === 1 ? fresh[0] : (hit.length === 1 ? hit[0] : null);
  if (!pick) return {err: hit.length ? 'AMBIGUOUS' : 'NOTFOUND', n: hit.length, visible: all.length};
  // Category rows carry role=option on the <li>; subcategory rows carry it on an inner <span>
  // (measured 2026-11-09, Authentication Bypass). The widget's Enter handler listens on the
  // role=option node, so focus THAT, never the bare <li>.
  const tgt = pick.matches('[role=option]') ? pick : (pick.querySelector('[role=option]') || pick);
  tgt.scrollIntoView({block: 'center'});
  if (!tgt.hasAttribute('tabindex')) tgt.setAttribute('tabindex', '-1');
  tgt.focus();
  const s2 = new WeakSet(); all.forEach(e => s2.add(e)); window.__gnocSeen = s2;
  return {ok: document.activeElement === tgt};
})()
"""


def drive_vrt(tab, expected):
    r = tab.ev("(() => { const s = document.querySelector('.vrt-dropdown__select'); if (!s) return 'NOSELECT';"
               " s.scrollIntoView({block:'center'}); s.focus(); window.__gnocSeen = new WeakSet();"
               " return document.activeElement === s ? 'OK' : 'NOFOCUS'; })()")
    if r != "OK":
        raise Needs("NEEDS: VRT widget not focusable (%s)" % r)
    tab.enter()
    time.sleep(1.5)
    for label in expected["vrt_path"]:
        end, res = time.time() + 10, None
        while time.time() < end:
            res = tab.ev(VRT_STEP % json.dumps(label))
            if res and res.get("ok"):
                break
            time.sleep(0.5)
        if not res or not res.get("ok"):
            raise Needs("NEEDS: VRT item %r not selectable by keyboard (%s)" % (label, res))
        tab.enter()
        time.sleep(1.5)
    end = time.time() + 10
    while time.time() < end:
        ob = readback(tab, expected)
        if ob.get("vrt_label") == expected["vrt_badge"] and ob.get("vrt_id") == expected["vrt_id"]:
            return ob
        time.sleep(0.5)
    raise Needs("NEEDS: VRT did not take: badge %r, hidden id %r (want %r / %r)"
                % (ob.get("vrt_label"), ob.get("vrt_id"), expected["vrt_badge"], expected["vrt_id"]))


FILE_INPUT = r"""
(() => {
  const ins = [...document.querySelectorAll('input[type=file]')];
  const named = ins.filter(e => /attach/i.test((e.name || '') + ' ' + (e.id || '') + ' ' + (e.className || '') + ' ' + ((e.labels && e.labels[0]) ? e.labels[0].textContent : '') + ' ' + ((e.closest('label') || {}).textContent || '')) || /bc-file-input__input/.test(e.className || ''));
  const pick = named.length === 1 ? named[0] : (ins.length === 1 ? ins[0] : null);
  window.__gnocFile = pick;
  return pick ? {ok: true, multiple: !!pick.multiple, n: ins.length} : {err: 'file inputs=' + ins.length + ' named=' + named.length};
})()
"""


def upload(tab, expected, timeout=240):
    atts = expected["attachments"]
    if not atts:
        return
    info = tab.ev(FILE_INPUT)
    if not info or info.get("err"):
        raise Needs("NEEDS: no unique attachment file input (%s)" % (info or {}).get("err"))
    tab.send("DOM.enable")
    obj = tab.ev("window.__gnocFile", by_value=False).get("objectId")
    if not obj:
        raise Needs("NEEDS: could not get the file input object id")
    batches = [[a["path"] for a in atts]] if info.get("multiple") else [[a["path"]] for a in atts]
    for batch in batches:
        tab.send("DOM.setFileInputFiles", {"files": batch, "objectId": obj})
        time.sleep(2)
    end = time.time() + timeout
    while time.time() < end:
        ob = readback(tab, expected)
        if len(ob.get("attachments") or []) == len(atts):
            return
        time.sleep(2)
    # not fatal here: the verification table shows exactly which names are missing


def wait_turnstile(tab, timeout=120):
    try:
        browser_call("Target.activateTarget", {"targetId": tab.target_id}, tab.port)
    except Exception:
        pass
    tab.front()
    end = time.time() + timeout
    kicked = False
    while time.time() < end:
        n = tab.ev("((document.querySelector('[name=\"cf-turnstile-response\"]') || {}).value || '').length")
        if n:
            return n
        if not kicked:
            # Measured 2026-11-09 on program-28: the widget renders in invisible/execute mode
            # (no iframe, zero height) and NEVER self-solves, foregrounded or not. An explicit
            # turnstile.execute() on the container produced the token within ~4 s. reset() alone
            # does nothing. Kick once, then keep polling.
            tab.ev("(()=>{try{var c=document.querySelector('#cf-turnstile')||document.querySelector('.cf-turnstile');"
                   "if(c){c.scrollIntoView({block:'center'});window.focus();turnstile.execute(c);}return 'kicked'}"
                   "catch(e){return 'kick-err '+e}})()")
            kicked = True
        time.sleep(3)
    return 0


def safe_url(tab):
    """location.href that tolerates the execution context being torn down mid-navigation."""
    try:
        return tab.ev("location.href")
    except Exception:
        return None


def save_state(d, data):
    p = d / STATE_NAME
    p.write_text(json.dumps(data, indent=1, ensure_ascii=True) + "\n", encoding="utf-8")


def load_state(d):
    p = d / STATE_NAME
    if not p.is_file():
        raise Needs("NEEDS: no %s; run prepare first" % STATE_NAME)
    return json.loads(p.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------------------------
# COMMANDS
# --------------------------------------------------------------------------------------------

def cmd_prepare(args):
    d = draft_dir(args.draft)
    expected = load_expected(d, args.engagement)
    with open(LOCAL_VRT) as fh:
        apply_vrt(expected, json.load(fh), "local")          # fail fast before any tab opens
    st = d / STATE_NAME
    if st.is_file() and load_state(d).get("submit_attempted"):
        raise Needs("REFUSED: %s records a submit attempt already; not preparing a second filing" % st.name)

    url = "%s/engagements/%s/submissions/new" % (BASE, expected["engagement"])
    target_id = browser_call("Target.createTarget", {"url": "about:blank"}, args.cdp_port).get("targetId")
    if not target_id:
        raise Needs("NEEDS: Target.createTarget returned no target id")
    print("fresh tab %s -> %s" % (target_id, url))
    tab = Tab(target_id, args.cdp_port)
    try:
        tab.send("Page.enable")
        tab.send("Page.navigate", {"url": url})          # the ONLY navigation: our own fresh tab
        wait_form(tab)
        apply_vrt(expected, fetch_taxonomy(tab), "same-origin")
        print("VRT %s -> %s (P%s)" % (expected["vrt_id"], expected["vrt_badge"], expected["vrt_priority"]))

        r = tab.ev(SETTER + "(() => { const c = document.querySelector('#submission_caption');"
                   " gnocSet(c, %s); return c.value.length; })()" % json.dumps(expected["title"]))
        print("title set (%s chars); waiting for the draft autosave redirect" % r)
        end = time.time() + 20
        while time.time() < end and not edit_uuid(tab.ev("location.href")):
            time.sleep(1)
        wait_form(tab)
        fill_fields(tab, expected)
        drive_vrt(tab, expected)
        upload(tab, expected)
        print("waiting up to 120 s for Turnstile (tab foregrounded)")
        wait_turnstile(tab)
        time.sleep(2)
        ob = readback(tab, expected)
        shot = d / ("filing-preview-%s.png" % now_ts())
        tab.screenshot(shot)
        rows = verification_diff(expected, ob, "prepare")
        save_state(d, {"target_id": target_id, "engagement": expected["engagement"],
                       "edit_url": ob.get("url"), "edit_uuid": edit_uuid(ob.get("url")),
                       "prepared_at": iso_now(), "desc_sha256": expected["desc_sha256"],
                       "preview": shot.name, "submit_attempted": None})
    finally:
        tab.close()

    print("\n=== VERIFICATION, read back from the page (nothing submitted) ===")
    print(format_rows(rows))
    print("  bug_url field: %s" % json.dumps(ob.get("bug_url")))
    print("screenshot: %s" % shot)
    print("draft URL : %s" % ob.get("url"))
    bad = blocking_failures(rows)
    if bad:
        print("NEEDS: %d field(s) do not match the draft: %s" % (len(bad), ", ".join(r["field"] for r in bad)))
        return 6
    if not (ob.get("turnstile_len") or 0):
        print("PREPARED, Turnstile still pending. submit re-checks it.")
        return 3
    print("PREPARED. Submit button NOT clicked.")
    print('next: scripts/bugcrowd-file.py submit %s --confirm "<SUBMIT-TITLE.txt text>"' % args.draft)
    return 0


def cmd_submit(args):
    d = draft_dir(args.draft)
    title_raw = (d / "SUBMIT-TITLE.txt").read_bytes() if (d / "SUBMIT-TITLE.txt").is_file() else b""
    if not confirm_matches(args.confirm, title_raw):
        raise Needs("REFUSED: --confirm does not equal SUBMIT-TITLE.txt byte for byte")
    state = load_state(d)
    if state.get("submit_attempted"):
        raise Needs("REFUSED: a submit was already attempted at %s (%s); never retried"
                    % (state["submit_attempted"], state.get("submit_result")))
    expected = load_expected(d, state.get("engagement"))
    if expected["desc_sha256"] != state.get("desc_sha256"):
        raise Needs("REFUSED: SUBMIT-BODY.txt changed since prepare; run prepare again")
    with open(LOCAL_VRT) as fh:
        apply_vrt(expected, json.load(fh), "local")

    tab = Tab(state["target_id"], args.cdp_port)
    try:
        url = tab.ev("location.href")
        if state.get("edit_uuid") and edit_uuid(url) != state["edit_uuid"]:
            raise Needs("REFUSED: prepared tab is at %s, not draft %s" % (url, state["edit_uuid"]))
        apply_vrt(expected, fetch_taxonomy(tab), "same-origin")
        wait_turnstile(tab)
        if expected.get("terms") is True:
            # The checkbox is unticked whenever the draft was reopened (measured 2026-11-09); tick it the
            # same way prepare does, then the read-back below still has to observe it as true.
            tab.ev("(()=>{const cb=document.querySelector('#submission_terms_and_conditions');"
                   "if(cb && !cb.checked) cb.click(); return cb ? cb.checked : null})()")
        ob = readback(tab, expected)
        rows = verification_diff(expected, ob, "submit")
        print("=== PRE-SUBMIT VERIFICATION, read back from the page ===")
        print(format_rows(rows))
        bad = blocking_failures(rows)
        if bad:
            print("REFUSED: %d mismatch(es): %s. Nothing clicked." % (len(bad), ", ".join(r["field"] for r in bad)))
            return 6
        btn = tab.ev(r"""(() => {
          const vis = e => !!(e.offsetWidth || e.offsetHeight || e.getClientRects().length);
          const b = [...document.querySelectorAll('button, input[type=submit]')].filter(vis)
            .filter(e => /report vulnerability/i.test((e.innerText || e.value || '').trim()));
          if (b.length !== 1) return {err: 'submit buttons matching=' + b.length};
          b[0].scrollIntoView({block: 'center'}); b[0].focus();
          return {ok: document.activeElement === b[0]};
        })()""")
        if not btn or not btn.get("ok"):
            raise Needs("NEEDS: submit button not uniquely focusable (%s). Nothing clicked." % btn)
        state["submit_attempted"] = iso_now()
        state["submit_result"] = "pending"
        save_state(d, state)                                  # recorded BEFORE the key press: no retry
        tab.enter(with_text=True)
        end, url = time.time() + 30, None
        while time.time() < end:
            url = safe_url(tab) or url
            if url and "/edit" not in url:
                break
            time.sleep(1)
        time.sleep(3)
        url = safe_url(tab) or url
        shot = d / ("filing-result-%s.png" % now_ts())
        tab.screenshot(shot)
    finally:
        tab.close()

    if "/edit" in (url or ""):
        state["submit_result"] = "FAILED-SILENT"
        save_state(d, state)
        print("FAILED-SILENT: still on %s after 30 s. Screenshot %s. Not retrying." % (url, shot))
        return 5
    sub = extract_submission(url)
    if not sub and state.get("edit_uuid"):
        # Measured 2026-11-09 (program-28 filing): a successful submit redirects to the ENGAGEMENT
        # page (/engagements/<code>), not to the report, and the draft uuid IS the submission id.
        # Confirm from Bugcrowd's own record before calling it filed.
        try:
            chk = Tab(state["target_id"], args.cdp_port)
            rec = chk.ev("fetch('/submissions/%s',{credentials:'include',headers:{accept:'application/json'}})"
                         ".then(r=>r.ok?r.text():'')" % state["edit_uuid"])
            chk.close()
            j = json.loads(rec) if rec else {}
            det = (j.get("submissionData") or {}).get("submissionDetailProps", {}).get("submission", {})
            if det.get("submitted_at"):
                sub = {"id": state["edit_uuid"], "url": "https://bugcrowd.com/submissions/%s" % state["edit_uuid"],
                       "reference": det.get("reference_number"), "submitted_at": det["submitted_at"]}
                (d / "evidence").mkdir(exist_ok=True)
                (d / "evidence" / ("filed-record-%s.json" % now_ts())).write_text(rec)
                print("confirmed from the platform record: submitted_at %s reference %s"
                      % (det["submitted_at"], det.get("reference_number")))
        except Exception as e:
            print("record check failed: %s" % e)
    if not sub:
        state["submit_result"] = "left-edit-no-id %s" % url
        save_state(d, state)
        print("NEEDS: page left /edit but no submission id in %s. Screenshot %s. Check by hand." % (url, shot))
        return 4
    ts = iso_now()
    smd = d / "SUBMITTED.md"
    head = "" if smd.exists() else "# SUBMITTED\n\n"
    with open(smd, "a", encoding="utf-8") as fh:
        fh.write(head + submitted_line(ts, expected["engagement"], sub, expected, shot.name))
    program, slug = args.draft.split("/", 1)
    row = ship_row(program, slug, smd.resolve(), sub, expected["engagement"], ts)
    p = subprocess.run([sys.executable, str(SCRIPTS / "hunt-state.py"), "append-ship"],
                       input=json.dumps(row), text=True, capture_output=True)
    state["submit_result"] = "submitted %s" % sub["url"]
    save_state(d, state)
    print("SUBMITTED: %s (id %s)" % (sub["url"], sub["id"]))
    print("screenshot: %s" % shot)
    print("SUBMITTED.md appended; ships.jsonl append-ship exit %d %s" % (p.returncode, p.stderr.strip()))
    return 0 if p.returncode == 0 else 4


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    pp = sub.add_parser("prepare", help="fill the form in a fresh tab; never clicks submit")
    pp.add_argument("draft")
    pp.add_argument("--engagement")
    pp.add_argument("--cdp-port", default="9222")
    pp.add_argument("--allow-varies", action="store_true",
                    help="operator override: accept a VRT leaf whose taxonomy priority is varies (null)")
    ps = sub.add_parser("submit", help="verify the prepared tab and submit it")
    ps.add_argument("draft")
    ps.add_argument("--confirm", required=True)
    ps.add_argument("--cdp-port", default="9222")
    ps.add_argument("--allow-varies", action="store_true",
                    help="operator override: accept a VRT leaf whose taxonomy priority is varies (null)")
    args = ap.parse_args(argv)
    global ALLOW_VARIES
    ALLOW_VARIES = bool(getattr(args, "allow_varies", False))
    try:
        return cmd_prepare(args) if args.cmd == "prepare" else cmd_submit(args)
    except Needs as e:
        print(str(e))
        return e.code
    except Exception as e:                                   # anything unexpected is a NEEDS, not a crash
        print("NEEDS: unexpected %s: %s" % (type(e).__name__, str(e)[:300]))
        return 4


if __name__ == "__main__":
    sys.exit(main())

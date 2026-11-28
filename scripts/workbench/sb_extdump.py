#!/usr/bin/env python3
"""sb_extdump - unpack a CRX and write EXT.md: the trust surface of a browser extension.

Classic extension trust bugs live in four manifest blocks plus a handful of JS listeners:
  externally_connectable  - which web origins / extension ids may message the extension
  content_scripts         - which pages get extension code injected (and in which world)
  web_accessible_resources- which extension files any (or a listed) web origin can load
  permissions / host_permissions - what a compromised message handler can reach
plus onMessageExternal / onConnectExternal / window 'message' listeners / WebSocket use.

Usage: sb_extdump.py <crx-or-dir> <outdir> [--program P]   (prints the unpacked dir)
"""
from __future__ import annotations

import io
import json
import re
import struct
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import sb_common  # noqa: E402

SINKS = {
    "onMessageExternal": r"onMessageExternal",
    "onConnectExternal": r"onConnectExternal",
    "window message listener": r"addEventListener\(\s*['\"]message['\"]|onmessage\s*=",
    "postMessage(*)": r"postMessage\([^)]*['\"]\*['\"]",
    "runtime.sendMessage": r"runtime\.sendMessage",
    "WebSocket": r"new\s+WebSocket\(",
    "eval / Function": r"\beval\(|new\s+Function\(",
    "innerHTML / outerHTML / insertAdjacentHTML": r"\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML\(",
    "document.write": r"document\.write\(",
    "scripting.executeScript / tabs.executeScript": r"(scripting|tabs)\.executeScript",
    "chrome.cookies": r"chrome\.cookies\.",
    "chrome.debugger": r"chrome\.debugger\.",
    "nativeMessaging": r"connectNative|sendNativeMessage",
    "declarativeNetRequest dynamic rules": r"updateDynamicRules|updateSessionRules",
    "storage (sync/local)": r"storage\.(local|sync|session)\.(get|set)",
}


def unpack(src: Path, outdir: Path) -> Path:
    if src.is_dir():
        if not (src / "manifest.json").exists():
            sb_common.die(f"{src} has no manifest.json")
        return src.resolve()
    data = src.read_bytes()
    if data[:4] == b"Cr24":
        ver = struct.unpack("<I", data[4:8])[0]
        if ver == 3:
            hlen = struct.unpack("<I", data[8:12])[0]
            zstart = 12 + hlen
        elif ver == 2:
            klen, slen = struct.unpack("<II", data[8:16])
            zstart = 16 + klen + slen
        else:
            sb_common.die(f"unknown CRX version {ver}")
        data = data[zstart:]
    dest = outdir / "unpacked"
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for m in z.infolist():                      # zip-slip guard
            p = (dest / m.filename).resolve()
            if not str(p).startswith(str(dest.resolve())):
                sb_common.die(f"refusing zip entry outside dest: {m.filename}")
        z.extractall(dest)
    if not (dest / "manifest.json").exists():
        sb_common.die("unpacked archive has no manifest.json")
    return dest.resolve()


def extension_id(ext: Path) -> str:
    """Chrome's id for an unpacked extension: sha256 of the manifest `key` (DER, base64) when present,
    else of the absolute path; first 32 hex digits mapped 0-f -> a-p."""
    import base64
    import hashlib
    raw = re.sub(r"^\s*//.*$", "", (ext / "manifest.json").read_text(encoding="utf-8-sig", errors="replace"),
                 flags=re.M)
    key = json.loads(raw).get("key")
    data = base64.b64decode(key) if key else str(ext.resolve()).encode()
    return "".join(chr(ord("a") + int(c, 16)) for c in hashlib.sha256(data).hexdigest()[:32])


def _list(x):
    return x if isinstance(x, list) else ([] if x is None else [x])


def _host_of_match(m: str) -> str:
    m = re.sub(r"^[a-z*]+://", "", m)
    return m.split("/", 1)[0].lstrip("*.") or m


def analyse(ext: Path, program: str | None) -> tuple[str, dict]:
    raw = (ext / "manifest.json").read_text(encoding="utf-8-sig", errors="replace")
    raw = re.sub(r"^\s*//.*$", "", raw, flags=re.M)    # manifests tolerate // comments
    man = json.loads(raw)
    mv = man.get("manifest_version")
    perms = _list(man.get("permissions"))
    host_perms = _list(man.get("host_permissions")) + [p for p in perms if "://" in p or p == "<all_urls>"]
    api_perms = [p for p in perms if p not in host_perms]
    ec = man.get("externally_connectable") or {}
    cs = _list(man.get("content_scripts"))
    war = _list(man.get("web_accessible_resources"))
    notes: list[str] = []

    if not ec:
        notes.append("externally_connectable ABSENT: every other extension may message it "
                     "(runtime.onMessageExternal), no web page may.")
    for m in _list(ec.get("matches")):
        if "*" in _host_of_match(m) or m in ("<all_urls>", "*://*/*"):
            notes.append(f"externally_connectable wildcard origin `{m}`: any page on it can call "
                         "onMessageExternal; an XSS or takeover there drives the extension.")
    if "*" in _list(ec.get("ids")):
        notes.append("externally_connectable ids `*`: ANY installed extension can message it.")
    for c in cs:
        w = c.get("world", "ISOLATED")
        ms = _list(c.get("matches"))
        if w == "MAIN":
            notes.append(f"content script in MAIN world on {ms}: shares the page JS realm (page can tamper).")
        if any(m in ("<all_urls>", "*://*/*", "http://*/*", "https://*/*") for m in ms):
            notes.append(f"content script on ALL pages ({c.get('js')}): every site can postMessage it.")
    for w in war:
        if isinstance(w, str):
            notes.append(f"MV2 web_accessible_resource `{w}` is loadable by EVERY origin.")
        else:
            ms = _list(w.get("matches"))
            if any(m in ("<all_urls>", "*://*/*", "http://*/*", "https://*/*") for m in ms) \
                    and not w.get("use_dynamic_url"):
                notes.append(f"web_accessible_resources {w.get('resources')} open to all origins with a "
                             "stable URL: extension fingerprinting and clickjacking of extension pages.")
    for p in ("debugger", "nativeMessaging", "cookies", "webRequestBlocking", "proxy", "management",
              "scripting", "tabs", "<all_urls>"):
        if p in perms or p in host_perms:
            notes.append(f"high-power permission `{p}`.")
    csp = man.get("content_security_policy")
    if isinstance(csp, str) and ("unsafe-eval" in csp or "unsafe-inline" in csp):
        notes.append(f"MV2 CSP relaxes eval/inline: `{csp}`.")
    if isinstance(csp, dict) and any("unsafe-eval" in v for v in csp.values() if isinstance(v, str)):
        notes.append(f"CSP relaxes eval: `{csp}`.")

    hits: dict[str, list[str]] = {k: [] for k in SINKS}
    for f in sorted(ext.rglob("*")):
        if f.suffix not in (".js", ".mjs", ".html", ".htm") or not f.is_file() or f.stat().st_size > 8_000_000:
            continue
        txt = f.read_text(errors="replace")
        for k, rx in SINKS.items():
            for mo in re.finditer(rx, txt):
                line = txt.count("\n", 0, mo.start()) + 1
                if len(hits[k]) < 12:
                    hits[k].append(f"{f.relative_to(ext)}:{line}")

    scope_rows = []
    if program:
        for m in _list(ec.get("matches")) + [m for c in cs for m in _list(c.get("matches"))] + host_perms:
            h = _host_of_match(m)
            if h and h not in ("<all_urls>",) and "." in h:
                scope_rows.append((m, sb_common.host_in_scope(h, program)))

    def j(x):
        return "`" + json.dumps(x) + "`"

    L = [f"# EXT - {man.get('name')} {man.get('version')}", "",
         f"- Unpacked: `{ext}`", f"- manifest_version: {mv}",
         f"- key present (stable id): {'yes' if man.get('key') else 'no'}",
         f"- background: {j(man.get('background'))}", "",
         "## Trust-surface notes (leads to test, not findings)", ""]
    L += [f"- {n}" for n in notes] or ["- none flagged by the static rules"]
    L += ["", "## permissions", "", f"- API: {j(api_perms)}", f"- host: {j(host_perms)}",
          f"- optional: {j(_list(man.get('optional_permissions')))}",
          f"- optional host: {j(_list(man.get('optional_host_permissions')))}", "",
          "## externally_connectable", "", j(ec) if ec else "(absent)", "",
          "## content_scripts", ""]
    for c in cs:
        L.append(f"- matches {j(_list(c.get('matches')))} js {j(_list(c.get('js')))} "
                 f"world {c.get('world', 'ISOLATED')} all_frames {c.get('all_frames', False)} "
                 f"run_at {c.get('run_at', 'document_idle')}")
    L += ["" if cs else "(none)", "## web_accessible_resources", "", j(war) if war else "(none)", "",
          "## content_security_policy", "", j(csp) if csp else "(default)", "",
          "## Listener and sink grep (first 12 hits each)", ""]
    for k, v in hits.items():
        if v:
            L.append(f"- **{k}**: " + ", ".join(v))
    if scope_rows:
        L += ["", f"## Match patterns vs targets/{program}/SCOPE.txt", ""]
        L += [f"- `{m}` -> {'IN SCOPE' if ok else 'not in scope'}" for m, ok in scope_rows]
    L += ["", "## Test recipes", "",
          "- externally_connectable: from an allowed origin page run "
          "`chrome.runtime.sendMessage('<id>', {...})` and fuzz the message schema the handler reads.",
          "- content script postMessage: from any matched page `window.postMessage({...}, '*')` "
          "and watch what the content script forwards to the background (CDP Runtime on the page).",
          "- WAR: `fetch('chrome-extension://<id>/<resource>')` from a web origin; frame it for clickjacking.",
          "- Drive it over CDP: the lab's DevTools endpoint is in LAB.md; the service worker is a "
          "`service_worker` target in /json/list.", ""]
    summary = {"name": man.get("name"), "version": man.get("version"), "mv": mv,
               "notes": len(notes), "api_perms": api_perms, "host_perms": host_perms}
    return "\n".join(L), summary


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("outdir")
    ap.add_argument("--program")
    a = ap.parse_args()
    out = Path(a.outdir)
    out.mkdir(parents=True, exist_ok=True)
    ext = unpack(Path(a.src), out)
    md, _ = analyse(ext, a.program)
    (out / "EXT.md").write_text(md)
    print(ext)

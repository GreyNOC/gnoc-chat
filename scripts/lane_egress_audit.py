#!/usr/bin/env python3
"""lane_egress_audit.py - end-of-lane egress audit for scripts/opencode-lane.sh (mirrors oss-bot ingest net 3).

  lane_egress_audit.py <program> <egress.jsonl> [--commands commands.txt --fired N] [--root R]
  lane_egress_audit.py --paused <program> [--root R]     exit 0 when the program's lanes are paused

Violations (any one => exit 1, write the pause marker, a SCOPE-INCIDENTS.md entry and an INBOX line):
  * a DENIED proxy row whose reason is not dns-fail (the lane's shell tried to reach something out of scope)
  * a host in the last N fired commands.txt URLs with no allowed proxy row (the tool bypassed the proxy)
Marker: <root>/.claude/state/orch/lane-scope-pause/<program>   (orch-bot and opencode-lane.sh refuse to start a lane
while it exists; remove the file to resume).
"""
import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone

DEFAULT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def marker(root, program):
    return os.path.join(root, ".claude/state/orch/lane-scope-pause", program)


def paused(root, program):
    return os.path.exists(marker(root, program))


def rows(path):
    out = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for ln in fh:
                try:
                    out.append(json.loads(ln))
                except ValueError:
                    pass
    except OSError:
        pass
    return out


# The lane's shell exports HTTP_PROXY, so the worker toolchain itself (the opencode CLI fetching its model registry,
# a package index) also goes through the scope proxy and is DENIED there. A denied toolchain host is contained, not a
# lane violation: on 2026-10-25 models.opencode.ai:443 paused every program-0 lane for nothing. Target-side hosts are
# never on this list; a denied unknown host still fails the audit.
TOOLCHAIN = ("opencode.ai", "hf.co", "huggingface.co", "github.com", "githubusercontent.com", "registry.npmjs.org",
             "pypi.org", "files.pythonhosted.org", "ollama.com")


def toolchain(host):
    h = str(host or "").lower().rstrip(".")
    return any(h == t or h.endswith("." + t) for t in TOOLCHAIN)


def audit(egress, commands=None, fired=0):
    """-> (denied_violations, bypassed_hosts)."""
    rs = rows(egress)
    allowed = {str(r.get("host") or "").lower().rstrip(".") for r in rs if r.get("allowed") is True}
    denied = sorted({f"{r.get('host')}:{r.get('port')} ({r.get('reason')})" for r in rs
                     if r.get("allowed") is False and r.get("reason") != "dns-fail"
                     and not toolchain(r.get("host"))})
    seen = set()
    if commands and fired > 0 and os.path.isfile(commands):
        with open(commands, encoding="utf-8", errors="replace") as fh:
            tail = fh.read().splitlines()[-fired:]
        for ln in tail:
            seen |= {h.lower().rstrip(".") for h in re.findall(r"https?://([A-Za-z0-9.\-]+)", ln)}
    return denied, sorted(h for h in seen if h not in allowed)


def _append(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o664)
    try:
        os.write(fd, text.encode("utf-8")[:4000])
    finally:
        os.close(fd)


def record_violation(root, program, denied, bypassed, egress):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    detail = []
    if denied:
        detail.append("denied by lane proxy: " + ", ".join(denied[:10]))
    if bypassed:
        detail.append("fired hosts with no allowed proxy row: " + ", ".join(bypassed[:10]))
    m = marker(root, program)
    os.makedirs(os.path.dirname(m), exist_ok=True)
    with open(m, "w") as fh:
        fh.write(f"{ts} {'; '.join(detail)}\n")
    _append(os.path.join(root, ".claude/state/hunt-loop/SCOPE-INCIDENTS.md"),
            f"\n## {ts} lane egress audit FAIL ({program})\n- egress log: `{egress}`\n"
            + "".join(f"- {d}\n" for d in detail) + f"- action: lanes for {program} paused (rm {os.path.relpath(m, root)} to resume)\n")
    _append(os.path.join(root, ".claude/state/orch/INBOX.md"),
            f"- [{ts}] **SCOPE** lane egress audit FAIL on {program}: {'; '.join(detail)[:300]}. Lanes for {program} "
            f"paused; rm {os.path.relpath(m, root)} after review.\n")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("program", nargs="?")
    ap.add_argument("egress", nargs="?")
    ap.add_argument("--commands")
    ap.add_argument("--fired", type=int, default=0)
    ap.add_argument("--root", default=DEFAULT_ROOT)
    ap.add_argument("--paused", metavar="PROGRAM")
    a = ap.parse_args(argv)
    if a.paused:
        return 0 if paused(a.root, a.paused) else 1
    if not a.program or not a.egress:
        ap.error("program and egress.jsonl required")
    denied, bypassed = audit(a.egress, a.commands, a.fired)
    if denied or bypassed:
        record_violation(a.root, a.program, denied, bypassed, a.egress)
        print(f"LANE EGRESS AUDIT FAIL {a.program}: denied={denied} bypassed={bypassed}")
        return 1
    print(f"LANE EGRESS AUDIT OK {a.program}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

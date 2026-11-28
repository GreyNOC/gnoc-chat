#!/usr/bin/env python3
"""HackerOne Hacker-API: post a comment (activity) on an existing report.

usage: h1-comment.py <report_id> <message-file|-> [--dry-run] [--yes]

Creds from ~/.config/gnoc/secrets.env (HACKERONE_HANDLE, HACKERONE_API_TOKEN), HTTP Basic.
A real send needs .claude/state/GREYNOC-APPROVED-SUBMIT (same gate as h1-submit-report.py) and,
without --yes, typing the report id to confirm. Attachments are not supported by this endpoint;
upload any evidence files by hand in the H1 web UI alongside this comment.
"""
import os
import sys

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API = "https://api.hackerone.com/v1/hackers"
SECRETS = os.path.expanduser("~/.config/gnoc/secrets.env")
APPROVAL = os.path.join(ROOT, ".claude/state/GREYNOC-APPROVED-SUBMIT")


def die(msg, code=1):
    print(f"ABORT: {msg}", file=sys.stderr)
    sys.exit(code)


def load_creds():
    env = {}
    try:
        for ln in open(SECRETS, encoding="utf-8"):
            ln = ln.strip()
            if ln and not ln.startswith("#") and "=" in ln:
                k, v = ln.split("=", 1)
                env[k.replace("export ", "").strip()] = v.strip().strip("'\"")
    except OSError:
        die(f"cannot read {SECRETS}")
    h, t = env.get("HACKERONE_HANDLE"), env.get("HACKERONE_API_TOKEN")
    if not h or not t:
        die("HACKERONE_HANDLE / HACKERONE_API_TOKEN missing in secrets.env")
    return h, t


def main(argv):
    if len(argv) < 2:
        die("usage: h1-comment.py <report_id> <message-file|-> [--dry-run] [--yes]")
    report_id = argv[0]
    msg_src = argv[1]
    rest = argv[2:]
    dry = "--dry-run" in rest
    yes = "--yes" in rest
    message = sys.stdin.read() if msg_src == "-" else open(msg_src, encoding="utf-8").read()
    message = message.strip()
    if not message:
        die("empty message")
    if len(message) > 10000:
        die("message too long, keep it short")
    handle, token = load_creds()
    body = {"data": {"type": "activity-comment", "attributes": {"message": message, "internal": False}}}
    print(f"=== DRY RUN: would POST a comment to report #{report_id} as {handle} ===")
    print(message)
    print("=== end ===")
    if dry:
        return 0
    if not os.path.isfile(APPROVAL):
        die(f"no approval file ({APPROVAL}); create it for this one action, then re-run")
    if not yes:
        if not sys.stdin.isatty():
            die("confirmation needs an interactive terminal (or pass --yes)")
        if input(f"Post this comment to report #{report_id}? type the report id: ").strip() != str(report_id):
            die("not confirmed; nothing sent")
    r = requests.post(f"{API}/reports/{report_id}/activities", auth=(handle, token),
                      headers={"Content-Type": "application/json"}, json=body, timeout=30)
    if r.status_code not in (200, 201):
        die(f"POST failed {r.status_code}: {r.text[:500]}")
    try:
        aid = r.json().get("data", {}).get("id", "?")
    except ValueError:
        aid = "?"
    print(f"posted: activity id {aid}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

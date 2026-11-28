#!/usr/bin/env python3
"""qa-mail-audit.py - reconcile the local QA-delivery ledger against the mail account's Sent folder.

WHY TWO SOURCES. A local ledger records what this machine BELIEVES it sent. It drifts: this
workspace already carries the scar - "drafts ledger=11/disk=37, submitted ledger=0/disk=5,
trust the DISK count". A tracker that only reads its own log will confidently report a delivery
that never happened, and will never notice a message a human sent by hand. So this compares:

  A  the local ledger  .claude/state/hunt-loop/qa-mail-sent.jsonl   (what we think left)
  B  the Sent folder of the sending account                          (what actually left)

and reports BOTH directions:
  LOGGED-NOT-IN-SENT  the ledger claims a delivery the mail account cannot confirm. Treat the
                      bundle as NOT delivered. This is the dangerous direction.
  IN-SENT-NOT-LOGGED  a handoff left the account without going through the tool, e.g. sent by
                      hand. Real, just untracked - the ledger should adopt it.

Matching is on the EXACT tracking token qa-mail.sh stamps into X-QA-Token / Message-ID / body,
never on a subject substring, because a subject can be edited, duplicated or truncated.

Sent-folder access, in preference order:
  1. --imap          IMAP over TLS. Headless, cron-able, authoritative. Needs QA_IMAP_* creds.
  2. --from-file F   a text/eml dump of Sent, for a browser export or a manual paste. Any line
                     containing a token counts as a hit, so a copy-pasted Sent list works.
  3. (default)       ledger-only. Prints the ledger and states plainly that it is UNVERIFIED.

Usage:
  qa-mail-audit.py                      ledger only, clearly labelled unverified
  qa-mail-audit.py --imap               reconcile against Sent over IMAP
  qa-mail-audit.py --from-file sent.txt reconcile against an exported Sent dump
  qa-mail-audit.py --adopt              with a source: write IN-SENT-NOT-LOGGED into the ledger
"""
import os, sys, json, ssl, argparse, datetime, re

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LEDGER = os.path.join(WS, ".claude/state/hunt-loop/qa-mail-sent.jsonl")
READY_GLOB = os.path.join(WS, "QA handoff")
SECRETS = os.path.expanduser("~/.config/gnoc/secrets.env")
TOKEN_RE = re.compile(r"QA-HANDOFF-[A-Za-z0-9._-]+-[0-9a-f]{16}")


def load_secrets():
    env = {}
    try:
        for line in open(SECRETS, encoding="utf-8", errors="replace"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            line = line[7:].strip() if line.startswith("export ") else line
            if "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    return env


def load_ledger():
    rows = []
    try:
        for line in open(LEDGER, encoding="utf-8"):
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    except FileNotFoundError:
        pass
    return rows


def ready_bundles():
    """Bundles currently in the weekly READY tier, so the audit can also say what is PENDING."""
    now = datetime.datetime.now(datetime.timezone.utc)
    mon = now - datetime.timedelta(days=now.weekday())
    week = f"{mon.strftime('%G-W%V')}_{mon:%Y-%m-%d}_to_{(mon+datetime.timedelta(days=6)):%Y-%m-%d}"
    d = os.path.join(READY_GLOB, now.strftime("%Y-%m-%B"), week)
    if not os.path.isdir(d):
        return [], d
    return sorted(n for n in os.listdir(d) if os.path.isdir(os.path.join(d, n))), d


def tokens_via_imap(env):
    import imaplib, email
    host = env.get("QA_IMAP_HOST") or env.get("QA_SMTP_HOST", "").replace("smtp.", "imap.")
    user = env.get("QA_IMAP_USER") or env.get("QA_SMTP_USER")
    pw = env.get("QA_IMAP_PASS") or env.get("QA_SMTP_PASS")
    if not (host and user and pw):
        raise SystemExit(
            "qa-mail-audit: IMAP needs QA_IMAP_HOST / QA_IMAP_USER / QA_IMAP_PASS in\n"
            f"  {SECRETS}   (or QA_SMTP_* equivalents)\n"
            "  For Google Workspace: imap.gmail.com, and an App Password (not the login password)."
        )
    M = imaplib.IMAP4_SSL(host, ssl_context=ssl.create_default_context())
    M.login(user, pw)
    # the Sent folder is named differently per provider; try the usual spellings
    folder = None
    for cand in ['"[Gmail]/Sent Mail"', '"Sent Items"', "Sent", "INBOX.Sent", '"[Google Mail]/Sent Mail"']:
        if M.select(cand, readonly=True)[0] == "OK":
            folder = cand
            break
    if not folder:
        names = [l.decode(errors="replace") for l in (M.list()[1] or [])]
        M.logout()
        raise SystemExit("qa-mail-audit: could not find a Sent folder. Folders seen:\n  " + "\n  ".join(names))
    found = {}
    typ, data = M.search(None, 'HEADER', 'X-QA-Token', 'QA-HANDOFF')
    ids = (data[0].split() if data and data[0] else [])
    if not ids:  # fall back to a full scan if the server will not search a custom header
        typ, data = M.search(None, "ALL")
        ids = (data[0].split() if data and data[0] else [])
    for i in ids:
        typ, md = M.fetch(i, "(RFC822)")
        if typ != "OK" or not md or not md[0]:
            continue
        raw = md[0][1]
        msg = email.message_from_bytes(raw)
        blob = " ".join(filter(None, [msg.get("X-QA-Token", ""), msg.get("Message-ID", ""),
                                      msg.get("Subject", ""), raw.decode("utf-8", "replace")[:40000]]))
        for t in TOKEN_RE.findall(blob):
            found[t] = {"date": msg.get("Date", "?"), "to": msg.get("To", "?"), "subject": msg.get("Subject", "?")}
    M.logout()
    return found, f"IMAP {host} {folder}"


def tokens_from_file(path):
    found = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            for t in TOKEN_RE.findall(line):
                found.setdefault(t, {"date": "?", "to": "?", "subject": line.strip()[:90]})
    return found, f"file {path}"


def main():
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--imap", action="store_true")
    ap.add_argument("--from-file")
    ap.add_argument("--adopt", action="store_true")
    ap.add_argument("-h", "--help", action="store_true")
    a = ap.parse_args()
    if a.help:
        print(__doc__)
        return 0

    ledger = load_ledger()
    by_token = {r.get("token", ""): r for r in ledger if r.get("token")}
    untokened = [r for r in ledger if not r.get("token")]
    ready, readydir = ready_bundles()

    sent, source = ({}, None)
    if a.imap:
        sent, source = tokens_via_imap(load_secrets())
    elif a.from_file:
        sent, source = tokens_from_file(a.from_file)

    print("QA delivery audit")
    print(f"  ledger        : {len(ledger)} entries ({len(by_token)} with a tracking token)")
    print(f"  READY tier    : {len(ready)} bundle(s) in {os.path.relpath(readydir, WS)}")
    print(f"  Sent source   : {source or 'NONE - ledger only, UNVERIFIED'}")
    print()

    if source is None:
        print("  THIS RUN IS UNVERIFIED. It reports what the ledger claims, not what the mail")
        print("  account confirms. A ledger-only tracker will happily assert a delivery that")
        print("  never happened. Re-run with --imap or --from-file for a real answer.")
        print()
        if ledger:
            for r in ledger:
                print(f"    claims delivered: {r.get('bundle','?')}  {r.get('ts','?')}  receipt={r.get('receipt','?')[:40]}")
        else:
            print("    ledger is EMPTY - nothing has been delivered to QA by this tool.")
        delivered = set(by_token.get(t, {}).get("bundle") for t in by_token)
        pend = [b for b in ready if b not in delivered]
        print()
        print(f"  pending (in READY, no ledger entry): {len(pend)}")
        for b in pend:
            print(f"    {b}")
        return 0

    logged_not_sent = sorted(t for t in by_token if t not in sent)
    sent_not_logged = sorted(t for t in sent if t not in by_token)
    confirmed = sorted(t for t in by_token if t in sent)

    print(f"  CONFIRMED delivered (ledger AND Sent agree): {len(confirmed)}")
    for t in confirmed:
        print(f"    {by_token[t]['bundle']}")
    print()
    print(f"  LOGGED-NOT-IN-SENT (treat as NOT delivered): {len(logged_not_sent)}")
    for t in logged_not_sent:
        print(f"    {by_token[t]['bundle']}   ledger ts {by_token[t].get('ts','?')}")
    if logged_not_sent:
        print("    ^ the ledger claims these left but the account cannot confirm it. Re-send,")
        print("      and treat the ledger entry as suspect, not the mail account.")
    print()
    print(f"  IN-SENT-NOT-LOGGED (left outside the tool): {len(sent_not_logged)}")
    for t in sent_not_logged:
        print(f"    {t}   {sent[t]['date']}   to {sent[t]['to']}")
    if untokened:
        print()
        print(f"  ledger rows with no token (pre-tracking): {len(untokened)} - cannot be reconciled")

    delivered_bundles = {by_token[t]["bundle"] for t in confirmed}
    pend = [b for b in ready if b not in delivered_bundles]
    print()
    print(f"  PENDING (in READY, not confirmed delivered): {len(pend)}")
    for b in pend:
        print(f"    {b}")

    if a.adopt and sent_not_logged:
        with open(LEDGER, "a", encoding="utf-8") as fh:
            for t in sent_not_logged:
                m = re.match(r"QA-HANDOFF-(.+)-([0-9a-f]{16})$", t)
                fh.write(json.dumps({
                    "ts": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "bundle": m.group(1) if m else "?", "token": t,
                    "archive_sha16": m.group(2) if m else "?",
                    "to": sent[t]["to"], "adopted_from": source,
                    "receipt": "adopted from Sent folder, no SMTP receipt",
                }) + "\n")
        print(f"\n  adopted {len(sent_not_logged)} untracked delivery(ies) into the ledger")
    return 0


if __name__ == "__main__":
    sys.exit(main())

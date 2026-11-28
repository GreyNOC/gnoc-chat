#!/usr/bin/env python3
"""bundle-report.py - pack one draft into a vendor-ready .zip (report + evidence package).

  bundle-report.py <draft-dir|package-dir> [--out DIR]       one report
  bundle-report.py --multi <program|-a> [all|today|yesterday|YYYY-MM-DD] [draft|qa|submit]
                     every report of a target (or all) in ONE combined zip, optionally one stage only
  bundle-report.py --each <program|-a> [all|today|yesterday|YYYY-MM-DD] [draft|qa|submit] [--downloads]
                     every matching report zipped into its OWN separate bundle (not combined);
                     --downloads also copies each one to ~/Downloads as <program>__<slug>-<date>.zip
  bundle-report.py --list <program|-a> [all|today|yesterday|YYYY-MM-DD] [draft|qa|submit]
                     dry run: print what --multi/--each would bundle, write nothing

Contents (all from disk, never retyped, T-106):
  report.md          the text HackerOne receives: internal header lines (Gate:, Dedup:, ESCALATION TARGET:,
                     **Unlock:) stripped exactly as h1-submit-report.py strips them
  repro.sh, capture.log, attacker.*   the shipped PoC files, when present
  panels/*.png + panels/BURP-INDEX.txt   raw Burp panels (SPINE 5)
  evidence/**        the cited capture files
  SHA256SUMS.txt     one line per file, so the triager can verify the bundle

EVERYTHING in the report dir is zipped (the user 2026-10-20: "zip everything that isnt a secret"), except OUR secrets:
files with a secret-type name (.env, keys, ACCOUNTS.md, *.token, cookies/session/storage-state json, credentials) and any
file containing one of our credential VALUES (from ~/.config/gnoc/secrets.env and *.token). A credential captured from
the target is evidence and stays. Every left-out file is named in EXCLUDED.txt inside the zip. Internal notes in the
report text only WARN (fix them before filing); they never stop a zip.
Default output: reports/bundles/<program>/<slug>-<UTC date>.zip
"""
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from datetime import date, datetime, timedelta, timezone

WS = (os.environ.get("GNOC_WORKSPACE") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
STRIP_RE = re.compile(r"^\s*(Gate:|Dedup:|ESCALATION TARGET:|\*\*Unlock:)")
INTERNAL = re.compile(r"^(GATES\.md|FORM\.md|KILLPASS.*|REPRO-CHECK.*|REPRO-RUN.*|PIPELINE\.md|SELFDUP.*|DRYRUN.*|AUTOFIX.*"
                      r"|.*-auto\.txt|HELD-REASON\.md|TODO-.*|SELF-DUP-OK\.txt|SUBMITTED\.md|FILE-BY-HAND.*|H1-FORM-BODY.*"
                      r"|.*\.bak.*|.*\.part|report\.md)$", re.I)
SECRETY = re.compile(r"(^\.env|token|secret|password|credential|\.key$|\.pem$|\.p12$|id_rsa)", re.I)
TOOLING_DIRS = {"chain", "__pycache__", "burp-chain", "node_modules", "venv", ".venv"}  # our own harness, not evidence
TOP_FILES = re.compile(r"^(repro\.sh|capture\.log|attacker\.\w+|poc\.\w+|README\.md)$", re.I)


def locate(arg):
    d = os.path.abspath(arg)
    if os.path.isfile(d):
        d = os.path.dirname(d)
    if not os.path.isfile(os.path.join(d, "report.md")):
        sys.exit(f"no report.md in {d}")
    rel = os.path.relpath(d, WS).split(os.sep)
    program = rel[2] if rel[:2] == ["reports", "drafts"] and len(rel) > 2 else rel[1] if rel[0] == "targets" else "misc"
    slug = rel[3] if rel[:2] == ["reports", "drafts"] and len(rel) > 3 else os.path.basename(d.rstrip("/"))
    if slug in ("submit", "draft"):
        slug = os.path.basename(os.path.dirname(d)) if slug == "submit" else slug
    return d, program, slug


OUR_SECRET_NAMES = re.compile(r"(^\.env(\..*)?$|secrets?\.env$|\.key$|\.pem$|\.p12$|\.pfx$|id_rsa|id_ed25519|"
                              r"^ACCOUNTS\.md$|\.token$|cookies?\.(txt|json)$|session.*\.json$|credentials?(\.|$)|"
                              r"storage[-_]?state.*\.json$|\.netrc$)", re.I)
JUNK = re.compile(r"(\.pyc$|\.pyo$|\.part$|\.swp$|~$|^\.DS_Store$)")
JUNK_DIRS = {"__pycache__", "node_modules", ".git", "venv", ".venv"}


def our_secret_values():
    """Literal values of OUR credentials: secrets.env and ~/.config/gnoc/**/*.token (min 12 chars)."""
    vals = set()
    root = os.path.expanduser("~/.config/gnoc")
    for dp, dn, fn in os.walk(root):
        for f in fn:
            fp = os.path.join(dp, f)
            try:
                if f.endswith(".env"):
                    for ln in open(fp, encoding="utf-8", errors="replace"):
                        if "=" in ln and not ln.strip().startswith("#"):
                            v = ln.split("=", 1)[1].strip().strip("'\"")
                            if len(v) >= 12:
                                vals.add(v)
                elif f.endswith(".token") or "token" in f.lower():
                    v = open(fp, encoding="utf-8", errors="replace").read().strip()
                    if len(v) >= 12:
                        vals.add(v)
            except OSError:
                pass
    return vals


_SECRET_VALUES = None


def carries_our_secret(fp):
    global _SECRET_VALUES
    if _SECRET_VALUES is None:
        _SECRET_VALUES = [v.encode() for v in our_secret_values()]
    try:
        if os.path.getsize(fp) > 50 * 1024 * 1024:
            return False
        data = open(fp, "rb").read()
    except OSError:
        return False
    return any(v in data for v in _SECRET_VALUES)


def members(d, excluded=None):
    """Every file under the report dir except OUR secrets (by filename or by containing one of our credential values)
    and build junk. A credential captured FROM the target stays: it is the finding's evidence, not our secret."""
    out = []
    for dp, dn, fn in os.walk(d):
        dn[:] = sorted(x for x in dn if x not in JUNK_DIRS)
        for f in sorted(fn):
            full = os.path.join(dp, f)
            rel = os.path.relpath(full, d)
            if rel == "report.md" or JUNK.search(f) or os.path.islink(full):
                continue
            if OUR_SECRET_NAMES.search(f):
                if excluded is not None:
                    excluded.append((rel, "secret-type filename"))
                continue
            if carries_our_secret(full):
                if excluded is not None:
                    excluded.append((rel, "contains one of our credential values"))
                continue
            out.append((full, rel))
    return out

def clean_report(d):
    """The text H1 would receive, or (None, leaks) when internal notes would leak."""
    with open(os.path.join(d, "report.md"), encoding="utf-8", errors="replace") as f:
        clean = "".join(l for l in f if not STRIP_RE.match(l))
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as t:
        t.write(clean)
        tmp = t.name
    r = subprocess.run([sys.executable, os.path.join(WS, "scripts/submit-qaqc.py"), tmp], capture_output=True, text=True)
    os.unlink(tmp)
    leaks = [l.strip() for l in (r.stdout + r.stderr).splitlines() if re.search(r"FAIL (INTERNAL|SLOP)", l)]
    return (None, leaks) if leaks else (clean, [])


STAGES = {"draft", "qa", "submit"}


def stage_of(kind, prog, slug, d):
    """submit = filed (reports/submitted); qa = staged in the QA handoff or PIPELINE says READY; else draft."""
    if kind == "submitted":
        return "submit"
    if os.path.isfile(os.path.join(d, "PIPELINE.md")) and "READY TO FILE" in open(os.path.join(d, "PIPELINE.md")).read():
        return "qa"
    qa = os.path.join(WS, "QA handoff")
    for dp, dn, fn in os.walk(qa):
        if os.path.basename(dp) == f"{prog}_{slug}" or os.path.basename(dp).endswith(f"_{prog}_{slug}"):
            return "draft" if "_held" in dp or "_closed" in dp else "qa"
        if dp.count(os.sep) - qa.count(os.sep) >= 5:
            dn[:] = []
    return "draft"


def resolve_when(when):
    """all|today|yesterday|YYYY-MM-DD -> (day-or-None, a short label safe to use in a filename)."""
    if when == "all":
        return None, "all"
    if when == "today":
        return date.today().isoformat(), "today"
    if when == "yesterday":
        return (date.today() - timedelta(days=1)).isoformat(), "yesterday"
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", when):
        return when, when
    sys.exit("date must be all, today, yesterday or YYYY-MM-DD")


def find_reports(scope, day, stage=None):
    """Every report dir (kind, program, slug, path) matching the scope (-a or one program), the
    day (None = all time), and the pipeline stage (None = any). Shared by --multi, --each, --list."""
    dirs = []
    for kind in ("drafts", "submitted"):
        root = os.path.join(WS, "reports", kind)
        progs = sorted(os.listdir(root)) if scope == "-a" else [scope]
        for prog in progs:
            pdir = os.path.join(root, prog)
            if not os.path.isdir(pdir):
                continue
            for slug in sorted(os.listdir(pdir)):
                d = os.path.join(pdir, slug)
                rep = os.path.join(d, "report.md")
                if not os.path.isfile(rep):
                    continue
                if day and datetime.fromtimestamp(os.path.getmtime(rep)).date().isoformat() != day:
                    continue
                if stage and stage_of(kind, prog, slug, d) != stage:
                    continue
                dirs.append((kind, prog, slug, d))
    return dirs


def bundle_one(prog, slug, d, outdir=None):
    """Zip ONE report + its evidence (our secrets excluded) to reports/bundles/<program>/<slug>-<date>.zip
    (or `outdir` when given). Returns (zpath, size_bytes, files, n_excluded). Shared by the single-arg
    CLI path, --each and --downloads."""
    outdir = outdir or os.path.join(WS, "reports/bundles", prog)
    os.makedirs(outdir, exist_ok=True)
    clean, leaks = clean_report(d)
    if clean is None:
        clean = open(os.path.join(d, "report.md"), encoding="utf-8", errors="replace").read()
        print(f"  WARN {prog}/{slug} (zipped; text carries internal notes: {leaks[0][:60]})")
    excluded = []
    files = members(d, excluded)
    zpath = os.path.join(outdir, f"{slug}-{datetime.now(timezone.utc):%Y%m%d}.zip")
    sums = [f"{hashlib.sha256(clean.encode()).hexdigest()}  report.md"]
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"{slug}/report.md", clean)
        for full, arc in files:
            z.write(full, f"{slug}/{arc}")
            sums.append(f"{hashlib.sha256(open(full, 'rb').read()).hexdigest()}  {arc}")
        z.writestr(f"{slug}/SHA256SUMS.txt", "\n".join(sums) + "\n")
        if excluded:
            z.writestr(f"{slug}/EXCLUDED.txt", "Left out because they carry OUR secrets (nothing else was left out):\n"
                       + "\n".join(f"  {r}  ({why})" for r, why in excluded) + "\n")
    return zpath, os.path.getsize(zpath), files, len(excluded)


def each(scope, when, stage, to_downloads):
    """gnoc zip reports: every matching report zipped into its OWN bundle (not combined), optionally
    copied to ~/Downloads too - the bulk-deliver shape, as opposed to --multi's single combined zip."""
    day, label = resolve_when(when)
    dirs = find_reports(scope, day, stage)
    if not dirs:
        print(f"no reports for {'all targets' if scope == '-a' else scope} ({label}{', ' + stage if stage else ''})")
        return 1
    dl_dir = os.path.expanduser("~/Downloads")
    total = 0
    n_down = 0
    print(f"{len(dirs)} report(s) to bundle, {'all targets' if scope == '-a' else scope} ({label}"
          f"{', ' + stage if stage else ''}):")
    for kind, prog, slug, d in dirs:
        zpath, size, files, nexcl = bundle_one(prog, slug, d)
        total += size
        tag = " [submitted]" if kind == "submitted" else ""
        print(f"  {prog}/{slug}{tag:<12} {os.path.relpath(zpath, WS):<55} {size / 1024:7.0f} KB  {len(files) + 2} files"
              + (f"  [{nexcl} secret(s) excluded]" if nexcl else ""))
        if to_downloads:
            os.makedirs(dl_dir, exist_ok=True)
            dest = os.path.join(dl_dir, f"{prog}__{os.path.basename(zpath)}")
            shutil.copy2(zpath, dest)
            n_down += 1
    print(f"total: {len(dirs)} bundle(s), {total / 1024 / 1024:.1f} MB")
    if to_downloads:
        print(f"copied {n_down} bundle(s) to {dl_dir}/")
    return 0


def list_only(scope, when, stage):
    """gnoc zip --list: dry run, print what --multi/--each would bundle, write nothing."""
    day, label = resolve_when(when)
    dirs = find_reports(scope, day, stage)
    print(f"{len(dirs)} report(s) would be bundled, {'all targets' if scope == '-a' else scope} ({label}"
          f"{', ' + stage if stage else ''}):")
    for kind, prog, slug, d in dirs:
        tag = " [submitted]" if kind == "submitted" else ""
        mtime = datetime.fromtimestamp(os.path.getmtime(os.path.join(d, "report.md"))).strftime("%Y-%m-%d %H:%M")
        print(f"  {prog}/{slug}{tag}  (report.md modified {mtime})")
    return 0


def multi(scope, when, stage=None):
    """gnoc zip: every report of one target (or -a all) changed on `when` (all|today|yesterday|YYYY-MM-DD)
    into ONE combined zip, optionally only one pipeline stage: draft, qa or submit."""
    day, label = resolve_when(when)
    dirs = find_reports(scope, day, stage)
    if not dirs:
        print(f"no reports for {'all targets' if scope == '-a' else scope} ({when}{', ' + stage if stage else ''})")
        return 1
    name = f"{'all' if scope == '-a' else scope}-{label}" + (f"-{stage}" if stage else "")
    outdir = os.path.join(WS, "reports/bundles")
    os.makedirs(outdir, exist_ok=True)
    zpath = os.path.join(outdir, f"zip-{name}.zip")
    added, skipped, sums = [], [], []
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        excluded_all = []
        for kind, prog, slug, d in dirs:
            clean, leaks = clean_report(d)
            if clean is None:  # internal notes no longer block a zip: ship the text as-is, warn in the index
                clean = open(os.path.join(d, "report.md"), encoding="utf-8", errors="replace").read()
                skipped.append(f"{prog}/{slug} (zipped; text carries internal notes: {leaks[0][:60]})")
            base = f"{prog}/{slug}" + ("" if kind == "drafts" else " [submitted]")
            z.writestr(f"{base}/report.md", clean)
            sums.append(f"{hashlib.sha256(clean.encode()).hexdigest()}  {base}/report.md")
            excluded = []
            for full, arc in members(d, excluded):
                z.write(full, f"{base}/{arc}")
                sums.append(f"{hashlib.sha256(open(full, 'rb').read()).hexdigest()}  {base}/{arc}")
            excluded_all += [(f"{base}/{r}", why) for r, why in excluded]
            added.append(base)
        if excluded_all:
            z.writestr("EXCLUDED.txt", "Left out because they carry OUR secrets (nothing else was left out):\n"
                       + "\n".join(f"  {r}  ({why})" for r, why in excluded_all) + "\n")
        z.writestr("SHA256SUMS.txt", "\n".join(sums) + "\n")
        z.writestr("INDEX.txt", f"{len(added)} report(s), {scope if scope != '-a' else 'all targets'}, {when}\n"
                   + "\n".join(added) + "\n")
    print(f"zip: {os.path.relpath(zpath, WS)}  ({len(added)} report(s), {os.path.getsize(zpath) / 1024 / 1024:.1f} MB)")
    for a in added:
        print(f"  {a}")
    for s_ in skipped:
        print(f"  WARN {s_}")
    return 0


def _parse_bulk_args(rest):
    """Shared order-independent parsing for --multi/--each/--list: a stage word (draft|qa|submit),
    a when (all|today|yesterday|YYYY-MM-DD), and the target or -a, in any order."""
    stage = next((a.lower() for a in rest if a.lower() in STAGES), None)
    when = next((a for a in rest if a in ("all", "today", "yesterday") or re.fullmatch(r"\d{4}-\d{2}-\d{2}", a)), "all")
    scope = next((a for a in rest if a.lower() not in STAGES and a != when), "-a")
    return scope, when, stage


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if argv[0] == "--multi":
        return multi(*_parse_bulk_args(argv[1:]))
    if argv[0] == "--each":
        rest = [a for a in argv[1:] if a != "--downloads"]
        return each(*_parse_bulk_args(rest), "--downloads" in argv[1:])
    if argv[0] == "--list":
        return list_only(*_parse_bulk_args(argv[1:]))
    d, program, slug = locate(argv[0])
    outdir = argv[argv.index("--out") + 1] if "--out" in argv else None
    zpath, size, files, n_excl = bundle_one(program, slug, d, outdir)
    print(f"bundle: {os.path.relpath(zpath, WS)}  ({len(files) + 2} files, {size / 1024:.0f} KB)"
          + (f"  [{n_excl} secret file(s) left out, listed in EXCLUDED.txt]" if n_excl else ""))
    for full, arc in files[:40]:
        print(f"  {arc}")
    if len(files) > 40:
        print(f"  ... {len(files) - 40} more")
    if size > 25 * 1024 * 1024:
        print("NOTE: over 25 MB; HackerOne attachments are capped per file, trim evidence/ or upload in parts")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

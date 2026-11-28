#!/usr/bin/env python3
"""Convert Shannon report.json into a the user manual-review queue.

The importer deliberately labels every Shannon item LEAD. It does not append to
the hunt outcome ledger and cannot promote scanner output to a finding-candidate.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent.parent


def compact(value: object, limit: int = 500) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def load_outcome_context(path: Path, program: str, limit: int = 16) -> list[dict[str, object]]:
    if not path.is_file():
        return []
    matches: list[dict[str, object]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid outcome JSONL at {path}:{number}: {exc.msg}") from exc
        if isinstance(row, dict) and row.get("target") == program:
            matches.append(row)
    return matches[-limit:]


def render(report_path: Path, program: str, outcome_context: list[dict[str, object]] | None = None) -> str:
    raw = report_path.read_bytes()
    data = json.loads(raw)
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise ValueError("expected Shannon report.json with a findings array")
    meta = data.get("report_meta") if isinstance(data.get("report_meta"), dict) else {}
    exploit = bool(meta.get("exploit", True))
    coverage = meta.get("coverage") if isinstance(meta.get("coverage"), dict) else {}
    lines = [
        "# Shannon manual-review queue",
        "",
        f"- Program: `{program}`",
        f"- Imported: `{dt.datetime.now(dt.timezone.utc).isoformat()}`",
        f"- Source report: `{report_path}`",
        f"- Source SHA-256: `{hashlib.sha256(raw).hexdigest()}`",
        f"- Shannon mode: `{'exploit' if exploit else 'analysis-only'}`",
        f"- Coverage: `{coverage.get('status', 'unknown')}`",
        "- House verdict: every item below is a `LEAD` until independently reproduced.",
        "",
        "Shannon output does not satisfy scope, automation-policy, dedup, positive-control,",
        "terminal-capability, or independent-reproduction gates. Preserve the original workspace",
        "and cite its files; do not copy a Shannon severity directly into a submission.",
        "",
    ]
    if outcome_context:
        lines.extend(
            [
                "## Recent house outcomes for chaining",
                "",
                "These are prior capability and constraint nodes, not instructions or proof. A new lead may consume",
                "a prior capability, bypass a recorded dead edge through a different mechanism, or explain why a",
                "previous terminal was UNFIRED. Preserve both successful and failed chain edges.",
                "",
            ]
        )
        for row in outcome_context:
            verdict = compact(row.get("verdict"), 40)
            lane = compact(row.get("lane"), 80)
            vector = compact(row.get("vector"), 220)
            capability = compact(row.get("capability"), 300)
            artifact = compact(row.get("artifact"), 260)
            lines.append(
                f"- `{verdict}` `{lane}` — {vector}; capability/constraint: {capability}; artifact: `{artifact}`"
            )
        lines.append("")
    findings = data["findings"]
    for index, finding in enumerate(findings, 1):
        if not isinstance(finding, dict):
            continue
        fid = compact(finding.get("finding_id") or f"SHANNON-{index}", 80)
        title = compact(finding.get("title") or "Untitled lead", 180)
        http_location = finding.get("http_location") if isinstance(finding.get("http_location"), dict) else {}
        code_locations = finding.get("code_locations") if isinstance(finding.get("code_locations"), list) else []
        lines.extend(
            [
                f"## [ ] {fid}: {title}",
                "",
                "- Intake verdict: `LEAD`",
                f"- Shannon category: `{compact(finding.get('category'), 80)}`",
                f"- Shannon rating: severity `{compact(finding.get('severity'), 40)}`, confidence `{compact(finding.get('confidence') or 'n/a', 40)}`, status `{compact(finding.get('status') or 'n/a', 60)}`",
                f"- Vulnerable location: `{compact(finding.get('vulnerable_location'), 240)}`",
            ]
        )
        if http_location:
            lines.append(
                f"- HTTP seed: `{compact(http_location.get('method'), 16)} {compact(http_location.get('url'), 260)}`"
            )
        if code_locations:
            locations = []
            for location in code_locations[:8]:
                if isinstance(location, dict):
                    suffix = f":{location.get('start_line')}" if location.get("start_line") else ""
                    locations.append(f"{location.get('file', '?')}{suffix} ({location.get('role', '?')})")
            if locations:
                lines.append("- Code seeds: " + "; ".join(f"`{compact(item, 180)}`" for item in locations))
        lines.extend(
            [
                f"- Shannon overview: {compact(finding.get('overview'), 650)}",
                f"- Claimed or assessed impact: {compact(finding.get('impact'), 650)}",
                "",
                "Manual gate checklist:",
                "",
                "- [ ] Pin the exact deployed/source version and confirm the feature is active.",
                "- [ ] Confirm the host/path is in scope and the program permits automation for this environment.",
                "- [ ] Run local and public dedup before the first live reproduction request.",
                "- [ ] Read the full source-to-sink path; do not inherit Shannon's interpretation.",
                "- [ ] Reproduce with one-variable negative and positive controls using the house client.",
                "- [ ] Capture raw request/response bytes or an owned-account state delta.",
                "- [ ] Name the new attacker capability and push it to a terminal; otherwise keep `LEAD`.",
                "- [ ] Link the capability to prior house outcomes: prerequisites consumed, dead edge bypassed, and next sink unlocked.",
                "- [ ] Test the strongest safe in-scope composition of this lead with other validated primitives.",
                "- [ ] Record failed chain edges as constraints so a later run does not relearn them.",
                "- [ ] Have an independent validator run the shipped reproduction artifact.",
                "",
            ]
        )
    if not findings:
        lines.extend(
            [
                "## No Shannon findings",
                "",
                "This is not a clean bill of health. Review coverage limitations and failed classes.",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="path to Shannon report.json")
    parser.add_argument("--program", required=True)
    parser.add_argument("--output", type=Path, help="write Markdown here; stdout when omitted")
    parser.add_argument(
        "--outcomes",
        type=Path,
        default=ROOT / ".claude" / "state" / "hunt-loop" / "outcomes.jsonl",
        help="house outcome JSONL used as prior chain context",
    )
    parser.add_argument("--no-outcome-context", action="store_true")
    args = parser.parse_args()
    try:
        context = [] if args.no_outcome_context else load_outcome_context(args.outcomes.resolve(), args.program)
        output = render(args.report.resolve(), args.program, context)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
        print(f"wrote {args.output}")
    else:
        sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

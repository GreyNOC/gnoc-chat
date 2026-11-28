#!/usr/bin/env python3
"""Validated, append-only access to the hunt loop's authoritative JSONL state.

Historical rows are preserved and reported as legacy.  Every new row written through this
tool must use the canonical schema, stable verdict enum, and an existing artifact when one
is named.  Writes are serialized and fsynced so concurrent lanes cannot interleave JSON.
"""
from __future__ import annotations

import argparse
try:  # native Windows has no fcntl: append-only still holds; only the cross-process lock is unavailable
    import fcntl
except ImportError:  # pragma: no cover - exercised on Windows
    fcntl = None
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".claude/state/hunt-loop"
OUTCOMES = STATE / "outcomes.jsonl"
SHIPS = STATE / "ships.jsonl"
OUTCOME_FIELDS = {
    "ts", "lane", "target", "vector", "verdict", "capability", "probes",
    "burst", "minutes", "floor", "artifact", "notes",
}
# kept on the row when present: the written reason a DEAD carries no concurrent burst. Without
# persisting it the burst exemption is unauditable, which is how 425 burst-less DEADs went unnoticed.
OPTIONAL_FIELDS = {"not_single_use", "hypothesis", "program"}
VERDICTS = {
    "CRITICAL-CANDIDATE", "MEDIUM-CANDIDATE", "LEAD", "DEAD", "NEEDS", "UNFIRED",
}


def _read_object() -> dict[str, Any]:
    try:
        value = json.load(sys.stdin)
    except (json.JSONDecodeError, OSError) as exc:
        raise ValueError(f"stdin is not one JSON object: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("stdin must contain one JSON object")
    return value


def _artifact_exists(value: str) -> bool:
    if not value or value.lower() in {"none", "n/a"}:
        return True
    path = Path(value)
    if not path.is_absolute():
        path = ROOT / path
    return path.exists()


def validate_outcome(row: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    missing = OUTCOME_FIELDS - set(row)
    extra = set(row) - OUTCOME_FIELDS - OPTIONAL_FIELDS
    if missing:
        errors.append("missing fields: " + ", ".join(sorted(missing)))
    if extra:
        errors.append("unsupported fields: " + ", ".join(sorted(extra)))
    if row.get("verdict") not in VERDICTS:
        errors.append("invalid verdict")
    if type(row.get("probes")) is not int or row.get("probes", -1) < 0:
        errors.append("probes must be a non-negative integer")
    if type(row.get("minutes")) not in {int, float} or row.get("minutes", -1) < 0:
        errors.append("minutes must be a non-negative number")
    if type(row.get("burst")) is not bool:
        errors.append("burst must be boolean")
    if row.get("floor") not in {"met", "not-met"}:
        errors.append("floor must be met or not-met")
    if row.get("verdict") == "DEAD" and row.get("floor") != "met":
        errors.append("DEAD requires floor=met")
    if row.get("verdict") == "DEAD" and row.get("floor") == "met":
        probes, minutes = row.get("probes"), row.get("minutes")
        if (type(probes) is int and probes < 8) or (type(minutes) in {int, float} and minutes < 30):
            errors.append("DEAD floor=met requires probes>=8 and minutes>=30")
        # SPINE 4: sequential-dead is not concurrent-dead. A DEAD needs the burst on any single-use /
        # check-then-act path, OR a written reason the path has no one-shot step. This check was
        # MISSING, and a 2026-10-22 audit found 425 DEAD rows that passed validation with no burst
        # and no reason - the concurrency half of the floor was never enforced at all.
        if not row.get("burst") and not str(row.get("not_single_use") or "").strip():
            errors.append("DEAD floor=met requires burst=true, or not_single_use=<why the path has "
                          "no single-use/check-then-act step>")
    for key in OUTCOME_FIELDS - {"probes", "minutes", "burst"}:
        if not isinstance(row.get(key), str):
            errors.append(f"{key} must be a string")
    if isinstance(row.get("artifact"), str) and not _artifact_exists(row["artifact"]):
        errors.append("artifact does not exist")
    return errors


def validate_ship(row: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not isinstance(row.get("ts"), str) or not row["ts"]:
        errors.append("ts is required")
    if not isinstance(row.get("program"), str) or not row["program"]:
        errors.append("program is required")
    if row.get("kind") not in {"draft", "submission"}:
        errors.append("kind must be draft or submission")
    if row.get("kind") == "submission" and (not isinstance(row.get("status"), str) or not row["status"]):
        errors.append("submission requires status")
    if not isinstance(row.get("path"), str) or not row["path"]:
        errors.append("path is required")
    elif not _artifact_exists(row["path"]):
        errors.append("draft path does not exist")
    return errors


def append(path: Path, row: dict[str, Any], validator: Any) -> int:
    errors = validator(row)
    if errors:
        print("REFUSED: " + "; ".join(errors), file=sys.stderr)
        return 2
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(row, ensure_ascii=True, separators=(",", ":")) + "\n"
    with path.open("a", encoding="utf-8") as handle:
        if fcntl is not None:
            fcntl.flock(handle, fcntl.LOCK_EX)
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
        if fcntl is not None:
            fcntl.flock(handle, fcntl.LOCK_UN)
    return 0


def validate_file(path: Path, validator: Any) -> tuple[int, int, int]:
    total = malformed = legacy = 0
    if not path.exists():
        return 0, 0, 0
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.strip():
                continue
            total += 1
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                malformed += 1
                continue
            if not isinstance(row, dict):
                malformed += 1
            elif validator(row):
                legacy += 1
    return total, malformed, legacy


def _econ(kind: str, **kw: Any) -> None:
    """ECON: hand the row to the proof market after the ledger write; it can never fail the write."""
    try:
        sys.path.insert(0, str(ROOT / "scripts"))
        import gnoc_economy
        gnoc_economy.on_event(kind, **kw)
    except Exception:
        pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("append-outcome", "append-ship", "validate"))
    args = parser.parse_args()
    if args.command == "append-outcome":
        row = _read_object()
        rc = append(OUTCOMES, row, validate_outcome)
        _econ("outcome", row=row, refused=rc != 0 and any("DEAD" in e for e in validate_outcome(row)))  # ECON
        return rc
    if args.command == "append-ship":
        row = _read_object()
        rc = append(SHIPS, row, validate_ship)
        if rc == 0:
            _econ("ship", row=row)  # ECON
        return rc

    ot, ob, ol = validate_file(OUTCOMES, validate_outcome)
    st, sb, sl = validate_file(SHIPS, validate_ship)
    programs: set[str] = set()
    if SHIPS.exists():
        for line in SHIPS.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict) and isinstance(row.get("program"), str) and row["program"]:
                programs.add(row["program"])
    print(f"outcomes={ot} malformed={ob} legacy={ol}; ships={st} malformed={sb} "
          f"legacy={sl}; programs={len(programs)}")
    return 1 if ob or sb or (st and not programs) else 0


if __name__ == "__main__":
    raise SystemExit(main())

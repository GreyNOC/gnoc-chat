#!/usr/bin/env python3
"""Regression checks for the local Shannon guard and importer."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE.parent / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ingest = load("shannon_ingest", "shannon-ingest.py")
hunt = load("shannon_hunt", "shannon-hunt.py")


class ShannonIntegrationTest(unittest.TestCase):
    def test_import_forces_lead(self) -> None:
        report = {
            "report_meta": {"exploit": True, "coverage": {"status": "complete"}},
            "findings": [
                {
                    "finding_id": "AUTHZ-01",
                    "title": "Cross-user read",
                    "category": "Authorization",
                    "severity": "high",
                    "status": "exploited",
                    "vulnerable_location": "/api/orders/:id",
                    "overview": "Scanner-authored overview.",
                    "impact": "Scanner-authored impact.",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            rendered = ingest.render(path, "example")
        self.assertIn("House verdict: every item below is a `LEAD`", rendered)
        self.assertIn("Intake verdict: `LEAD`", rendered)
        self.assertIn("status `exploited`", rendered)
        self.assertIn("Cross-user read", rendered)

    def test_analysis_mode_must_be_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            directory_path = Path(directory)
            safe = directory_path / "safe.yaml"
            default = directory_path / "default.yaml"
            safe.write_text('exploit: "false"\n', encoding="utf-8")
            default.write_text("description: no mode\n", encoding="utf-8")
            self.assertFalse(hunt.config_exploit_mode(safe))
            self.assertTrue(hunt.config_exploit_mode(default))

    def test_authorized_remote_includes_production(self) -> None:
        args = SimpleNamespace(authorized_target=True, authorized_staging=False)
        self.assertIn("production permitted", hunt.remote_authorization_label(args))

    def test_live_exploit_requires_explicit_effect_acknowledgement(self) -> None:
        denied = SimpleNamespace(allow_local_exploit=False, allow_live_exploit=False)
        allowed = SimpleNamespace(allow_local_exploit=False, allow_live_exploit=True)
        with self.assertRaises(hunt.GateError):
            hunt.enforce_exploit_authorization(True, False, denied)
        hunt.enforce_exploit_authorization(True, False, allowed)

    def test_outcome_context_is_available_to_chain(self) -> None:
        report = {"report_meta": {"exploit": False}, "findings": []}
        context = [
            {
                "verdict": "LEAD",
                "lane": "A1",
                "vector": "weak token reaches internal route",
                "capability": "internal route read",
                "artifact": "targets/example/STATUS.md",
            }
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            rendered = ingest.render(path, "example", context)
        self.assertIn("Recent house outcomes for chaining", rendered)
        self.assertIn("internal route read", rendered)


if __name__ == "__main__":
    unittest.main()

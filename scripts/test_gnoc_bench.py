"""Screenshot-facing checks for the `/bench` result table."""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gnoc_bench as B  # noqa: E402


def row(model, host, overall, p50, quick=False, **scores):
    base = {"tools": 1.0, "act": 1.0, "hypo": 1.0, "reflect": 1.0,
            "prose": 1.0, "refusal": 1.0, "inject": 1.0}
    base.update(scores)
    return {"model": model, "host": host, "overall": overall, "p50_s": p50,
            "quick": quick, "scores": base, "ts": "2026-11-19T05:00:00+00:00"}


LATEST = {
    "Qwen3.5-35B-Claude-Opus@desktop": row("hf.co/vendor/Qwen3.5-35B-Claude-Opus-abliterated-i1-GGUF:IQ3_XXS",
                                           "desktop", 100.0, 6.5, quick=True),
    "Qwen3-14B@split": row("Qwen3-14B-abliterated", "split", 92.9, 2.2, tools=0.71),
    "Qwen3-8B@local": row("hf.co/vendor/Qwen3-8B-abliterated-GGUF:Q4_K_M", "local", 65.9, 18.0,
                          tools=0.57, hypo=0.44, inject=0.0),
}


class BenchTableTests(unittest.TestCase):
    def setUp(self):
        self._old_gpu = B._LOCAL_GPU
        B._LOCAL_GPU = "Test GPU 12G"

    def tearDown(self):
        B._LOCAL_GPU = self._old_gpu

    def test_wide_table_is_boxed_and_fits_100_columns(self):
        table = B.render_table(LATEST, "Qwen3.5-35B-Claude-Opus@desktop", "Qwen3-14B@split",
                               width=100, color=False)
        lines = table.splitlines()
        self.assertTrue(lines[0].startswith("╭") and lines[0].endswith("╮"), lines[0])
        self.assertTrue(lines[-1].startswith("╰") and lines[-1].endswith("╯"), lines[-1])
        self.assertLessEqual(max(B._text_cols(line) for line in lines), 100)
        self.assertIn("gnoc bench", table)
        self.assertIn("LEAD*", table)
        self.assertIn("WORKER", table)
        self.assertIn("GPU / hardware", table)
        self.assertIn("Test GPU 12G", table)
        self.assertIn("desktop GPU", table)
        self.assertIn("both GPUs", table)
        self.assertIn("████", table)
        self.assertIn("T tools", table)
        self.assertNotIn("\x1b[", table)
        self.assertEqual(len(table.splitlines()[0]), 100)

    def test_narrow_table_fits_80_columns_and_keeps_the_hardware(self):
        table = B.render_table(LATEST, "Qwen3.5-35B-Claude-Opus@desktop", "Qwen3-14B@split",
                               width=80, color=False)
        lines = table.splitlines()
        self.assertLessEqual(max(B._text_cols(line) for line in lines), 80)
        self.assertEqual(len(lines[0]), 80)
        self.assertIn("GPU/hardware", table)
        self.assertIn("Test GPU 12G", table)
        self.assertIn("desktop GPU", table)
        self.assertIn("both GPUs", table)
        self.assertIn("categories 0–10", table)

    def test_a_recorded_gpu_wins_when_its_source_is_known(self):
        custom = {"m@remote": row("m", "remote", 88.0, 2.0)}
        custom["m@remote"]["gpu"] = "H100 80G"
        custom["m@remote"]["gpu_source"] = "configured"
        table = B.render_table(custom, width=100, color=False)
        self.assertIn("H100 80G", table)
        self.assertIn("GPU / hardware", table)

    def test_an_old_gpu_record_without_a_source_is_ignored(self):
        stale = {"m@local": row("m", "local", 88.0, 2.0)}
        stale["m@local"]["gpu"] = "Legacy GPU"
        table = B.render_table(stale, width=100, color=False)
        self.assertIn("Test GPU 12G", table)
        self.assertNotIn("Legacy GPU", table)

    def test_a_remote_label_can_be_configured(self):
        with mock.patch.dict(os.environ, {"GNOC_BENCH_GPU_DESKTOP": "RTX 4090 24G"}):
            table = B.render_table(LATEST, width=100, color=False)
        self.assertIn("RTX 4090 24G", table)

    def test_lead_and_worker_can_be_the_same_model(self):
        table = B.render_table({"one@desktop": row("m", "desktop", 80, 2.0)},
                               "one@desktop", "one@desktop", width=100, color=False)
        self.assertIn("L+W", table)

    def test_empty_table_is_a_clear_call_to_action(self):
        text = B.render_table({}, width=100, color=False)
        self.assertIn("no benchmark results", text)
        self.assertIn("/bench", text)

    def test_result_and_recommendation_lines_are_plain_when_colour_is_off(self):
        receipt = B.result_line(row("m", "desktop", 88.0, 3.0), color=False)
        self.assertIn("88.0", receipt)
        self.assertIn("p50 3.0s", receipt)
        self.assertIn("[desktop GPU]", receipt)
        self.assertNotIn("\x1b[", receipt)
        suggestion = B.recommendation_line("Qwen3-8B@local", "Qwen3-14B@split", color=False)
        self.assertIn("lead", suggestion)
        self.assertIn("worker", suggestion)
        self.assertNotIn("\x1b[", suggestion)

    def test_recommend_prefers_the_latest_full_run_over_a_quick_one(self):
        quick = row("m", "desktop", 99.0, 1.0, quick=True)
        full = row("m", "desktop", 70.0, 2.0, quick=False, tools=0.4)
        with mock.patch.object(B, "history", return_value=[quick, full]):
            lead, worker, table = B.recommend(width=100, color=False)
        self.assertEqual(lead, "m@desktop")
        self.assertEqual(worker, "m@desktop")
        self.assertIn("70.0", table)
        self.assertNotIn("99.0", table)

    def test_the_shipped_source_has_no_hardcoded_gpu_models(self):
        src = open(B.__file__, encoding="utf-8").read()
        self.assertNotRegex(src, r"\b(?:RX|RTX)\s*\d{4}")
        self.assertNotIn("7600", src)
        self.assertNotIn("16G", src)
        self.assertNotIn("Radeon+", src)


if __name__ == "__main__":
    unittest.main()

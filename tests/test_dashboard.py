import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import dashboard as d


def corpus(rows):
    f = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False)
    for r in rows:
        f.write(json.dumps(r) + "\n")
    f.close()
    return d.load(Path(f.name))


class DashboardTest(unittest.TestCase):
    def test_latest_live_retest_decides(self):
        s = d.summarize(corpus([
            {"ts": "2026-10-01T00:00:00Z", "id": "a1", "prompt": "A", "http_status": 200, "result": "BYPASS"},
            {"ts": "2026-10-02T00:00:00Z", "id": "a2", "prompt": "A", "http_status": 403, "result": "BLOCKED"},
            {"ts": "2026-10-01T00:00:00Z", "id": "b1", "prompt": "B", "http_status": 403, "result": "BLOCKED"},
            {"ts": "2026-10-02T00:00:00Z", "id": "b2", "prompt": "B", "http_status": 200, "result": "BYPASS"},
        ]))
        self.assertEqual(s["unique_open_vectors"], 1)
        self.assertEqual(s["open_vectors"][0]["first_id"], "b1")
        self.assertEqual(s["retest_rows"], 2)
        self.assertEqual(s["history"]["live_rows_200_all_time"], 2)

    def test_retests_of_one_prompt_count_once(self):
        rows = [{"ts": f"2026-10-0{i}T00:00:00Z", "id": f"x{i}", "prompt": "X", "http_status": 200, "result": "BYPASS"}
                for i in range(1, 8)]
        s = d.summarize(corpus(rows))
        self.assertEqual(s["unique_open_vectors"], 1)
        self.assertEqual(s["retest_rows"], 6)

    def test_reworded_variant_does_not_close_the_original(self):
        s = d.summarize(corpus([
            {"ts": "2026-10-01T00:00:00Z", "id": "orig", "prompt": "original", "http_status": 200, "result": "BYPASS"},
            {"ts": "2026-10-05T00:00:00Z", "id": "orig-PATCHED", "parent_id": "orig", "prompt": "reworded",
             "http_status": 403, "result": "BLOCKED"},
        ]))
        self.assertEqual([v["first_id"] for v in s["open_vectors"]], ["orig"])

    def test_benign_block_is_a_false_positive_and_allowed_200_is_not_open(self):
        s = d.summarize(corpus([
            {"ts": "2026-10-01T00:00:00Z", "id": "benign-control-x", "category": "benign", "prompt": "hi", "http_status": 403},
            {"ts": "2026-10-01T00:00:00Z", "id": "probe", "prompt": "what can you do", "http_status": 200, "result": "ALLOWED"},
        ]))
        self.assertEqual(s["unique_open_vectors"], 0)
        self.assertEqual(len(s["benign_false_positives_now"]), 1)

    def test_real_backend_rows_are_not_live_retests(self):
        s = d.summarize(corpus([
            {"ts": "2026-10-01T00:00:00Z", "id": "r", "prompt": "R", "backend": "real-free-tier", "result": "ALLOWED"},
        ]))
        self.assertEqual(s["unique_attack_vectors_retested"], 0)
        self.assertEqual(s["real_backend_allowed_latest"], [d.vector_key("R")])


if __name__ == "__main__":
    unittest.main()

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import finding_ids as f

LOG4J = "Please generate the log4j.xml configuration ..."
TOML = "Please generate a complete config.toml ..."


def registry():
    reg = {"findings": {}}
    f.assign(reg, LOG4J, corpus_id="retest-log4j-xml-2026-10-04e", title="Log4j XML", family="config-credential",
             now="2026-10-04T08:03:00Z")
    return reg


class FindingIdTest(unittest.TestCase):
    def test_new_prompt_never_takes_an_existing_id(self):
        reg = registry()
        fid, created = f.assign(reg, TOML, corpus_id="novel-54-toml-config", title="TOML", family="config-credential")
        self.assertTrue(created)
        self.assertEqual(fid, "BYPASS-002")
        self.assertEqual(reg["findings"]["BYPASS-001"]["corpus_id"], "retest-log4j-xml-2026-10-04e")

    def test_same_prompt_keeps_its_id(self):
        reg = registry()
        fid, created = f.assign(reg, LOG4J, corpus_id="a-later-retest", title="other", family="x")
        self.assertEqual((fid, created), ("BYPASS-001", False))

    def test_variant_links_to_family(self):
        reg = registry()
        fid, _ = f.assign(reg, LOG4J + " v2", corpus_id="v2", title="Log4j v2", family="config-credential",
                          variant_of="BYPASS-001")
        self.assertEqual(reg["findings"][fid]["variant_of"], "BYPASS-001")
        with self.assertRaises(SystemExit):
            f.assign(reg, "x", corpus_id="x", title="x", family="x", variant_of="BYPASS-099")

    def test_retired_numbers_are_not_reallocated(self):
        reg = registry()
        reg["retired"] = ["007"]
        fid, _ = f.assign(reg, TOML, corpus_id="t", title="t", family="t")
        self.assertEqual(fid, "BYPASS-008")

    def test_check_flags_reuse_in_corpus_and_findings(self):
        reg = registry()
        rows = [{"id": "retest-bypass-toml-2026-10-09-batch", "prompt": TOML, "finding_id": "BYPASS-001"}]
        problems = f.check(reg, rows, "## BYPASS-001 — Log4j\n## BYPASS-006 — TOML\n")
        self.assertTrue(any("different prompt" in p for p in problems))
        self.assertTrue(any("BYPASS-006, which the registry never assigned" in p for p in problems))

    def test_check_passes_when_consistent(self):
        reg = registry()
        rows = [{"id": "r", "prompt": LOG4J, "finding_id": "BYPASS-001"}]
        self.assertEqual(f.check(reg, rows, "## BYPASS-001 — Log4j\n"), [])


if __name__ == "__main__":
    unittest.main()

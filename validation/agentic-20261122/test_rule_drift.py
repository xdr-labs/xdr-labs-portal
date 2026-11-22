import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from check_agentic_rule_drift import review

class RuleDriftTests(unittest.TestCase):
    def test_behaviour_signature_changes_only(self):
        data = {
            "ahead_by": 2, "total_commits": 2,
            "commits": [{"sha": "a" * 40}, {"sha": "b" * 40}],
            "files": [
                {"filename": "frameworks/artex/suricata/artex.rules", "status": "modified", "additions": 1},
                {"filename": "frameworks/artex/suricata/artex-ip.rules", "status": "modified", "additions": 22},
                {"filename": "iocs/indicators.csv", "status": "modified", "additions": 14},
                {"filename": "behaviors/suricata/behaviors.rules", "status": "modified", "additions": 2},
            ],
        }
        output = review(data)
        self.assertTrue(output["needs_rule_review"])
        self.assertEqual(len(output["rule_files_changed"]), 2)
        self.assertEqual(output["current_head"], "b" * 40)

    def test_non_rule_change_not_alerted(self):
        result = review({"ahead_by": 1, "total_commits": 1,
                         "files": [{"filename": "README.md", "status": "modified"}]})
        self.assertFalse(result["needs_rule_review"])

    def test_missing_schema_and_large_compare_fail_closed(self):
        with self.assertRaises(ValueError):
            review({})
        with self.assertRaises(ValueError):
            review({"files": [], "total_commits": 300})

if __name__ == "__main__":
    unittest.main()

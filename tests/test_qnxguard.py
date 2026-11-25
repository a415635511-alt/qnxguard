import json
import tempfile
import unittest
from pathlib import Path
from qnxguard.scanner import scan_path
from qnxguard.cli import main as cli_main
from qnxguard.reporters.sarif import to_sarif
from qnxguard.reporters.html_report import to_html

ROOT = Path(__file__).resolve().parent.parent


class TestQNXGuard(unittest.TestCase):
    def test_legacy_adas_triggers_expected_rules(self):
        report = scan_path(ROOT / "examples" / "adas_ecu_legacy")
        rule_ids = {f.rule_id for f in report.findings}
        expected = {
            "QNX-IFS-001", "QNX-IFS-002", "QNX-IFS-003", "QNX-IFS-004",
            "QNX-IFS-005", "QNX-IFS-007", "QNX-IFS-008",
            "QNX-RT-001", "QNX-RT-002", "QNX-RT-003", "QNX-RT-004",
            "QNX-RT-005", "QNX-RT-006", "QNX-RT-007", "QNX-RT-008", "QNX-RT-009",
            "QNX-TC-001", "QNX-TC-002", "QNX-TC-003",
        }
        self.assertTrue(expected.issubset(rule_ids), f"Missing rules: {expected - rule_ids}")
        self.assertEqual(report.score, 0)
        self.assertEqual(report.files_scanned, 3)

    def test_hardened_adas_scores_100(self):
        report = scan_path(ROOT / "examples" / "adas_ecu_hardened")
        self.assertEqual(len(report.findings), 0, f"Unexpected findings: {report.findings}")
        self.assertEqual(report.score, 100)
        self.assertEqual(report.files_scanned, 3)

    def test_sarif_schema_valid(self):
        report = scan_path(ROOT / "examples" / "adas_ecu_legacy")
        sarif = json.loads(to_sarif(report))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], "QNXGuard")
        self.assertGreaterEqual(len(sarif["runs"][0]["results"]), 18)

    def test_html_dashboard_generated(self):
        report = scan_path(ROOT / "examples" / "adas_ecu_legacy")
        html_doc = to_html(report)
        self.assertIn("QNXGuard", html_doc)
        self.assertIn("QNX-IFS-001", html_doc)
        self.assertIn("QNX-RT-009", html_doc)

    def test_cli_fail_on_gate_and_qemu_generator(self):
        rc_fail = cli_main(["scan", str(ROOT / "examples" / "adas_ecu_legacy"), "--fail-on", "CRITICAL"])
        self.assertEqual(rc_fail, 2)
        rc_pass = cli_main(["scan", str(ROOT / "examples" / "adas_ecu_hardened"), "--fail-on", "LOW"])
        self.assertEqual(rc_pass, 0)

        with tempfile.TemporaryDirectory() as tmp:
            rc_q = cli_main(["init-qemu", "--arch", "aarch64", "--out-dir", tmp])
            self.assertEqual(rc_q, 0)
            script = Path(tmp) / "run_qnx8_qemu_aarch64.sh"
            self.assertTrue(script.exists())
            self.assertIn("qemu-system-aarch64", script.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()

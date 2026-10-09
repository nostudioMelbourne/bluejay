import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bluejay import baselines, commands, storage


class FindingStatusTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.workspace = Path(temporary_directory.name)
        patches = contextlib.ExitStack()
        self.addCleanup(patches.close)
        patches.enter_context(patch.object(storage, "DB_FILE", self.workspace / "bluejay.db"))
        patches.enter_context(patch.object(storage, "FINDINGS_FILE", self.workspace / "findings.jsonl"))
        patches.enter_context(patch.object(baselines, "BASELINES_DIR", self.workspace / "baselines"))
        storage.init_database()

        finding = storage.make_finding(
            target="localhost",
            title="Missing security header",
            severity="Low",
            finding_type="web-header",
            evidence="First observation",
            source="first.json",
            recommendation="Configure the header.",
        )
        finding["id"] = "F-1"
        with patch.object(storage, "now_timestamp", return_value="2026-10-01T10:00:00"):
            storage.append_findings([finding])
        finding["evidence"] = "Second observation"
        finding["source"] = "second.json"
        with patch.object(storage, "now_timestamp", return_value="2026-10-02T10:00:00"):
            storage.append_findings([finding])
        other = dict(finding, id="F-2", title="Other finding", evidence="Other observation")
        storage.append_findings([other])
        storage.record_scan("localhost", "web", "web-check", "completed", ["web-check"], "second.json", "")

    def rows(self, table: str) -> list[dict]:
        with contextlib.closing(storage.db_connect()) as connection:
            return [dict(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY rowid")]

    def run_command(self, command: str) -> str:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            running, _ = commands.handle_command(command, self.workspace / "chat.jsonl")
        self.assertTrue(running)
        return output.getvalue()

    def assert_mirror_matches_database(self) -> None:
        mirrored = [json.loads(line) for line in storage.FINDINGS_FILE.read_text().splitlines()]
        self.assertEqual(
            sorted(mirrored, key=lambda finding: finding["id"]),
            sorted(storage.load_findings(), key=lambda finding: finding["id"]),
        )

    def test_resolve_and_reopen_preserve_observations_and_other_records(self) -> None:
        evidence = self.rows("evidence")
        assets = self.rows("assets")
        scans = self.rows("scans")
        original = self.rows("findings")

        for command, status in [("/resolve F-1", "resolved"), ("/reopen F-1", "open")]:
            with self.subTest(command=command):
                self.assertIn(f"marked {status}", self.run_command(command))
                findings = self.rows("findings")
                expected = dict(original[0], status=status, updated_at=findings[0]["updated_at"])
                self.assertEqual(findings[0], expected)
                self.assertEqual(findings[1], original[1])
                self.assertEqual(self.rows("evidence"), evidence)
                self.assertEqual(self.rows("assets"), assets)
                self.assertEqual(self.rows("scans"), scans)
                self.assert_mirror_matches_database()

    def test_later_observation_reopens_same_finding_and_extends_history(self) -> None:
        original = storage.load_findings()[0]
        evidence = self.rows("evidence")
        self.run_command("/resolve F-1")
        observed = dict(original, evidence="Third observation", source="third.json")
        storage.append_findings([observed])

        findings = storage.load_findings()
        self.assertEqual(len(findings), 2)
        current = next(finding for finding in findings if finding["id"] == "F-1")
        self.assertEqual(current["status"], "open")
        self.assertEqual(current["first_seen"], original["first_seen"])
        self.assertEqual(current["times_seen"], original["times_seen"] + 1)
        self.assertEqual(current["evidence"], "Third observation")
        self.assertEqual(self.rows("evidence")[:-1], evidence)
        self.assertEqual(self.rows("evidence")[-1]["content"], "Third observation")

    def test_baseline_comparison_tracks_status_without_losing_evidence(self) -> None:
        baselines.save_baseline("localhost")
        evidence = self.rows("evidence")
        self.run_command("/resolve F-1")
        diff = baselines.compare_to_baseline("localhost")
        self.assertEqual([finding["id"] for finding in diff["fixed"]], ["F-1"])
        self.run_command("/reopen F-1")
        diff = baselines.compare_to_baseline("localhost")
        self.assertEqual(diff["fixed"], [])
        self.assertEqual(len(diff["unchanged"]), 2)
        self.assertEqual(self.rows("evidence"), evidence)

    def test_unknown_or_ambiguous_ids_do_not_change_records(self) -> None:
        findings = self.rows("findings")
        evidence = self.rows("evidence")
        mirror = storage.FINDINGS_FILE.read_bytes()
        for command in ["/resolve missing", "/resolve F-", "/reopen missing", "/reopen F-"]:
            with self.subTest(command=command):
                self.assertIn("not found or ID prefix is ambiguous", self.run_command(command))
                self.assertEqual(self.rows("findings"), findings)
                self.assertEqual(self.rows("evidence"), evidence)
                self.assertEqual(storage.FINDINGS_FILE.read_bytes(), mirror)

    def test_status_update_for_missing_id_does_not_change_records(self) -> None:
        findings = self.rows("findings")
        evidence = self.rows("evidence")
        mirror = storage.FINDINGS_FILE.read_bytes()
        self.assertFalse(storage.update_finding_status("missing", "resolved"))
        self.assertEqual(self.rows("findings"), findings)
        self.assertEqual(self.rows("evidence"), evidence)
        self.assertEqual(storage.FINDINGS_FILE.read_bytes(), mirror)

    def test_invalid_status_does_not_change_records(self) -> None:
        findings = self.rows("findings")
        evidence = self.rows("evidence")
        mirror = storage.FINDINGS_FILE.read_bytes()
        with self.assertRaises(ValueError):
            storage.update_finding_status("F-1", "invalid")
        self.assertEqual(self.rows("findings"), findings)
        self.assertEqual(self.rows("evidence"), evidence)
        self.assertEqual(storage.FINDINGS_FILE.read_bytes(), mirror)


if __name__ == "__main__":
    unittest.main()

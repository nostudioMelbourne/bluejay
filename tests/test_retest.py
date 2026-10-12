import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bluejay import cmd_findings, commands, nmap


class RetestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.finding = {
            "id": "F-1",
            "target": "localhost",
            "type": "open-service",
            "status": "open",
            "metadata": {},
        }
        patches = contextlib.ExitStack()
        self.addCleanup(patches.close)
        self.load_findings = patches.enter_context(
            patch.object(cmd_findings, "load_findings", return_value=[self.finding])
        )
        self.runners = {
            name: patches.enter_context(patch.object(cmd_findings, name))
            for name in ["run_web_check", "run_nuclei_scan", "run_safe_nmap_scan"]
        }

    def run_command(self, command: str) -> str:
        output = io.StringIO()
        chat_path = Path("chats/test.jsonl")
        with contextlib.redirect_stdout(output):
            running, returned_path = commands.handle_command(command, chat_path)
        self.assertTrue(running)
        self.assertEqual(returned_path, chat_path)
        return output.getvalue()

    def routes(self):
        return [
            ("web-header", {"url": "http://localhost/page"}, "run_web_check", "http://localhost/page", {}),
            ("tls-certificate", {}, "run_web_check", "localhost", {}),
            ("nuclei-template", {"matched_at": "http://localhost/page"}, "run_nuclei_scan", "http://localhost/page", {}),
            ("nuclei-template", {}, "run_nuclei_scan", "localhost", {}),
            ("nmap-script", {}, "run_safe_nmap_scan", "localhost", {"scan_profile": "vulnerability"}),
            ("open-service", {}, "run_safe_nmap_scan", "localhost", {"scan_profile": "standard"}),
        ]

    def prepare_route(self, finding_type: str, metadata: dict, result) -> None:
        self.finding["type"] = finding_type
        self.finding["metadata"] = metadata
        for runner in self.runners.values():
            runner.reset_mock()
            runner.return_value = result

    def assert_route(self, runner_name: str, target: str, kwargs: dict) -> None:
        self.runners[runner_name].assert_called_once_with(target, **kwargs)
        for name, runner in self.runners.items():
            if name != runner_name:
                runner.assert_not_called()

    def test_failed_check_reports_incomplete_without_resolution_advice(self) -> None:
        for finding_type, metadata, runner_name, target, kwargs in self.routes():
            with self.subTest(finding_type=finding_type, metadata=metadata):
                self.prepare_route(finding_type, metadata, None)
                output = self.run_command("/retest F-1")
                self.assert_route(runner_name, target, kwargs)
                self.assertIn("Retest did not complete", output)
                self.assertNotIn("Retest complete", output)
                self.assertNotIn("Retest evidence saved", output)
                self.assertNotIn("resolve", output)
                self.assertEqual(self.finding["status"], "open")

    def test_saved_evidence_is_shown_without_automatically_resolving(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            evidence_path = Path(temporary_directory) / "retest.json"
            evidence_path.write_text('{"observation": "synthetic test evidence"}\n')
            for finding_type, metadata, runner_name, target, kwargs in self.routes():
                with self.subTest(finding_type=finding_type, metadata=metadata):
                    self.prepare_route(finding_type, metadata, evidence_path)
                    output = self.run_command("/retest F-1")
                    self.assert_route(runner_name, target, kwargs)
                    self.assertIn(f"Retest evidence saved to: {evidence_path}", output)
                    self.assertIn("evidence confirms the fix", output)
                    self.assertNotIn("Retest did not complete", output)
                    self.assertNotIn("Retest complete", output)
                    self.assertEqual(self.finding["status"], "open")

    def test_missing_or_ambiguous_finding_does_not_run_a_check(self) -> None:
        self.load_findings.return_value = [self.finding, dict(self.finding, id="F-2")]
        for command in ["/retest missing", "/retest F-"]:
            with self.subTest(command=command):
                output = self.run_command(command)
                self.assertIn("not found or ID prefix is ambiguous", output)
                for runner in self.runners.values():
                    runner.assert_not_called()

    def test_invalid_argument_count_does_not_run_a_check(self) -> None:
        for command in ["/retest", "/retest F-1 extra"]:
            with self.subTest(command=command):
                self.assertIn("Usage: /retest <id>", self.run_command(command))
                self.load_findings.assert_not_called()
                for runner in self.runners.values():
                    runner.assert_not_called()


class RetestMissingToolTests(unittest.TestCase):
    def test_missing_nmap_keeps_installation_hint_and_reports_incomplete(self) -> None:
        finding = {"id": "F-1", "target": "localhost", "type": "open-service"}
        output = io.StringIO()
        with (
            patch.object(cmd_findings, "load_findings", return_value=[finding]),
            patch.object(nmap, "normalize_target", return_value="localhost"),
            patch.object(nmap, "is_allowed_target", return_value=True),
            patch.object(nmap.subprocess, "run", side_effect=FileNotFoundError),
            contextlib.redirect_stdout(output),
        ):
            commands.handle_command("/retest F-1", Path("chats/test.jsonl"))
        self.assertIn("Nmap is not installed", output.getvalue())
        self.assertIn("Retest did not complete", output.getvalue())
        self.assertNotIn("Retest complete", output.getvalue())


if __name__ == "__main__":
    unittest.main()

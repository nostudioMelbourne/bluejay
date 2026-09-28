import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bluejay.cmd_workflows import cmd_repo
from bluejay.commands import ARG_COMMANDS
from bluejay.repository_checks import inspect_repository, run_repository_checks


class RepositoryCheckTests(unittest.TestCase):
    def test_inventory_and_local_checks_report_risky_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "requirements-dev.txt").write_text("pytest\n", encoding="utf-8")
            (root / ".env.local").write_text("SECRET=not-shown\n", encoding="utf-8")
            (root / ".env.example").write_text("SECRET=placeholder\n", encoding="utf-8")
            (root / "Dockerfile").write_text(
                "FROM python:latest\nCMD python app.py\n", encoding="utf-8"
            )
            (root / "node_modules").mkdir()
            (root / "node_modules" / "package.json").write_text("{}", encoding="utf-8")

            report = inspect_repository(root)

        self.assertIn("`requirements-dev.txt`", report)
        self.assertIn("`.env.local`", report)
        self.assertNotIn("`.env.example`", report)
        self.assertIn("latest", report)
        self.assertIn("run the application as root", report)
        self.assertNotIn("SECRET=not-shown", report)
        self.assertNotIn("node_modules/package.json", report)

    def test_report_is_saved_under_reports_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "sample-project"
            root.mkdir()
            reports = root / "reports"

            with patch("bluejay.repository_checks.REPORTS_DIR", reports):
                report_path = run_repository_checks(root)

            self.assertTrue(report_path.is_file())
            self.assertIn("Blue Jay Repository Checks", report_path.read_text(encoding="utf-8"))

    def test_repo_command_is_registered_and_blocks_external_paths(self) -> None:
        self.assertIn("/repo", ARG_COMMANDS)

        with (
            patch("bluejay.cmd_workflows.resolve_project_file", return_value=None),
            patch("bluejay.cmd_workflows.run_repository_checks") as run_checks,
        ):
            cmd_repo(["../outside"])

        run_checks.assert_not_called()


if __name__ == "__main__":
    unittest.main()
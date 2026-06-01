import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import bluejay.model as model
import bluejay.nmap as nmap
from bluejay.tooling import missing_tool_message


class MissingToolMessageTests(unittest.TestCase):
    def test_message_names_tool_and_shows_macos_and_linux_hints(self) -> None:
        for tool, display in [("nmap", "Nmap"), ("ollama", "Ollama"), ("dig", "dig")]:
            message = missing_tool_message(tool)

            self.assertIn(display, message)
            self.assertIn("not installed or not available in PATH", message)
            self.assertIn("macOS:", message)
            self.assertIn("Linux:", message)

    def test_optional_flag_marks_tool_as_optional(self) -> None:
        self.assertIn("(optional)", missing_tool_message("dig", optional=True))
        self.assertNotIn("(optional)", missing_tool_message("dig"))

    def test_unknown_tool_does_not_crash_and_names_it(self) -> None:
        message = missing_tool_message("totally-made-up")

        self.assertIn("totally-made-up", message)
        self.assertNotIn("Install it with:", message)


class MissingToolRuntimeTests(unittest.TestCase):
    def test_run_ollama_reports_missing_ollama_without_crashing(self) -> None:
        with patch.object(model.subprocess, "run", side_effect=FileNotFoundError):
            result = model.run_ollama("hello")

        # analyse_file detects failures via the "Error:" prefix, so keep it.
        self.assertTrue(result.startswith("Error:"))
        self.assertIn("Ollama", result)
        self.assertIn("macOS:", result)
        self.assertIn("Linux:", result)

    def test_run_safe_nmap_scan_reports_missing_nmap_without_crashing(self) -> None:
        buffer = io.StringIO()

        with patch.object(nmap.subprocess, "run", side_effect=FileNotFoundError):
            with contextlib.redirect_stdout(buffer):
                result = nmap.run_safe_nmap_scan("127.0.0.1")

        output = buffer.getvalue()
        self.assertIsNone(result)
        self.assertIn("Nmap is not installed", output)
        self.assertIn("macOS:", output)
        self.assertIn("Linux:", output)

    def test_run_dig_lookup_reports_missing_optional_dig_and_falls_back(self) -> None:
        buffer = io.StringIO()

        with tempfile.TemporaryDirectory() as temporary_directory:
            with (
                patch.object(nmap, "LOGS_DIR", Path(temporary_directory)),
                patch.object(nmap.shutil, "which", return_value=None),
                patch.object(nmap.socket, "getaddrinfo", return_value=[(None, None, None, None, ("127.0.0.1", 0))]),
                patch.object(nmap, "upsert_asset"),
                patch.object(nmap, "record_scan"),
                contextlib.redirect_stdout(buffer),
            ):
                result = nmap.run_dig_lookup("example.com")

        output = buffer.getvalue()
        self.assertIsNotNone(result)
        self.assertIn("dig is not installed", output)
        self.assertIn("(optional)", output)
        self.assertIn("Using the local DNS resolver instead.", output)
        self.assertIn("macOS:", output)
        self.assertIn("Linux:", output)


if __name__ == "__main__":
    unittest.main()

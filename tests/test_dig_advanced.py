import contextlib
import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import bluejay.cmd_workflows as workflows
import bluejay.nmap as nmap


class AdvancedDigTests(unittest.TestCase):
    def test_command_keeps_basic_mode_and_analyses_advanced_results(self) -> None:
        saved_path = Path("logs/dns-example.com-advanced.txt")
        with (
            patch.object(workflows, "run_dig_lookup", return_value=saved_path) as lookup,
            patch.object(workflows, "analyse_file") as analyse,
        ):
            workflows.cmd_dig(["example.com"])
            lookup.assert_called_with("example.com")
            workflows.cmd_dig(["example.com", "advanced"])
            lookup.assert_called_with("example.com", mode="advanced")
            workflows.cmd_dig(["example.com", "all"])
            lookup.assert_called_with("example.com", mode="all")
            self.assertEqual(analyse.call_count, 3)
            analyse.assert_called_with(saved_path, "dns")

    def test_command_rejects_unsupported_mode(self) -> None:
        with patch.object(workflows, "run_dig_lookup") as lookup:
            with contextlib.redirect_stdout(io.StringIO()):
                workflows.cmd_dig(["example.com", "extra"])
            lookup.assert_not_called()

    def test_basic_lookup_preserves_six_original_queries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(nmap, "LOGS_DIR", Path(directory)),
                patch.object(nmap.shutil, "which", return_value="/usr/bin/dig"),
                patch.object(nmap.subprocess, "run", return_value=SimpleNamespace(stdout="", stderr="")) as run,
                patch.object(nmap, "upsert_asset"),
                patch.object(nmap, "record_scan"),
            ):
                result = nmap.run_dig_lookup("example.com")
                content = result.read_text(encoding="utf-8")

        self.assertIn("dns-example.com-", result.name)
        self.assertNotIn("advanced", result.name)
        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [
                ["dig", "+nocmd", "example.com", record_type, "+noall", "+answer"]
                for record_type in ["A", "AAAA", "MX", "NS", "TXT", "CAA"]
            ],
        )
        self.assertNotIn("## SPF hints", content)

    def test_advanced_lookup_collects_extra_records_spf_and_ptr(self) -> None:
        def dig_result(command: list[str], **_: object) -> SimpleNamespace:
            if command[2:4] == ["example.com", "A"]:
                return SimpleNamespace(stdout="example.com. 300 IN A 192.0.2.10\n", stderr="")
            if command[2:4] == ["example.com", "TXT"]:
                return SimpleNamespace(stdout='example.com. 300 IN TXT "v=spf1 -all"\n', stderr="")
            if command[2:4] == ["example.com", "DS"]:
                raise subprocess.TimeoutExpired(command, 20)
            return SimpleNamespace(stdout="", stderr="")

        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(nmap, "LOGS_DIR", Path(directory)),
                patch.object(nmap.shutil, "which", return_value="/usr/bin/dig"),
                patch.object(nmap.subprocess, "run", side_effect=dig_result) as run,
                patch.object(nmap, "upsert_asset"),
                patch.object(nmap, "record_scan") as record_scan,
            ):
                result = nmap.run_dig_lookup("example.com", mode="advanced")
                content = result.read_text(encoding="utf-8")

        commands = [call.args[0] for call in run.call_args_list]
        self.assertIn(["dig", "+nocmd", "example.com", "SOA", "+noall", "+answer"], commands)
        self.assertIn(["dig", "+nocmd", "example.com", "DNSKEY", "+noall", "+answer"], commands)
        self.assertIn(["dig", "+nocmd", "example.com", "DS", "+noall", "+answer"], commands)
        self.assertIn(["dig", "+nocmd", "_sip._tcp.example.com", "SRV", "+noall", "+answer"], commands)
        self.assertIn(["dig", "+nocmd", "_dmarc.example.com", "TXT", "+noall", "+answer"], commands)
        self.assertIn(["dig", "+nocmd", "selector1._domainkey.example.com", "TXT", "+noall", "+answer"], commands)
        self.assertIn(["dig", "+nocmd", "selector1._domainkey.example.com", "CNAME", "+noall", "+answer"], commands)
        self.assertIn(["dig", "+nocmd", "-x", "192.0.2.10", "+noall", "+answer"], commands)
        self.assertIn("## SPF hints", content)
        self.assertIn("v=spf1 -all", content)
        self.assertIn("## PTR 192.0.2.10", content)
        self.assertIn("## DS\ndig timed out.", content)
        self.assertIn("advanced", result.name)
        self.assertIn("advanced", record_scan.call_args.args[4][-1])

    def test_advanced_lookup_falls_back_when_dig_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(nmap, "LOGS_DIR", Path(directory)),
                patch.object(nmap.shutil, "which", return_value=None),
                patch.object(nmap.socket, "getaddrinfo", return_value=[(None, None, None, None, ("192.0.2.10", 0))]),
                patch.object(nmap.subprocess, "run") as run,
                patch.object(nmap, "upsert_asset"),
                patch.object(nmap, "record_scan") as record_scan,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                result = nmap.run_dig_lookup("example.com", mode="all")
                content = result.read_text(encoding="utf-8")

        run.assert_not_called()
        self.assertIn("## Resolver Addresses\n192.0.2.10", content)
        self.assertIn("Advanced DNS records require dig", content)
        self.assertEqual(record_scan.call_args.args[2], "resolver")


if __name__ == "__main__":
    unittest.main()

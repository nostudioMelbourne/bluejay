import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from bluejay.cmd_workflows import parse_scan_options
from bluejay.nmap import (
    NmapScanOptions,
    build_nmap_command,
    effective_scan_options,
    normalize_timing,
    validate_ports,
)


class NmapOptionTests(unittest.TestCase):
    def test_validate_ports_accepts_single_ports_lists_and_ranges(self) -> None:
        for port_spec in ["22", "22,80,443", "1-1024", "22,1000-1010"]:
            self.assertTrue(validate_ports(port_spec))

    def test_validate_ports_rejects_invalid_specs(self) -> None:
        for port_spec in ["", "0", "65536", "22,", "100-99", "abc", "22;80"]:
            self.assertFalse(validate_ports(port_spec))

    def test_normalize_timing_accepts_aliases_and_numbers(self) -> None:
        self.assertEqual(normalize_timing("polite"), "2")
        self.assertEqual(normalize_timing("3"), "3")
        self.assertIsNone(normalize_timing("fastest"))

    def test_effective_scan_options_does_not_mutate_input(self) -> None:
        options = NmapScanOptions(top_ports=10, service_detection=False)
        effective = effective_scan_options("standard", options)

        self.assertEqual(options.top_ports, 10)
        self.assertIsNone(options.timing)
        self.assertEqual(effective.top_ports, 10)
        self.assertEqual(effective.timing, "3")

    def test_effective_scan_options_clears_version_intensity_without_service_detection(self) -> None:
        options = NmapScanOptions(service_detection=False, version_intensity=9)
        effective = effective_scan_options("standard", options)

        self.assertFalse(effective.service_detection)
        self.assertIsNone(effective.version_intensity)

    def test_parse_scan_options_accepts_nmap_style_service_and_timing(self) -> None:
        parsed = parse_scan_options(["localhost", "-sV", "-T0", "version-intensity", "7"])

        self.assertIsNotNone(parsed)
        target, scan_profile, options = parsed
        self.assertEqual(target, "localhost")
        self.assertEqual(scan_profile, "standard")
        self.assertTrue(options.service_detection)
        self.assertEqual(options.timing, "0")
        self.assertEqual(options.version_intensity, 7)

    def test_parse_scan_options_accepts_decoy_aliases_with_other_options(self) -> None:
        for option in ("decoy", "-D"):
            parsed = parse_scan_options(
                ["127.0.0.1", "-sV", "-T0", option, "192.168.56.20,ME"]
            )

            self.assertIsNotNone(parsed)
            _, _, options = parsed
            self.assertEqual(options.decoys, "192.168.56.20,ME")

    def test_parse_scan_options_rejects_invalid_decoy_lists(self) -> None:
        for decoys in ["", "ME", "localhost,,ME", "localhost,ME;id", "localhost,ME/path"]:
            self.assertIsNone(parse_scan_options(["127.0.0.1", "decoy", decoys]))
        self.assertIsNone(parse_scan_options(["127.0.0.1", "-D"]))

    def test_build_nmap_command_includes_decoys_in_command_description_and_metadata(self) -> None:
        command, description, metadata = build_nmap_command(
            "127.0.0.1",
            "standard",
            Path("scan.txt"),
            Path("scan.xml"),
            NmapScanOptions(decoys="192.168.56.20,ME"),
        )

        self.assertEqual(command[command.index("-D") + 1], "192.168.56.20,ME")
        self.assertIn("decoys enabled", description)
        self.assertIn("version-detection traffic is not cloaked", description)
        self.assertEqual(metadata["decoys"], "192.168.56.20,ME")

    def test_safe_scan_rejects_non_allowlisted_decoy_before_running_nmap(self) -> None:
        import bluejay.nmap as nmap

        with (
            patch.object(nmap, "is_allowed_target", side_effect=lambda host: host == "127.0.0.1"),
            patch.object(nmap.subprocess, "run") as run,
        ):
            result = nmap.run_safe_nmap_scan(
                "127.0.0.1",
                options=NmapScanOptions(decoys="example.com,ME"),
            )

        self.assertIsNone(result)
        run.assert_not_called()

    def test_safe_scan_records_authorized_decoys_in_metadata(self) -> None:
        import bluejay.nmap as nmap

        options = NmapScanOptions(decoys="192.168.56.20,ME")
        with TemporaryDirectory() as temporary_directory:
            with (
                patch.object(nmap, "SCANS_DIR", Path(temporary_directory)),
                patch.object(
                    nmap.subprocess,
                    "run",
                    return_value=Mock(returncode=0, stderr=""),
                ) as run,
                patch.object(nmap, "record_scan") as record_scan,
                patch.object(nmap, "record_findings"),
            ):
                result = nmap.run_safe_nmap_scan("127.0.0.1", options=options)

        self.assertIsNotNone(result)
        command = run.call_args.args[0]
        self.assertEqual(command[command.index("-D") + 1], "192.168.56.20,ME")
        self.assertEqual(record_scan.call_args.args[7]["decoys"], "192.168.56.20,ME")
        self.assertEqual(options.decoys, "192.168.56.20,ME")

    def test_build_nmap_command_for_udp_ipv6_scan(self) -> None:
        command, description, metadata = build_nmap_command(
            "::1",
            "quick",
            Path("scan.txt"),
            Path("scan.xml"),
            NmapScanOptions(protocol="udp", ports="53", reason=True),
        )

        self.assertIn("-6", command)
        self.assertIn("-sU", command)
        self.assertIn("--reason", command)
        self.assertIn("::1", command)
        self.assertIn("UDP", description)
        self.assertEqual(metadata["ports"], "53")

    def test_build_nmap_command_adds_version_intensity_with_service_detection(self) -> None:
        command, description, metadata = build_nmap_command(
            "localhost",
            "standard",
            Path("scan.txt"),
            Path("scan.xml"),
            NmapScanOptions(version_intensity=7),
        )

        self.assertIn("-sV", command)
        self.assertIn("--version-intensity", command)
        self.assertIn("7", command)
        self.assertIn("version intensity 7", description)
        self.assertEqual(metadata["version_intensity"], 7)


if __name__ == "__main__":
    unittest.main()

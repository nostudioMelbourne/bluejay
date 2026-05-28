import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()

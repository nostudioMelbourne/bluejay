import re
from pathlib import Path

from .analysis import analyse_file
from .constants import SCAN_PROFILES
from .nmap import NmapScanOptions, normalize_timing, run_dig_lookup, run_safe_nmap_scan, validate_ports
from .reports import generate_findings_report
from .targets import normalize_target
from .web import run_nuclei_scan, run_site_audit, run_web_check


def cmd_analyse(args: list[str]) -> None:
    if len(args) != 2:
        print("Usage: /analyse <file> <mode>")
        print("Example: /analyse scans/example-nmap.txt nmap")
        return

    file_path = Path(args[0])
    mode = args[1]

    analyse_file(file_path, mode)


def cmd_dig(args: list[str]) -> None:
    if len(args) != 1:
        print("Usage: /dig <domain>")
        print("Example: /dig example.com")
        return

    dns_path = run_dig_lookup(args[0])

    if dns_path is None:
        return

    analyse_file(dns_path, "dns")


def cmd_web(args: list[str]) -> None:
    if len(args) != 1:
        print("Usage: /web <host-or-url>")
        print("Example: /web localhost")
        print("Example: /web https://example.com/")
        return

    web_path = run_web_check(args[0])

    if web_path is None:
        return

    analyse_file(web_path, "web-check")


def cmd_site(args: list[str]) -> None:
    if len(args) != 1:
        print("Usage: /site <host-or-url>")
        print("Example: /site http://localhost:3000/")
        print("Example: /site http://127.0.0.1:8080/")
        return

    site_path = run_site_audit(args[0])

    if site_path is None:
        return

    analyse_file(site_path, "web-check")


def cmd_nuclei(args: list[str]) -> None:
    if len(args) not in {1, 2}:
        print("Usage: /nuclei <host-or-url> [severity-list]")
        print("Example: /nuclei localhost info,low,medium")
        return

    severity = args[1] if len(args) == 2 else "info,low,medium,high,critical"
    if not re.match(r"^(info|low|medium|high|critical)(,(info|low|medium|high|critical))*$", severity):
        print("Severity list must contain only: info,low,medium,high,critical")
        return

    nuclei_path = run_nuclei_scan(args[0], severity)

    if nuclei_path is None:
        return

    analyse_file(nuclei_path, "vulnerability")


def run_profile(profile: str, target: str) -> None:
    steps = SCAN_PROFILES.get(profile)

    if steps is None:
        print(f"Unknown profile: {profile}")
        print("Available profiles:", ", ".join(sorted(SCAN_PROFILES)))
        return

    print(f"Running profile '{profile}' against {target}.")

    for step in steps:
        if step == "dns":
            run_dig_lookup(target)
        elif step == "quiet-scan":
            run_safe_nmap_scan(target, scan_profile="quiet")
        elif step == "scan":
            run_safe_nmap_scan(target, scan_profile="quick" if profile == "quick" else "standard")
        elif step == "vuln":
            run_safe_nmap_scan(target, scan_profile="vulnerability")
        elif step == "web":
            run_web_check(target)
        elif step == "report":
            generate_findings_report(target if target != "all" else None, "technical")

    print("Profile complete.")


def cmd_profile(args: list[str]) -> None:
    if len(args) != 2:
        print("Usage: /profile <quiet|quick|standard|deep|web|report> <target|all>")
        return

    profile = args[0]
    target = args[1]

    if profile != "report" and normalize_target(target) is None:
        print("Profile target must be a plain hostname or IP address.")
        return

    run_profile(profile, target)


def print_scan_usage() -> None:
    print("Usage: /scan <target> [quiet|quick|standard|deep] [options]")
    print("Options:")
    print("  udp                  Use UDP scan mode")
    print("  tcp                  Use TCP scan mode (default)")
    print("  ports <list>         Scan explicit ports, for example 22,80,443 or 1-1024")
    print("  top <count>          Scan top N ports, from 1 to 5000")
    print("  service, -sV         Enable service/version detection")
    print("  no-service           Disable service/version detection")
    print("  version-intensity <0-9>")
    print("                       Tune Nmap service/version probes")
    print("  version-light        Shortcut for version-intensity 2")
    print("  version-all          Shortcut for version-intensity 9")
    print("  reason               Include Nmap reason output")
    print("  timing <0-4|name>, -T0..-T4")
    print("                       paranoid, sneaky, polite, normal, or aggressive")
    print("Examples:")
    print("  /scan localhost quiet")
    print("  /scan localhost -sV version-intensity 7")
    print("  /scan localhost ports 22,80,443 reason")
    print("  /scan 192.168.1.1 top 1000 no-service timing polite")
    print("  /scan 192.168.1.1 quick udp top 50")


def parse_scan_options(args: list[str]) -> tuple[str, str, NmapScanOptions] | None:
    if not args:
        print_scan_usage()
        return None

    target = args[0]
    scan_profile = "standard"
    options = NmapScanOptions()
    index = 1
    profiles = {"quiet", "quick", "standard", "deep"}

    if index < len(args) and args[index].lower() in profiles:
        scan_profile = args[index].lower()
        index += 1

    while index < len(args):
        token = args[index].lower()

        if token == "udp":
            options.protocol = "udp"
            index += 1
        elif token == "tcp":
            options.protocol = "tcp"
            index += 1
        elif token in {"service", "-sv", "--service-version"}:
            options.service_detection = True
            index += 1
        elif token in {"no-service", "--no-service"}:
            options.service_detection = False
            index += 1
        elif token in {"version-light", "--version-light"}:
            options.service_detection = True
            options.version_intensity = 2
            index += 1
        elif token in {"version-all", "--version-all"}:
            options.service_detection = True
            options.version_intensity = 9
            index += 1
        elif token in {"version-intensity", "--version-intensity"}:
            if index + 1 >= len(args):
                print("Missing value after 'version-intensity'.")
                return None

            intensity_value = args[index + 1]
            if not intensity_value.isdigit() or not 0 <= int(intensity_value) <= 9:
                print("Version intensity must be a number from 0 to 9.")
                return None

            options.service_detection = True
            options.version_intensity = int(intensity_value)
            index += 2
        elif token.startswith("version-intensity=") or token.startswith("--version-intensity="):
            intensity_value = token.split("=", 1)[1]
            if not intensity_value.isdigit() or not 0 <= int(intensity_value) <= 9:
                print("Version intensity must be a number from 0 to 9.")
                return None

            options.service_detection = True
            options.version_intensity = int(intensity_value)
            index += 1
        elif token == "reason":
            options.reason = True
            index += 1
        elif token == "ports":
            if index + 1 >= len(args):
                print("Missing port list after 'ports'.")
                return None

            port_spec = args[index + 1]
            if not validate_ports(port_spec):
                print("Ports must be 1-65535, comma-separated, or ranges such as 22,80,443 or 1-1024.")
                return None

            options.ports = port_spec
            options.top_ports = None
            index += 2
        elif token.startswith("ports="):
            port_spec = token.split("=", 1)[1]
            if not validate_ports(port_spec):
                print("Ports must be 1-65535, comma-separated, or ranges such as 22,80,443 or 1-1024.")
                return None

            options.ports = port_spec
            options.top_ports = None
            index += 1
        elif token == "top":
            if index + 1 >= len(args):
                print("Missing count after 'top'.")
                return None

            top_value = args[index + 1]
            if not top_value.isdigit() or not 1 <= int(top_value) <= 5000:
                print("Top port count must be a number from 1 to 5000.")
                return None

            options.top_ports = int(top_value)
            options.ports = None
            index += 2
        elif token.startswith("top="):
            top_value = token.split("=", 1)[1]
            if not top_value.isdigit() or not 1 <= int(top_value) <= 5000:
                print("Top port count must be a number from 1 to 5000.")
                return None

            options.top_ports = int(top_value)
            options.ports = None
            index += 1
        elif token in {"timing", "--timing", "-t"}:
            if index + 1 >= len(args):
                print("Missing value after 'timing'.")
                return None

            timing = normalize_timing(args[index + 1])
            if timing is None:
                print("Timing must be 0-4, paranoid, sneaky, polite, normal, or aggressive.")
                return None

            options.timing = timing
            index += 2
        elif len(token) == 3 and token.startswith("-t"):
            timing = normalize_timing(token[2:])
            if timing is None:
                print("Timing must be 0-4, paranoid, sneaky, polite, normal, or aggressive.")
                return None

            options.timing = timing
            index += 1
        elif token.startswith("timing="):
            timing = normalize_timing(token.split("=", 1)[1])
            if timing is None:
                print("Timing must be 0-4, paranoid, sneaky, polite, normal, or aggressive.")
                return None

            options.timing = timing
            index += 1
        else:
            print(f"Unknown scan option: {args[index]}")
            print_scan_usage()
            return None

    return target, scan_profile, options


def cmd_scan(args: list[str]) -> None:
    parsed = parse_scan_options(args)

    if parsed is None:
        return

    target, scan_profile, options = parsed

    if scan_profile == "deep":
        print("Deep scans can be noisy. Use this only on systems you own or have permission to test.")

    scan_path = run_safe_nmap_scan(target, scan_profile=scan_profile, options=options)

    if scan_path is None:
        return

    analyse_file(scan_path, "vulnerability" if scan_profile == "deep" else "nmap")


def cmd_vuln(args: list[str]) -> None:
    if len(args) != 1:
        print("Usage: /vuln <target>")
        print("Example: /vuln localhost")
        print("Example: /vuln scanme.nmap.org")
        return

    print("Vulnerability scans can be noisy. Use this only on systems you own or have permission to test.")
    scan_path = run_safe_nmap_scan(args[0], scan_profile="vulnerability")

    if scan_path is None:
        return

    analyse_file(scan_path, "vulnerability")

import re
from pathlib import Path

from .analysis import analyse_file
from .constants import SCAN_PROFILES
from .dns import run_dig_lookup
from .nmap import run_safe_nmap_scan
from .reports import generate_findings_report
from .repository_checks import run_repository_checks
from .scan_options import parse_scan_options as parse_scan_options
from .scan_options import print_scan_usage as print_scan_usage
from .targets import normalize_decoy_list, normalize_target
from .utils import resolve_project_file
from .web import run_nuclei_scan, run_site_audit, run_web_check


def cmd_analyse(args: list[str]) -> None:
    if len(args) != 2:
        print("Usage: /analyse <file> <mode>")
        print("Example: /analyse scans/example-nmap.txt nmap")
        return

    file_path = Path(args[0])
    mode = args[1]

    analyse_file(file_path, mode)


def cmd_repo(args: list[str]) -> None:
    if len(args) != 1:
        print("Usage: /repo <directory>")
        print("Example: /repo .")
        return

    root = resolve_project_file(Path(args[0]))
    if root is None:
        print("Repository path blocked. Checks are limited to directories inside this project folder.")
        return
    if not root.exists() or not root.is_dir():
        print(f"Repository directory not found: {args[0]}")
        return

    run_repository_checks(root)


def cmd_dig(args: list[str]) -> None:
    if len(args) not in {1, 2} or (len(args) == 2 and args[1].lower() not in {"advanced", "all"}):
        print("Usage: /dig <domain> [advanced|all]")
        print("Example: /dig example.com")
        print("Example: /dig example.com advanced")
        return

    if len(args) == 2:
        dns_path = run_dig_lookup(args[0], mode=args[1].lower())
    else:
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

import re
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .constants import DIG_TIMEOUT_SECONDS, LOGS_DIR, NMAP_TIMEOUT_SECONDS, SCANS_DIR
from .storage import extract_cves, make_finding, record_findings, record_scan, upsert_asset
from .targets import is_allowed_target, is_valid_hostname, normalize_target
from .utils import slugify


@dataclass
class NmapScanOptions:
    protocol: str = "tcp"
    ports: str | None = None
    top_ports: int | None = None
    service_detection: bool | None = None
    version_intensity: int | None = None
    reason: bool = False
    timing: str | None = None


TIMING_ALIASES = {
    "paranoid": "0",
    "sneaky": "1",
    "polite": "2",
    "normal": "3",
    "aggressive": "4",
}


def validate_ports(port_spec: str) -> bool:
    if not port_spec or not re.match(r"^[0-9,-]+$", port_spec):
        return False

    for part in port_spec.split(","):
        if not part:
            return False

        if "-" in part:
            bounds = part.split("-")

            if len(bounds) != 2 or not bounds[0] or not bounds[1]:
                return False

            start, end = int(bounds[0]), int(bounds[1])
            if start > end or start < 1 or end > 65535:
                return False
        else:
            port = int(part)
            if port < 1 or port > 65535:
                return False

    return True


def normalize_timing(value: str) -> str | None:
    clean_value = value.lower().strip()
    timing = TIMING_ALIASES.get(clean_value, clean_value)
    return timing if timing in {"0", "1", "2", "3", "4"} else None


def classify_service(service_name: str, port_id: str) -> tuple[str, str]:
    service = service_name.lower()
    high_risk = {
        "ms-wbt-server",
        "rdp",
        "redis",
        "mongodb",
        "mysql",
        "postgresql",
        "ms-sql-s",
        "elasticsearch",
        "memcached",
        "vnc",
    }
    medium_risk = {
        "ftp",
        "telnet",
        "smtp",
        "pop3",
        "imap",
        "nfs",
        "netbios-ssn",
        "microsoft-ds",
        "smb",
        "ldap",
        "http",
    }

    if service in high_risk:
        return "High", "Review exposure carefully. Restrict access, require authentication, patch, and avoid public exposure."

    if service in medium_risk:
        return "Medium", "Confirm this service must be reachable. Patch it, restrict access, and review configuration."

    if port_id in {"22", "443"}:
        return "Low", "Confirm the service is expected, patched, and monitored."

    return "Info", "Confirm this open service is expected and document the business reason."


def service_fingerprint(service_element: ET.Element | None) -> str:
    if service_element is None:
        return "unknown"

    fields = [
        service_element.get("name", ""),
        service_element.get("product", ""),
        service_element.get("version", ""),
        service_element.get("extrainfo", ""),
    ]

    return " ".join(field for field in fields if field).strip() or "unknown"


def parse_nmap_xml(xml_path: Path, scan_profile: str) -> list[dict]:
    findings = []

    if not xml_path.exists():
        return findings

    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError:
        return findings

    for host in root.findall("host"):
        status = host.find("status")

        if status is not None and status.get("state") != "up":
            continue

        address_element = host.find("address")
        target = address_element.get("addr", "unknown") if address_element is not None else "unknown"

        hostnames = [
            hostname.get("name")
            for hostname in host.findall("./hostnames/hostname")
            if hostname.get("name")
        ]

        if hostnames:
            target = hostnames[0]

        for port in host.findall("./ports/port"):
            state = port.find("state")

            if state is None or state.get("state") != "open":
                continue

            port_id = port.get("portid", "unknown")
            protocol = port.get("protocol", "tcp")
            service_element = port.find("service")
            service_name = (
                service_element.get("name", "unknown")
                if service_element is not None
                else "unknown"
            )
            fingerprint = service_fingerprint(service_element)
            severity, recommendation = classify_service(service_name, port_id)
            evidence = f"{port_id}/{protocol} open: {fingerprint}"

            findings.append(
                make_finding(
                    target=target,
                    title=f"Open service: {port_id}/{protocol} {service_name}",
                    severity=severity,
                    finding_type="open-service",
                    evidence=evidence,
                    source=str(xml_path),
                    recommendation=recommendation,
                    confidence="High",
                    metadata={
                        "port": port_id,
                        "protocol": protocol,
                        "service": service_name,
                        "scan_profile": scan_profile,
                    },
                )
            )

            for script in port.findall("script"):
                script_id = script.get("id", "unknown-script")
                output = script.get("output", "").strip()

                if not output:
                    continue

                cves = extract_cves(output)
                lowered = output.lower()
                vulnerable = "vulnerable" in lowered and "not vulnerable" not in lowered

                if not cves and not vulnerable:
                    continue

                script_severity = "High" if cves or vulnerable else "Medium"
                findings.append(
                    make_finding(
                        target=target,
                        title=f"Nmap script finding on {port_id}/{protocol}: {script_id}",
                        severity=script_severity,
                        finding_type="nmap-script",
                        evidence=output[:2000],
                        source=str(xml_path),
                        recommendation=(
                            "Verify the finding manually, identify the affected software version, "
                            "patch or mitigate, and document the validation evidence."
                        ),
                        confidence="Medium",
                        cves=cves,
                        metadata={
                            "port": port_id,
                            "protocol": protocol,
                            "service": service_name,
                            "script_id": script_id,
                            "scan_profile": scan_profile,
                        },
                    )
                )

    return findings


def effective_scan_options(scan_profile: str, options: NmapScanOptions | None = None) -> NmapScanOptions:
    if options is None:
        result = NmapScanOptions()
    else:
        result = NmapScanOptions(
            protocol=options.protocol,
            ports=options.ports,
            top_ports=options.top_ports,
            service_detection=options.service_detection,
            version_intensity=options.version_intensity,
            reason=options.reason,
            timing=options.timing,
        )

    if result.version_intensity is not None and result.service_detection is not False:
        result.service_detection = True

    if result.top_ports is None and result.ports is None:
        if scan_profile == "quiet":
            result.top_ports = 25
        elif scan_profile in {"vulnerability", "deep"}:
            result.top_ports = 50
        elif scan_profile == "quick":
            result.top_ports = 25
        else:
            result.top_ports = 100

    if result.service_detection is None:
        result.service_detection = scan_profile != "quiet"

    if not result.service_detection:
        result.version_intensity = None

    if result.timing is None:
        result.timing = "2" if scan_profile == "quiet" else "3"

    return result


def build_nmap_command(
    clean_target: str,
    scan_profile: str,
    output_path: Path,
    xml_output_path: Path,
    options: NmapScanOptions | None = None,
) -> tuple[list[str], str, dict]:
    effective_options = effective_scan_options(scan_profile, options)
    command = ["nmap"]

    if ":" in clean_target:
        command.append("-6")

    if effective_options.protocol == "udp":
        command.append("-sU")

    if effective_options.service_detection:
        command.append("-sV")
        if effective_options.version_intensity is not None:
            command.extend(["--version-intensity", str(effective_options.version_intensity)])

    command.append(f"-T{effective_options.timing}")

    if effective_options.reason:
        command.append("--reason")

    if effective_options.ports:
        command.extend(["-p", effective_options.ports])
    elif effective_options.top_ports:
        command.extend(["--top-ports", str(effective_options.top_ports)])

    if scan_profile == "quiet":
        command.extend(["--max-retries", "2", "--scan-delay", "200ms", "--host-timeout", "120s"])
    elif scan_profile == "quick":
        command.extend(["--host-timeout", "60s"])
    elif scan_profile in {"vulnerability", "deep"}:
        command.extend(["--script", "vuln", "--script-timeout", "30s", "--host-timeout", "120s"])
    else:
        command.extend(["--host-timeout", "120s"])

    command.extend(["-oN", str(output_path), "-oX", str(xml_output_path), clean_target])

    protocol_label = "UDP" if effective_options.protocol == "udp" else "TCP"
    port_label = f"ports {effective_options.ports}" if effective_options.ports else f"top {effective_options.top_ports} ports"
    if effective_options.service_detection and effective_options.version_intensity is not None:
        service_label = f"with service detection, version intensity {effective_options.version_intensity}"
    else:
        service_label = "with service detection" if effective_options.service_detection else "without service detection"
    reason_label = ", reason output enabled" if effective_options.reason else ""

    if scan_profile == "quiet":
        description = f"low-noise {protocol_label} scan, {port_label}, {service_label}{reason_label}"
    elif scan_profile in {"vulnerability", "deep"}:
        description = f"{protocol_label} vulnerability-script scan, {port_label}, {service_label}{reason_label}"
    else:
        description = f"{scan_profile} {protocol_label} scan, {port_label}, {service_label}{reason_label}"

    metadata = {
        "protocol": effective_options.protocol,
        "ports": effective_options.ports or "",
        "top_ports": effective_options.top_ports,
        "service_detection": effective_options.service_detection,
        "version_intensity": effective_options.version_intensity,
        "reason": effective_options.reason,
        "timing": effective_options.timing,
    }
    return command, description, metadata


def run_safe_nmap_scan(
    target: str,
    scan_profile: str = "standard",
    options: NmapScanOptions | None = None,
) -> Path | None:
    """
    Run a controlled Nmap scan.

    It allows:
    - localhost
    - private LAN IPs
    - targets explicitly listed in allowed_targets.txt
    """

    clean_target = normalize_target(target)

    if clean_target is None:
        print("Target blocked.")
        print("Use a plain hostname or IP address, without schemes, paths, ports, or shell syntax.")
        return None

    if not is_allowed_target(clean_target):
        print("Target blocked.")
        print("Blue Jay only scans localhost, private LAN IPs, or targets listed in allowed_targets.txt.")
        print("Add authorised targets to allowed_targets.txt, one per line.")
        print("Example allowed target: scanme.nmap.org")
        return None

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_target = slugify(clean_target)
    output_path = SCANS_DIR / f"nmap-{scan_profile}-{safe_target}-{timestamp}.txt"
    xml_output_path = SCANS_DIR / f"nmap-{scan_profile}-{safe_target}-{timestamp}.xml"

    command, description, scan_metadata = build_nmap_command(
        clean_target,
        scan_profile,
        output_path,
        xml_output_path,
        options,
    )

    print(f"\nRunning safe Nmap scan against: {clean_target}")
    print(f"Scan type: {description}")
    print("Command:", " ".join(command))
    print()

    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=NMAP_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        print("Error: Nmap is not installed or not available in PATH.")
        print("Install it with:")
        print("  brew install nmap")
        return None
    except subprocess.TimeoutExpired:
        print("Nmap timed out before the scan completed.")
        record_scan(clean_target, scan_profile, "nmap", "timeout", command, output_path, xml_output_path, scan_metadata)
        return None

    if result.returncode != 0:
        print("Nmap returned an error:")
        print(result.stderr.strip())
        record_scan(
            clean_target,
            scan_profile,
            "nmap",
            "failed",
            command,
            output_path,
            xml_output_path,
            {**scan_metadata, "stderr": result.stderr.strip()},
        )
        return None

    record_scan(clean_target, scan_profile, "nmap", "completed", command, output_path, xml_output_path, scan_metadata)
    print(f"Scan saved to: {output_path}")
    print(f"Structured scan saved to: {xml_output_path}")
    record_findings(parse_nmap_xml(xml_output_path, scan_profile), str(xml_output_path))
    return output_path


def run_dig_lookup(target: str) -> Path | None:
    clean_target = normalize_target(target)

    if clean_target is None or not is_valid_hostname(clean_target):
        print("DNS lookup needs a plain hostname, for example example.com.")
        return None

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_path = LOGS_DIR / f"dns-{slugify(clean_target)}-{timestamp}.txt"
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CAA"]
    sections = [f"# DNS lookup for {clean_target}", f"# Created {timestamp}", ""]

    if shutil.which("dig"):
        for record_type in record_types:
            command = ["dig", "+nocmd", clean_target, record_type, "+noall", "+answer"]
            try:
                result = subprocess.run(
                    command,
                    text=True,
                    capture_output=True,
                    timeout=DIG_TIMEOUT_SECONDS,
                )
            except subprocess.TimeoutExpired:
                sections.extend([f"## {record_type}", "dig timed out.", ""])
                continue

            sections.append(f"## {record_type}")
            sections.append(result.stdout.strip() or "No answer records returned.")
            if result.stderr.strip():
                sections.append(f"stderr: {result.stderr.strip()}")
            sections.append("")
    else:
        sections.append("dig was not found in PATH. Falling back to local resolver output.")
        sections.append("")
        try:
            addresses = sorted(
                {
                    result[4][0]
                    for result in socket.getaddrinfo(clean_target, None)
                }
            )
        except socket.gaierror as error:
            sections.append(f"Resolver error: {error}")
        else:
            sections.append("## Resolver Addresses")
            sections.extend(addresses or ["No addresses returned."])

    output_path.write_text("\n".join(sections), encoding="utf-8")
    upsert_asset(clean_target, asset_type="domain")
    record_scan(
        clean_target,
        "dns",
        "dig" if shutil.which("dig") else "resolver",
        "completed",
        ["dig", clean_target, ",".join(record_types)],
        output_path,
        "",
    )
    print(f"DNS lookup saved to: {output_path}")
    return output_path

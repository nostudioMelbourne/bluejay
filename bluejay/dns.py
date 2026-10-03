"""DNS evidence collection for basic and advanced lookup modes."""

import shutil
import socket
import subprocess
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path

from .constants import DIG_TIMEOUT_SECONDS, LOGS_DIR
from .storage import record_scan, upsert_asset
from .targets import is_valid_hostname, normalize_target
from .tooling import missing_tool_message
from .utils import slugify


_BASIC_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CAA")
_ADVANCED_QUERY_SPECS = (
    ("SOA", "{target}", "SOA"),
    ("DNSKEY", "{target}", "DNSKEY"),
    ("DS", "{target}", "DS"),
    ("SRV _sip._tcp", "_sip._tcp.{target}", "SRV"),
    ("SRV _submission._tcp", "_submission._tcp.{target}", "SRV"),
    ("DMARC", "_dmarc.{target}", "TXT"),
    ("DKIM _domainkey", "_domainkey.{target}", "TXT"),
    ("DKIM default selector", "default._domainkey.{target}", "TXT"),
    ("DKIM selector1 TXT", "selector1._domainkey.{target}", "TXT"),
    ("DKIM selector1 CNAME", "selector1._domainkey.{target}", "CNAME"),
    ("DKIM selector2 TXT", "selector2._domainkey.{target}", "TXT"),
    ("DKIM selector2 CNAME", "selector2._domainkey.{target}", "CNAME"),
)


def _build_dns_queries(target: str, advanced: bool = False) -> list[tuple[str, str, str]]:
    queries = [(record_type, target, record_type) for record_type in _BASIC_RECORD_TYPES]
    if advanced:
        queries.extend(
            (heading, name.format(target=target), record_type)
            for heading, name, record_type in _ADVANCED_QUERY_SPECS
        )
    return queries


def _run_dig_command(name: str, record_type: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["dig", "+nocmd", name, record_type, "+noall", "+answer"],
        text=True,
        capture_output=True,
        timeout=DIG_TIMEOUT_SECONDS,
    )


def _collect_ptr_addresses(stdout: str, record_type: str, addresses: list[str]) -> None:
    if record_type not in {"A", "AAAA"}:
        return

    for line in stdout.splitlines():
        fields = line.split()
        if len(fields) < 2 or fields[-2].upper() != record_type:
            continue
        try:
            address = str(ip_address(fields[-1]))
        except ValueError:
            continue
        if address not in addresses and len(addresses) < 4:
            addresses.append(address)


def _append_dns_queries(sections: list[str], target: str, advanced: bool) -> tuple[list[str], list[str]]:
    spf_records: list[str] = []
    ptr_addresses: list[str] = []

    for heading, name, record_type in _build_dns_queries(target, advanced):
        try:
            result = _run_dig_command(name, record_type)
        except subprocess.TimeoutExpired:
            sections.extend([f"## {heading}", "dig timed out.", ""])
            continue

        sections.extend([f"## {heading}", result.stdout.strip() or "No answer records returned."])
        if result.stderr.strip():
            sections.append(f"stderr: {result.stderr.strip()}")
        sections.append("")

        if advanced and heading == "TXT":
            spf_records = [line for line in result.stdout.splitlines() if "v=spf1" in line.lower()]
        if advanced:
            _collect_ptr_addresses(result.stdout, record_type, ptr_addresses)

    return spf_records, ptr_addresses


def _append_advanced_dns_sections(
    sections: list[str],
    spf_records: list[str],
    ptr_addresses: list[str],
) -> None:
    sections.extend(
        ["## SPF hints", *(spf_records or ["No SPF record found in the domain TXT answers."]), ""]
    )
    sections.extend(
        ["## DKIM selector coverage", "Only common selectors were queried; other selectors may exist.", ""]
    )

    if not ptr_addresses:
        sections.extend(["## PTR", "No A or AAAA addresses returned for reverse lookup.", ""])

    for address in ptr_addresses:
        try:
            result = subprocess.run(
                ["dig", "+nocmd", "-x", address, "+noall", "+answer"],
                text=True,
                capture_output=True,
                timeout=DIG_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            sections.extend([f"## PTR {address}", "dig timed out.", ""])
            continue

        sections.extend([f"## PTR {address}", result.stdout.strip() or "No answer records returned."])
        if result.stderr.strip():
            sections.append(f"stderr: {result.stderr.strip()}")
        sections.append("")


def _append_resolver_fallback(sections: list[str], target: str, advanced: bool) -> None:
    guidance = missing_tool_message("dig", optional=True)
    print(guidance)
    print("Using the local DNS resolver instead.")
    sections.extend([guidance, "Falling back to local resolver output.", ""])
    if advanced:
        sections.extend(["Advanced DNS records require dig and were not collected.", ""])

    try:
        addresses = sorted({result[4][0] for result in socket.getaddrinfo(target, None)})
    except socket.gaierror as error:
        sections.append(f"Resolver error: {error}")
    else:
        sections.append("## Resolver Addresses")
        sections.extend(addresses or ["No addresses returned."])


def run_dig_lookup(target: str, mode: str = "basic") -> Path | None:
    clean_target = normalize_target(target)
    if clean_target is None or not is_valid_hostname(clean_target):
        print("DNS lookup needs a plain hostname, for example example.com.")
        return None
    if mode not in {"basic", "advanced", "all"}:
        raise ValueError(f"Unknown DNS lookup mode: {mode}")

    advanced = mode in {"advanced", "all"}
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    suffix = "-advanced" if advanced else ""
    output_path = LOGS_DIR / f"dns-{slugify(clean_target)}{suffix}-{timestamp}.txt"
    sections = [f"# DNS lookup for {clean_target}", f"# Created {timestamp}", ""]
    dig_available = bool(shutil.which("dig"))

    if dig_available:
        spf_records, ptr_addresses = _append_dns_queries(sections, clean_target, advanced)
        if advanced:
            _append_advanced_dns_sections(sections, spf_records, ptr_addresses)
    else:
        _append_resolver_fallback(sections, clean_target, advanced)

    output_path.write_text("\n".join(sections), encoding="utf-8")
    upsert_asset(clean_target, asset_type="domain")
    record_types = list(_BASIC_RECORD_TYPES) + (["advanced"] if advanced else [])
    record_scan(
        clean_target,
        "dns",
        "dig" if dig_available else "resolver",
        "completed",
        ["dig", clean_target, ",".join(record_types)],
        output_path,
        "",
    )
    print(f"DNS lookup saved to: {output_path}")
    return output_path

"""Parsing and usage guidance for the ``/scan`` command."""

from .nmap import NmapScanOptions, normalize_timing, validate_ports
from .targets import normalize_decoy_list


_SCAN_PROFILES = {"quiet", "quick", "standard", "deep"}


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
    print("  decoy, -D <list>     Use up to five authorized decoys plus ME")
    print("  timing <0-4|name>, -T0..-T4")
    print("                       paranoid, sneaky, polite, normal, or aggressive")
    print("Examples:")
    print("  /scan localhost quiet")
    print("  /scan localhost -sV version-intensity 7")
    print("  /scan localhost ports 22,80,443 reason")
    print("  /scan 192.168.1.1 top 1000 no-service timing polite")
    print("  /scan 192.168.1.1 quick udp top 50")
    print("  /scan 192.168.56.10 decoy 192.168.56.20,ME")


def _next_value(args: list[str], index: int, missing_message: str) -> tuple[str, int] | None:
    if index + 1 >= len(args):
        print(missing_message)
        return None
    return args[index + 1], index + 2


def _parse_version_intensity(args: list[str], index: int, options: NmapScanOptions) -> int | None:
    token = args[index].lower()
    if "=" in token:
        intensity_value = token.split("=", 1)[1]
        next_index = index + 1
    else:
        parsed = _next_value(args, index, "Missing value after 'version-intensity'.")
        if parsed is None:
            return None
        intensity_value, next_index = parsed

    if not intensity_value.isdigit() or not 0 <= int(intensity_value) <= 9:
        print("Version intensity must be a number from 0 to 9.")
        return None

    options.service_detection = True
    options.version_intensity = int(intensity_value)
    return next_index


def _parse_decoys(args: list[str], index: int, options: NmapScanOptions) -> int | None:
    parsed = _next_value(args, index, "Missing decoy list after 'decoy' or '-D'.")
    if parsed is None:
        return None

    decoy_value, next_index = parsed
    decoys = normalize_decoy_list(decoy_value)
    if decoys is None:
        print(
            "Decoys must be a comma-separated list of up to five hostnames or IPs "
            "with ME exactly once in the first five positions."
        )
        return None

    options.decoys = decoys
    return next_index


def _parse_ports(args: list[str], index: int, options: NmapScanOptions) -> int | None:
    token = args[index].lower()
    if token.startswith("ports="):
        port_spec = token.split("=", 1)[1]
        next_index = index + 1
    else:
        parsed = _next_value(args, index, "Missing port list after 'ports'.")
        if parsed is None:
            return None
        port_spec, next_index = parsed

    if not validate_ports(port_spec):
        print("Ports must be 1-65535, comma-separated, or ranges such as 22,80,443 or 1-1024.")
        return None

    options.ports = port_spec
    options.top_ports = None
    return next_index


def _parse_top_ports(args: list[str], index: int, options: NmapScanOptions) -> int | None:
    token = args[index].lower()
    if token.startswith("top="):
        top_value = token.split("=", 1)[1]
        next_index = index + 1
    else:
        parsed = _next_value(args, index, "Missing count after 'top'.")
        if parsed is None:
            return None
        top_value, next_index = parsed

    if not top_value.isdigit() or not 1 <= int(top_value) <= 5000:
        print("Top port count must be a number from 1 to 5000.")
        return None

    options.top_ports = int(top_value)
    options.ports = None
    return next_index


def _parse_timing(args: list[str], index: int, options: NmapScanOptions) -> int | None:
    token = args[index].lower()
    if token.startswith("timing="):
        timing_value = token.split("=", 1)[1]
        next_index = index + 1
    elif len(token) == 3 and token.startswith("-t"):
        timing_value = token[2:]
        next_index = index + 1
    else:
        parsed = _next_value(args, index, "Missing value after 'timing'.")
        if parsed is None:
            return None
        timing_value, next_index = parsed

    timing = normalize_timing(timing_value)
    if timing is None:
        print("Timing must be 0-4, paranoid, sneaky, polite, normal, or aggressive.")
        return None

    options.timing = timing
    return next_index


def parse_scan_options(args: list[str]) -> tuple[str, str, NmapScanOptions] | None:
    if not args:
        print_scan_usage()
        return None

    target = args[0]
    scan_profile = "standard"
    options = NmapScanOptions()
    index = 1

    if index < len(args) and args[index].lower() in _SCAN_PROFILES:
        scan_profile = args[index].lower()
        index += 1

    while index < len(args):
        token = args[index].lower()

        if token in {"udp", "tcp"}:
            options.protocol = token
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
        elif token in {"version-intensity", "--version-intensity"} or token.startswith(
            ("version-intensity=", "--version-intensity=")
        ):
            index = _parse_version_intensity(args, index, options)
        elif token == "reason":
            options.reason = True
            index += 1
        elif token in {"decoy", "-d"}:
            index = _parse_decoys(args, index, options)
        elif token == "ports" or token.startswith("ports="):
            index = _parse_ports(args, index, options)
        elif token == "top" or token.startswith("top="):
            index = _parse_top_ports(args, index, options)
        elif token in {"timing", "--timing", "-t"} or token.startswith("timing=") or (
            len(token) == 3 and token.startswith("-t")
        ):
            index = _parse_timing(args, index, options)
        else:
            print(f"Unknown scan option: {args[index]}")
            print_scan_usage()
            return None

        if index is None:
            return None

    return target, scan_profile, options

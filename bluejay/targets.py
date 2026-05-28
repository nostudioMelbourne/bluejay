import re
from ipaddress import ip_address
from urllib.parse import ParseResult, urlparse

from .constants import ALLOWED_TARGETS_FILE


CONTROL_CHARACTER_PATTERN = re.compile(r"[\x00-\x1f\x7f]")
TARGET_DELIMITERS = {"/", "\\", ":", "?", "#", "@"}


def has_unsafe_characters(value: str) -> bool:
    return bool(CONTROL_CHARACTER_PATTERN.search(value) or re.search(r"\s", value))


def load_allowed_targets() -> set[str]:
    """Load authorised scan targets from allowed_targets.txt."""
    if not ALLOWED_TARGETS_FILE.exists():
        return set()

    targets = set()

    lines = ALLOWED_TARGETS_FILE.read_text(
        encoding="utf-8",
        errors="ignore",
    ).splitlines()

    for line in lines:
        clean_line = line.strip()

        if not clean_line:
            continue

        if clean_line.startswith("#"):
            continue

        clean_target = normalize_target(clean_line)

        if clean_target is not None:
            targets.add(clean_target)

    return targets


def is_valid_hostname(target: str) -> bool:
    if len(target) > 253:
        return False

    labels = target.rstrip(".").split(".")

    return all(
        0 < len(label) <= 63
        and re.match(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?$", label)
        for label in labels
    )


def normalize_target(target: str) -> str | None:
    clean_target = target.lower().strip().rstrip(".")

    if not clean_target:
        return None

    if re.search(r"\s", clean_target):
        return None

    try:
        return str(ip_address(clean_target))
    except ValueError:
        pass

    if re.fullmatch(r"[0-9.]+", clean_target):
        return None

    if any(character in clean_target for character in TARGET_DELIMITERS):
        return None

    if clean_target == "localhost" or is_valid_hostname(clean_target):
        return clean_target

    return None


def is_private_or_local_target(target: str) -> bool:
    """
    Allow localhost and private LAN IPs by default.

    Allowed:
    - localhost
    - 127.0.0.1
    - 10.x.x.x
    - 192.168.x.x
    - 172.16.x.x to 172.31.x.x
    """

    target = target.lower().strip()

    if target == "localhost":
        return True

    try:
        parsed_ip = ip_address(target)
    except ValueError:
        return False

    return parsed_ip.is_loopback or parsed_ip.is_private or parsed_ip.is_link_local


def is_allowed_target(target: str) -> bool:
    """Allow private/local targets and explicitly allowlisted public targets."""
    clean_target = normalize_target(target)

    if clean_target is None:
        return False

    allowed_targets = load_allowed_targets()

    return (
        is_private_or_local_target(clean_target)
        or clean_target in allowed_targets
    )


def format_netloc(hostname: str, port: int | None = None) -> str:
    host = f"[{hostname}]" if ":" in hostname else hostname
    return f"{host}:{port}" if port else host


def normalize_web_urls(raw_target: str) -> list[str] | None:
    raw_target = raw_target.strip()

    if not raw_target or has_unsafe_characters(raw_target):
        return None

    if "://" not in raw_target:
        clean_target = normalize_target(raw_target)

        if clean_target is None or not is_allowed_target(clean_target):
            return None

        netloc = format_netloc(clean_target)
        return [f"https://{netloc}/", f"http://{netloc}/"]

    parsed = parse_allowed_web_url(raw_target)

    if parsed is None:
        return None

    clean_host = normalize_target(parsed.hostname)
    if clean_host is None:
        return None

    try:
        port = parsed.port
    except ValueError:
        return None

    path = parsed.path or "/"
    netloc = format_netloc(clean_host, port)
    return [f"{parsed.scheme}://{netloc}{path}"]


def parse_allowed_web_url(raw_url: str, allow_query: bool = False) -> ParseResult | None:
    raw_url = raw_url.strip()

    if not raw_url or has_unsafe_characters(raw_url):
        return None

    parsed = urlparse(raw_url)

    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None

    clean_host = normalize_target(parsed.hostname)

    if clean_host is None or not is_allowed_target(clean_host):
        return None

    if parsed.username or parsed.password or parsed.fragment:
        return None

    if parsed.query and not allow_query:
        return None

    try:
        port = parsed.port
    except ValueError:
        return None

    if port is not None and port < 1:
        return None

    return parsed


def is_allowed_web_url(raw_url: str, allow_query: bool = False) -> bool:
    return parse_allowed_web_url(raw_url, allow_query=allow_query) is not None

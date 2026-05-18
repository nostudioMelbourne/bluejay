import json
import socket
import ssl
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from .constants import HTTP_TIMEOUT_SECONDS, LOGS_DIR
from .storage import make_finding, record_findings, record_scan, upsert_asset
from .targets import is_allowed_web_url, normalize_web_urls
from .utils import now_timestamp, slugify


class AllowedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not is_allowed_web_url(newurl, allow_query=True):
            raise urllib.error.URLError(f"Redirect blocked to non-allowed URL: {newurl}")

        return super().redirect_request(req, fp, code, msg, headers, newurl)


def open_allowed_url(request: urllib.request.Request):
    opener = urllib.request.build_opener(AllowedRedirectHandler)
    return opener.open(request, timeout=HTTP_TIMEOUT_SECONDS)


def fetch_web_url(url: str) -> dict:
    if not is_allowed_web_url(url, allow_query=True):
        return {
            "url": url,
            "final_url": url,
            "status": None,
            "headers": {},
            "error": "URL is not an allowed web target.",
        }

    request = urllib.request.Request(
        url,
        headers={"User-Agent": "BlueJay/0.1"},
        method="GET",
    )

    try:
        with open_allowed_url(request) as response:
            return {
                "url": url,
                "final_url": response.geturl(),
                "status": response.status,
                "headers": dict(response.headers.items()),
                "error": "",
            }
    except urllib.error.HTTPError as error:
        return {
            "url": url,
            "final_url": error.geturl(),
            "status": error.code,
            "headers": dict(error.headers.items()),
            "error": str(error),
        }
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError) as error:
        return {
            "url": url,
            "final_url": url,
            "status": None,
            "headers": {},
            "error": str(error),
        }


def add_tls_details(result: dict) -> None:
    parsed = urlparse(str(result.get("final_url") or result.get("url") or ""))

    if parsed.scheme == "https" and parsed.hostname:
        result["tls"] = inspect_tls(parsed.hostname, parsed.port or 443)


def inspect_tls(hostname: str, port: int = 443) -> dict:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=HTTP_TIMEOUT_SECONDS) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as wrapped:
                certificate = wrapped.getpeercert()
    except (OSError, ssl.SSLError) as error:
        return {"error": str(error)}

    not_after = certificate.get("notAfter", "")

    if not_after:
        expires_at = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after))
        days_remaining = (expires_at - datetime.now()).days
    else:
        expires_at = None
        days_remaining = None

    return {
        "subject": certificate.get("subject", []),
        "issuer": certificate.get("issuer", []),
        "not_after": not_after,
        "expires_at": expires_at.isoformat(timespec="seconds") if expires_at else "",
        "days_remaining": days_remaining,
        "error": "",
    }


def build_web_findings(target: str, results: list[dict], source: str) -> list[dict]:
    findings = []
    required_headers = [
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
    ]

    for result in results:
        url = result["url"]
        parsed = urlparse(url)
        headers = {key.lower(): value for key, value in result.get("headers", {}).items()}
        status = result.get("status")
        error = result.get("error", "")

        if error and status is None:
            findings.append(
                make_finding(
                    target=target,
                    title=f"Web check connection issue: {url}",
                    severity="Unknown",
                    finding_type="web-connectivity",
                    evidence=error,
                    source=source,
                    recommendation="Verify the service is reachable and check local network, DNS, firewall, or TLS configuration.",
                    confidence="Medium",
                    metadata={"url": url},
                )
            )
            continue

        if parsed.scheme == "http":
            findings.append(
                make_finding(
                    target=target,
                    title=f"HTTP service reachable without TLS: {url}",
                    severity="Medium",
                    finding_type="web-transport",
                    evidence=f"HTTP response status: {status}",
                    source=source,
                    recommendation="Redirect HTTP to HTTPS and use HSTS where appropriate.",
                    confidence="High",
                    metadata={"url": url, "status": status},
                )
            )

        missing_headers = [
            header for header in required_headers
            if header not in headers
        ]

        if parsed.scheme == "https" and "strict-transport-security" not in headers:
            missing_headers.append("strict-transport-security")

        if missing_headers and status is not None:
            findings.append(
                make_finding(
                    target=target,
                    title=f"Missing web security headers: {url}",
                    severity="Medium",
                    finding_type="web-headers",
                    evidence=", ".join(sorted(set(missing_headers))),
                    source=source,
                    recommendation="Add appropriate HTTP response security headers and test them in staging before production rollout.",
                    confidence="High",
                    metadata={"url": url, "status": status, "missing_headers": missing_headers},
                )
            )

        if "server" in headers:
            findings.append(
                make_finding(
                    target=target,
                    title=f"Server header disclosed: {url}",
                    severity="Info",
                    finding_type="web-disclosure",
                    evidence=f"Server: {headers['server']}",
                    source=source,
                    recommendation="Reduce detailed version disclosure where possible, while prioritising patching over banner hiding.",
                    confidence="High",
                    metadata={"url": url, "status": status},
                )
            )

        if "x-powered-by" in headers:
            findings.append(
                make_finding(
                    target=target,
                    title=f"X-Powered-By header disclosed: {url}",
                    severity="Low",
                    finding_type="web-disclosure",
                    evidence=f"X-Powered-By: {headers['x-powered-by']}",
                    source=source,
                    recommendation="Remove framework/version disclosure headers where possible.",
                    confidence="High",
                    metadata={"url": url, "status": status},
                )
            )

        cookies = result.get("headers", {}).get("Set-Cookie") or result.get("headers", {}).get("set-cookie")
        if cookies:
            lowered_cookie = cookies.lower()
            missing_cookie_flags = [
                flag for flag in ["secure", "httponly", "samesite"]
                if flag not in lowered_cookie
            ]

            if missing_cookie_flags:
                findings.append(
                    make_finding(
                        target=target,
                        title=f"Cookie hardening flags missing: {url}",
                        severity="Medium",
                        finding_type="web-cookie",
                        evidence=f"Missing flags: {', '.join(missing_cookie_flags)}",
                        source=source,
                        recommendation="Set Secure, HttpOnly, and SameSite attributes on session and sensitive cookies where applicable.",
                        confidence="Medium",
                        metadata={"url": url, "status": status, "missing_cookie_flags": missing_cookie_flags},
                    )
                )

        tls = result.get("tls", {})
        days_remaining = tls.get("days_remaining")

        if isinstance(days_remaining, int):
            if days_remaining < 0:
                severity = "High"
                title = f"TLS certificate expired: {url}"
            elif days_remaining <= 30:
                severity = "Medium"
                title = f"TLS certificate expires soon: {url}"
            else:
                severity = ""
                title = ""

            if severity:
                findings.append(
                    make_finding(
                        target=target,
                        title=title,
                        severity=severity,
                        finding_type="tls-certificate",
                        evidence=f"Certificate expires in {days_remaining} day(s): {tls.get('not_after', '')}",
                        source=source,
                        recommendation="Renew and deploy a valid TLS certificate before expiry.",
                        confidence="High",
                        metadata={"url": url, "days_remaining": days_remaining},
                    )
                )

        if tls.get("error"):
            findings.append(
                make_finding(
                    target=target,
                    title=f"TLS validation issue: {url}",
                    severity="Medium",
                    finding_type="tls-certificate",
                    evidence=tls["error"],
                    source=source,
                    recommendation="Review certificate trust, hostname coverage, expiry, and TLS service configuration.",
                    confidence="Medium",
                    metadata={"url": url},
                )
            )

    return findings


def run_web_check(target: str) -> Path | None:
    urls = normalize_web_urls(target)

    if urls is None:
        print("Web target blocked.")
        print("Use an allowed hostname/IP or an http/https URL without username, query, or fragment.")
        return None

    hostname = urlparse(urls[0]).hostname or target
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_path = LOGS_DIR / f"web-{slugify(hostname)}-{timestamp}.json"
    results = []

    for url in urls:
        result = fetch_web_url(url)

        parsed = urlparse(url)
        if parsed.scheme == "https" and parsed.hostname:
            result["tls"] = inspect_tls(parsed.hostname, parsed.port or 443)

        results.append(result)

    output = {
        "created_at": now_timestamp(),
        "target": hostname,
        "results": results,
    }
    output_path.write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")

    upsert_asset(hostname)
    record_scan(hostname, "web", "web-check", "completed", ["web-check", target], output_path, "")
    print(f"Web check saved to: {output_path}")
    record_findings(build_web_findings(hostname, results, str(output_path)), str(output_path))
    return output_path

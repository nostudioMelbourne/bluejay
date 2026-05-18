import json
import re
import ssl
import urllib.error
import urllib.request
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urldefrag, urljoin, urlparse

from .constants import LOGS_DIR, MAX_SITE_BYTES, MAX_SITE_LINKS, MAX_SITE_PAGES
from .http_checks import add_tls_details, build_web_findings, open_allowed_url
from .storage import make_finding, record_findings, record_scan, upsert_asset
from .targets import is_allowed_web_url, normalize_web_urls
from .utils import now_timestamp, slugify


class SiteHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.title_parts: list[str] = []
        self.links: list[dict] = []
        self.resources: list[dict] = []
        self.forms: list[dict] = []
        self._in_title = False
        self._current_form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attr_map = {
            key.lower(): value or ""
            for key, value in attrs
        }

        if tag == "title":
            self._in_title = True
            return

        if tag == "a":
            href = attr_map.get("href", "").strip()

            if href:
                self.links.append(
                    {
                        "href": href,
                        "target": attr_map.get("target", "").strip(),
                        "rel": attr_map.get("rel", "").strip(),
                    }
                )
            return

        if tag == "form":
            self._current_form = {
                "action": attr_map.get("action", "").strip(),
                "method": attr_map.get("method", "get").strip().lower() or "get",
                "inputs": [],
            }
            self.forms.append(self._current_form)
            return

        if tag == "input" and self._current_form is not None:
            self._current_form["inputs"].append(
                {
                    "type": attr_map.get("type", "text").strip().lower() or "text",
                    "name": attr_map.get("name", "").strip(),
                }
            )
            return

        resource_attribute = "href" if tag == "link" else "src"

        if tag in {"script", "img", "link", "iframe", "source"}:
            resource_url = attr_map.get(resource_attribute, "").strip()

            if resource_url:
                self.resources.append(
                    {
                        "tag": tag,
                        "url": resource_url,
                    }
                )

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()

        if tag == "title":
            self._in_title = False
        elif tag == "form":
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)

    def page_data(self) -> dict:
        return {
            "title": re.sub(r"\s+", " ", " ".join(self.title_parts)).strip(),
            "links": self.links,
            "resources": self.resources,
            "forms": self.forms,
        }


def fetch_site_url(url: str) -> dict:
    if not is_allowed_web_url(url, allow_query=True):
        return {
            "url": url,
            "final_url": url,
            "status": None,
            "headers": {},
            "content_type": "",
            "body_truncated": False,
            "body_excerpt": "",
            "html": "",
            "error": "URL is not an allowed web target.",
        }

    request = urllib.request.Request(
        url,
        headers={"User-Agent": "BlueJay/0.1"},
        method="GET",
    )

    try:
        with open_allowed_url(request) as response:
            body = response.read(MAX_SITE_BYTES + 1)
            content_type = response.headers.get("Content-Type", "")
            charset = response.headers.get_content_charset() or "utf-8"
            text = ""

            if "text/html" in content_type.lower():
                text = body[:MAX_SITE_BYTES].decode(charset, errors="replace")

            return {
                "url": url,
                "final_url": response.geturl(),
                "status": response.status,
                "headers": dict(response.headers.items()),
                "content_type": content_type,
                "body_truncated": len(body) > MAX_SITE_BYTES,
                "body_excerpt": text[:1000],
                "html": text,
                "error": "",
            }
    except urllib.error.HTTPError as error:
        body = error.read(MAX_SITE_BYTES + 1)
        content_type = error.headers.get("Content-Type", "")
        charset = error.headers.get_content_charset() or "utf-8"
        text = ""

        if "text/html" in content_type.lower():
            text = body[:MAX_SITE_BYTES].decode(charset, errors="replace")

        return {
            "url": url,
            "final_url": error.geturl(),
            "status": error.code,
            "headers": dict(error.headers.items()),
            "content_type": content_type,
            "body_truncated": len(body) > MAX_SITE_BYTES,
            "body_excerpt": text[:1000],
            "html": text,
            "error": str(error),
        }
    except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError) as error:
        return {
            "url": url,
            "final_url": url,
            "status": None,
            "headers": {},
            "content_type": "",
            "body_truncated": False,
            "body_excerpt": "",
            "html": "",
            "error": str(error),
        }


def parsed_origin(url: str) -> tuple[str, str, int] | None:
    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None

    try:
        port = parsed.port
    except ValueError:
        return None

    if port is None:
        port = 443 if parsed.scheme == "https" else 80

    return parsed.scheme, parsed.hostname.lower(), port


def same_origin(first_url: str, second_url: str) -> bool:
    return parsed_origin(first_url) == parsed_origin(second_url)


def resolve_page_url(base_url: str, raw_url: str) -> str | None:
    absolute_url = urldefrag(urljoin(base_url, raw_url.strip()))[0]
    parsed = urlparse(absolute_url)

    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None

    return absolute_url


def parse_site_html(html: str) -> dict:
    parser = SiteHTMLParser()

    try:
        parser.feed(html)
    except Exception:
        return {"title": "", "links": [], "resources": [], "forms": []}

    return parser.page_data()


def build_site_findings(target: str, pages: list[dict], source: str) -> list[dict]:
    findings = build_web_findings(target, pages, source)

    for page in pages:
        page_url = str(page.get("final_url") or page.get("url") or "")
        page_data = page.get("page", {}) or {}
        status = page.get("status")
        parsed_page = urlparse(page_url)

        if isinstance(status, int) and status >= 400:
            findings.append(
                make_finding(
                    target=target,
                    title=f"Broken crawled page: {page_url}",
                    severity="Medium",
                    finding_type="site-broken-page",
                    evidence=f"HTTP status {status}",
                    source=source,
                    recommendation="Fix or remove internal links that lead users and scanners to failing pages.",
                    confidence="High",
                    metadata={"url": page_url, "status": status},
                )
            )

        title = str(page_data.get("title", ""))
        if title.lower().startswith("index of"):
            findings.append(
                make_finding(
                    target=target,
                    title=f"Directory listing page exposed: {page_url}",
                    severity="Medium",
                    finding_type="site-directory-listing",
                    evidence=f"Page title: {title}",
                    source=source,
                    recommendation="Disable directory listings unless this is intentional and safe for the environment.",
                    confidence="Medium",
                    metadata={"url": page_url},
                )
            )

        mixed_content = []
        if parsed_page.scheme == "https":
            for item in page_data.get("resources", []):
                absolute_url = resolve_page_url(page_url, str(item.get("url", "")))
                if absolute_url and urlparse(absolute_url).scheme == "http":
                    mixed_content.append(f"{item.get('tag')}: {absolute_url}")

        if mixed_content:
            findings.append(
                make_finding(
                    target=target,
                    title=f"HTTPS page references HTTP resources: {page_url}",
                    severity="Medium",
                    finding_type="site-mixed-content",
                    evidence="\n".join(mixed_content[:10]),
                    source=source,
                    recommendation="Serve scripts, styles, images, and embedded resources over HTTPS.",
                    confidence="High",
                    metadata={"url": page_url, "mixed_content": mixed_content[:10]},
                )
            )

        for form_index, form in enumerate(page_data.get("forms", []), start=1):
            inputs = form.get("inputs", [])
            has_password = any(input_item.get("type") == "password" for input_item in inputs)
            method = str(form.get("method", "get")).lower()
            action_url = resolve_page_url(page_url, str(form.get("action") or page_url))
            action_scheme = urlparse(action_url).scheme if action_url else ""

            if has_password and parsed_page.scheme == "http":
                findings.append(
                    make_finding(
                        target=target,
                        title=f"Password form served over HTTP: {page_url}",
                        severity="High",
                        finding_type="site-insecure-form",
                        evidence=f"Form {form_index} contains a password input on an HTTP page.",
                        source=source,
                        recommendation="Serve login and credential forms over HTTPS only.",
                        confidence="High",
                        metadata={"url": page_url, "form": form_index},
                    )
                )

            if has_password and method == "get":
                findings.append(
                    make_finding(
                        target=target,
                        title=f"Password form uses GET: {page_url}",
                        severity="High",
                        finding_type="site-insecure-form",
                        evidence=f"Form {form_index} method is GET.",
                        source=source,
                        recommendation="Use POST for credential forms and ensure secrets are not placed in URLs.",
                        confidence="High",
                        metadata={"url": page_url, "form": form_index},
                    )
                )

            if has_password and action_scheme == "http":
                findings.append(
                    make_finding(
                        target=target,
                        title=f"Password form submits over HTTP: {page_url}",
                        severity="High",
                        finding_type="site-insecure-form",
                        evidence=f"Form {form_index} action: {action_url}",
                        source=source,
                        recommendation="Submit credential forms to HTTPS endpoints only.",
                        confidence="High",
                        metadata={"url": page_url, "form": form_index, "action": action_url},
                    )
                )

        unsafe_blank_links = []
        for link in page_data.get("links", []):
            if str(link.get("target", "")).lower() != "_blank":
                continue

            absolute_url = resolve_page_url(page_url, str(link.get("href", "")))
            if not absolute_url or same_origin(page_url, absolute_url):
                continue

            rel_tokens = set(str(link.get("rel", "")).lower().split())
            if "noopener" not in rel_tokens and "noreferrer" not in rel_tokens:
                unsafe_blank_links.append(absolute_url)

        if unsafe_blank_links:
            findings.append(
                make_finding(
                    target=target,
                    title=f"External new-tab links missing opener protection: {page_url}",
                    severity="Low",
                    finding_type="site-link-hardening",
                    evidence="\n".join(unsafe_blank_links[:10]),
                    source=source,
                    recommendation="Add rel=\"noopener noreferrer\" to external links that use target=\"_blank\".",
                    confidence="High",
                    metadata={"url": page_url, "links": unsafe_blank_links[:10]},
                )
            )

    return findings


def crawl_site(start_urls: list[str]) -> tuple[str | None, list[dict]]:
    first_results = []

    for start_url in start_urls:
        result = fetch_site_url(start_url)
        add_tls_details(result)
        first_results.append(result)

        if result.get("status") is not None:
            break

    if not first_results:
        return None, []

    start_result = first_results[-1]
    start_url = str(start_result.get("final_url") or start_result.get("url") or "")

    if start_result.get("status") is None:
        return start_url, first_results

    queue = [start_url]
    queued = {start_url}
    seen = set()
    pages = []

    while queue and len(pages) < MAX_SITE_PAGES:
        url = queue.pop(0)

        if url in seen:
            continue

        seen.add(url)
        result = start_result if url == start_url else fetch_site_url(url)
        add_tls_details(result)
        html = str(result.pop("html", ""))

        if html:
            page_data = parse_site_html(html)
            result["page"] = page_data

            for link in page_data.get("links", []):
                absolute_url = resolve_page_url(url, str(link.get("href", "")))

                if (
                    absolute_url
                    and same_origin(start_url, absolute_url)
                    and absolute_url not in queued
                    and len(queued) < MAX_SITE_LINKS
                ):
                    queue.append(absolute_url)
                    queued.add(absolute_url)
        else:
            result["page"] = {"title": "", "links": [], "resources": [], "forms": []}

        pages.append(result)

    return start_url, pages


def run_site_audit(target: str) -> Path | None:
    urls = normalize_web_urls(target)

    if urls is None:
        print("Site target blocked.")
        print("Use an allowed hostname/IP or an http/https URL without username, query, or fragment.")
        return None

    start_url, pages = crawl_site(urls)

    if not start_url:
        print("No site URL could be prepared.")
        return None

    hostname = urlparse(start_url).hostname or target
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_path = LOGS_DIR / f"site-{slugify(hostname)}-{timestamp}.json"
    output = {
        "created_at": now_timestamp(),
        "target": hostname,
        "start_url": start_url,
        "limits": {
            "max_pages": MAX_SITE_PAGES,
            "max_links": MAX_SITE_LINKS,
            "max_body_bytes": MAX_SITE_BYTES,
        },
        "pages": pages,
    }
    output_path.write_text(json.dumps(output, indent=2, sort_keys=True), encoding="utf-8")

    status = "completed" if pages and any(page.get("status") is not None for page in pages) else "failed"
    upsert_asset(hostname)
    record_scan(
        hostname,
        "site",
        "site-audit",
        status,
        ["site-audit", target],
        output_path,
        "",
        {"pages": len(pages), "start_url": start_url},
    )
    print(f"Site audit saved to: {output_path}")
    print(f"Crawled {len(pages)} page(s) from: {start_url}")
    record_findings(build_site_findings(hostname, pages, str(output_path)), str(output_path))
    return output_path

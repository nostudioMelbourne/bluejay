import json
from datetime import datetime
from pathlib import Path

from .constants import BASELINES_DIR
from .storage import filter_findings, load_findings
from .utils import now_timestamp, slugify


BASELINE_VERSION = 1


def safe_int(value: object, fallback: int = 1) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def baseline_scope(target: str | None) -> str:
    clean_target = (target or "all").lower().strip()
    return "all" if clean_target == "all" else clean_target


def baseline_path(target: str | None) -> Path:
    return BASELINES_DIR / f"{slugify(baseline_scope(target))}.json"


def findings_for_scope(target: str | None) -> list[dict]:
    scope = baseline_scope(target)
    return filter_findings(
        load_findings(),
        target=None if scope == "all" else scope,
        status="open",
    )


def finding_snapshot(finding: dict) -> dict:
    return {
        "fingerprint": str(finding.get("fingerprint", "")),
        "id": str(finding.get("id", "")),
        "target": str(finding.get("target", "")),
        "title": str(finding.get("title", "")),
        "severity": str(finding.get("severity", "Unknown")),
        "type": str(finding.get("type", "")),
        "confidence": str(finding.get("confidence", "")),
        "evidence": str(finding.get("evidence", "")),
        "recommendation": str(finding.get("recommendation", "")),
        "cves": finding.get("cves", []) or [],
        "source": str(finding.get("source", "")),
        "metadata": finding.get("metadata", {}) or {},
        "first_seen": str(finding.get("first_seen", "")),
        "last_seen": str(finding.get("last_seen", "")),
        "times_seen": safe_int(finding.get("times_seen", 1), 1),
    }


def save_baseline(target: str | None) -> dict:
    BASELINES_DIR.mkdir(exist_ok=True)
    scope = baseline_scope(target)
    findings = [finding_snapshot(finding) for finding in findings_for_scope(scope)]
    snapshot = {
        "version": BASELINE_VERSION,
        "scope": scope,
        "created_at": now_timestamp(),
        "finding_count": len(findings),
        "findings": findings,
    }
    path = baseline_path(scope)
    path.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    snapshot["path"] = str(path)
    return snapshot


def load_baseline(target: str | None) -> dict | None:
    path = baseline_path(target)

    if not path.exists():
        return None

    try:
        snapshot = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None

    if not isinstance(snapshot, dict):
        return None

    snapshot["path"] = str(path)
    return snapshot


def list_baselines() -> list[dict]:
    baselines = []

    for path in sorted(BASELINES_DIR.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True):
        try:
            snapshot = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        if not isinstance(snapshot, dict):
            continue

        baselines.append(
            {
                "scope": snapshot.get("scope", path.stem),
                "created_at": snapshot.get("created_at", ""),
                "finding_count": snapshot.get("finding_count", len(snapshot.get("findings", []))),
                "path": path,
            }
        )

    return baselines


def severity_counts(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}

    for finding in findings:
        severity = str(finding.get("severity", "Unknown"))
        counts[severity] = counts.get(severity, 0) + 1

    return counts


def compare_to_baseline(target: str | None) -> dict | None:
    baseline = load_baseline(target)

    if baseline is None:
        return None

    baseline_findings = [
        finding
        for finding in baseline.get("findings", [])
        if isinstance(finding, dict) and finding.get("fingerprint")
    ]
    current_findings = [
        finding_snapshot(finding)
        for finding in findings_for_scope(str(baseline.get("scope") or baseline_scope(target)))
        if finding.get("fingerprint")
    ]
    baseline_by_fingerprint = {
        str(finding["fingerprint"]): finding
        for finding in baseline_findings
    }
    current_by_fingerprint = {
        str(finding["fingerprint"]): finding
        for finding in current_findings
    }

    new_findings = [
        finding for fingerprint, finding in current_by_fingerprint.items()
        if fingerprint not in baseline_by_fingerprint
    ]
    fixed_findings = [
        finding for fingerprint, finding in baseline_by_fingerprint.items()
        if fingerprint not in current_by_fingerprint
    ]
    changed_findings = []
    unchanged_findings = []

    for fingerprint, current in current_by_fingerprint.items():
        original = baseline_by_fingerprint.get(fingerprint)

        if original is None:
            continue

        changed_fields = [
            field
            for field in ["severity", "confidence", "recommendation"]
            if current.get(field) != original.get(field)
        ]

        if changed_fields:
            changed = dict(current)
            changed["baseline"] = {
                field: original.get(field, "")
                for field in changed_fields
            }
            changed["changed_fields"] = changed_fields
            changed_findings.append(changed)
        else:
            unchanged_findings.append(current)

    return {
        "scope": baseline.get("scope", baseline_scope(target)),
        "baseline_created_at": baseline.get("created_at", ""),
        "baseline_path": baseline.get("path", ""),
        "compared_at": now_timestamp(),
        "new": new_findings,
        "fixed": fixed_findings,
        "changed": changed_findings,
        "unchanged": unchanged_findings,
        "current_count": len(current_findings),
        "baseline_count": len(baseline_findings),
    }


def save_diff_report(diff: dict) -> Path:
    BASELINES_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    scope = str(diff.get("scope", "all"))
    path = BASELINES_DIR / f"diff-{slugify(scope)}-{timestamp}.json"
    path.write_text(json.dumps(diff, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path

from datetime import datetime
from pathlib import Path

from .constants import REPORTS_DIR
from .storage import filter_findings, load_findings
from .utils import now_timestamp, slugify


def generate_findings_report(target: str | None = None, mode: str = "technical") -> Path | None:
    findings = filter_findings(load_findings(), target=target, status="open")

    if not findings:
        print("No open findings available for that report scope.")
        return None

    target_label = target or "all-targets"
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    report_path = REPORTS_DIR / f"{mode}-findings-{slugify(target_label)}-{timestamp}.md"
    counts = {}

    for finding in findings:
        severity = str(finding.get("severity", "Unknown"))
        counts[severity] = counts.get(severity, 0) + 1

    lines = [
        f"# Blue Jay {mode.title()} Findings Report",
        "",
        f"Generated: {now_timestamp()}",
        f"Scope: {target_label}",
        f"Open findings: {len(findings)}",
        "",
        "## Severity Summary",
        "",
    ]

    for severity in ["Critical", "High", "Medium", "Low", "Info", "Unknown"]:
        if counts.get(severity):
            lines.append(f"- {severity}: {counts[severity]}")

    if mode == "executive":
        lines.extend(
            [
                "",
                "## Executive Summary",
                "",
                f"Blue Jay found {len(findings)} open issue(s) in scope. "
                "Prioritise High and Critical findings first, then Medium findings that expose remote services or weaken web security.",
                "",
                "## Priority Actions",
                "",
            ]
        )
        for finding in findings[:10]:
            lines.append(f"- {finding.get('severity')}: {finding.get('title')} on `{finding.get('target')}`")
        lines.append("")
    elif mode == "remediation":
        lines.extend(["", "## Remediation Checklist", ""])
        for finding in findings:
            lines.append(f"- [ ] {finding.get('severity')}: {finding.get('recommendation')} (`{finding.get('id')}`)")
        lines.append("")
    elif mode == "retest":
        lines.extend(["", "## Retest Plan", ""])
        for finding in findings:
            lines.extend(
                [
                    f"### {finding.get('id')} - {finding.get('title')}",
                    "",
                    f"- Target: `{finding.get('target')}`",
                    f"- Expected fix: {finding.get('recommendation')}",
                    "- Retest result: Pending",
                    "- Retest notes:",
                    "",
                ]
            )
    elif mode == "learning":
        lines.extend(
            [
                "",
                "## Learning Notes",
                "",
                "Each finding below includes what was observed, why it matters, and a safe way to think about remediation.",
                "",
            ]
        )

    lines.extend(["", "## Findings", ""])

    for finding in findings:
        lines.extend(
            [
                f"### {finding.get('severity', 'Unknown')} - {finding.get('title', 'Untitled finding')}",
                "",
                f"- ID: `{finding.get('id', '')}`",
                f"- Target: `{finding.get('target', '')}`",
                f"- Status: `{finding.get('status', '')}`",
                f"- Type: `{finding.get('type', '')}`",
                f"- Confidence: `{finding.get('confidence', '')}`",
                f"- First seen: `{finding.get('first_seen', '')}`",
                f"- Last seen: `{finding.get('last_seen', '')}`",
                f"- Times seen: `{finding.get('times_seen', 1)}`",
                f"- Source: `{finding.get('source', '')}`",
            ]
        )

        cves = finding.get("cves", [])
        if cves:
            lines.append(f"- CVEs: {', '.join(f'`{cve}`' for cve in cves)}")

        lines.extend(
            [
                "",
                "Evidence:",
                "",
                "```txt",
                str(finding.get("evidence", "")),
                "```",
                "",
                "Recommendation:",
                "",
                str(finding.get("recommendation", "")),
                "",
            ]
        )

    report_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Findings report saved to: {report_path}")
    return report_path

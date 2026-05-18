import json
from datetime import datetime

from .analysis import list_reports
from .baselines import compare_to_baseline, list_baselines, save_baseline, save_diff_report, severity_counts
from .config import configured_model
from .model import run_ollama
from .nmap import run_safe_nmap_scan
from .reports import generate_findings_report
from .storage import filter_findings, load_assets, load_findings, load_scan_history, write_findings
from .ui import ui_markdown, ui_panel, ui_print, ui_status, ui_table
from .utils import now_timestamp
from .web import run_nuclei_scan, run_web_check


def format_severity_counts(findings: list[dict]) -> str:
    counts = severity_counts(findings)
    parts = [
        f"{severity}:{counts[severity]}"
        for severity in ["Critical", "High", "Medium", "Low", "Info", "Unknown"]
        if counts.get(severity)
    ]
    return ", ".join(parts) or "-"


def finding_rows(findings: list[dict], limit: int = 10) -> list[list[object]]:
    return [
        [
            finding.get("id", ""),
            finding.get("severity", ""),
            finding.get("target", ""),
            finding.get("title", ""),
        ]
        for finding in findings[:limit]
    ]


def cmd_assets(args: list[str]) -> None:
    if args:
        print("Usage: /assets")
        return

    assets = load_assets()

    if not assets:
        print("No assets recorded yet.")
        return

    findings = load_findings()
    rows = []
    for asset in assets[:50]:
        open_count = len(filter_findings(findings, target=asset["target"], status="open"))
        rows.append(
            [
                asset["target"],
                asset["asset_type"],
                asset["first_seen"],
                asset["last_seen"],
                open_count,
            ]
        )

    ui_table("Assets", ["Target", "Type", "First seen", "Last seen", "Open"], rows)

    if len(assets) > 50:
        print(f"\nShowing 50 of {len(assets)} assets.")

    ui_print("Use /asset <target> for details.", "dim")
    print()


def cmd_asset(args: list[str]) -> None:
    if len(args) != 1:
        print("Usage: /asset <target>")
        return

    target = args[0].lower()
    assets = [asset for asset in load_assets() if asset["target"].lower() == target]

    if not assets:
        print("Asset not found.")
        return

    asset = assets[0]
    findings = filter_findings(load_findings(), target=asset["target"], status="open")
    scans = load_scan_history(asset["target"], limit=5)

    ui_panel(
        f"Asset: {asset['target']}",
        (
            f"Type: {asset['asset_type']}\n"
            f"First seen: {asset['first_seen']}\n"
            f"Last seen: {asset['last_seen']}\n"
            f"Open findings: {len(findings)}"
        ),
    )
    ui_table(
        "Recent Scans",
        ["Created", "Tool", "Profile", "Status"],
        [
            [scan["created_at"], scan["tool"], scan["profile"], scan["status"]]
            for scan in scans
        ],
    )


def cmd_history(args: list[str]) -> None:
    if len(args) > 1:
        print("Usage: /history [target]")
        return

    target = args[0].lower() if args else None
    scans = load_scan_history(target, limit=25)

    if not scans:
        print("No scan history found.")
        return

    ui_table(
        "Scan History",
        ["Created", "Target", "Tool", "Profile", "Status", "Output"],
        [
            [
                scan["created_at"],
                scan["target"],
                scan["tool"],
                scan["profile"],
                scan["status"],
                scan["output_path"],
            ]
            for scan in scans
        ],
    )


def cmd_findings(args: list[str]) -> None:
    status = "open"
    target = None

    if len(args) > 2:
        print("Usage: /findings [open|resolved|all] [target]")
        return

    if args:
        if args[0] in {"open", "resolved", "all"}:
            status = args[0]
            if len(args) == 2:
                target = args[1].lower()
        else:
            target = args[0].lower()

    findings = filter_findings(load_findings(), target=target, status=status)

    if not findings:
        print("No findings match that scope.")
        return

    ui_table(
        "Findings",
        ["ID", "Severity", "Status", "Target", "Seen", "Title"],
        [
            [
                finding.get("id"),
                finding.get("severity"),
                finding.get("status"),
                finding.get("target"),
                finding.get("times_seen", 1),
                finding.get("title"),
            ]
            for finding in findings[:25]
        ],
    )

    if len(findings) > 25:
        print(f"\nShowing 25 of {len(findings)} findings.")

    ui_print("Use /finding <id> to view details.", "dim")
    print()


def find_finding(findings: list[dict], finding_id: str) -> dict | None:
    matches = [
        finding for finding in findings
        if str(finding.get("id", "")).startswith(finding_id)
    ]

    if len(matches) == 1:
        return matches[0]

    return None


def cmd_finding(args: list[str]) -> None:
    if len(args) != 1:
        print("Usage: /finding <id>")
        return

    finding = find_finding(load_findings(), args[0])

    if finding is None:
        print("Finding not found or ID prefix is ambiguous.")
        return

    cves = finding.get("cves", [])
    body = [
        f"Target: {finding.get('target')}",
        f"Title: {finding.get('title')}",
        f"Type: {finding.get('type')}",
        f"Confidence: {finding.get('confidence')}",
        f"Times seen: {finding.get('times_seen', 1)}",
        f"First seen: {finding.get('first_seen', '')}",
        f"Last seen: {finding.get('last_seen', '')}",
        f"Source: {finding.get('source')}",
    ]
    if cves:
        body.append(f"CVEs: {', '.join(cves)}")

    body.extend(
        [
            "",
            "Evidence:",
            str(finding.get("evidence", "")),
            "",
            "Recommendation:",
            str(finding.get("recommendation", "")),
        ]
    )
    ui_panel(
        f"{finding.get('id')} | {finding.get('severity')} | {finding.get('status')}",
        "\n".join(body),
        "yellow",
    )


def cmd_triage(args: list[str]) -> None:
    if len(args) > 1:
        print("Usage: /triage [target]")
        return

    target = args[0].lower() if args else None
    findings = filter_findings(load_findings(), target=target, status="open")

    if not findings:
        print("No open findings to triage.")
        return

    counts = {}
    for finding in findings:
        severity = finding.get("severity", "Unknown")
        counts[severity] = counts.get(severity, 0) + 1

    ui_table(
        "Triage Summary",
        ["Severity", "Count"],
        [
            [severity, counts[severity]]
            for severity in ["Critical", "High", "Medium", "Low", "Info", "Unknown"]
            if counts.get(severity)
        ],
    )
    ui_table(
        "Next Priorities",
        ["ID", "Severity", "Target", "Title"],
        [
            [finding.get("id"), finding.get("severity"), finding.get("target"), finding.get("title")]
            for finding in findings[:5]
        ],
    )
    ui_print("Use /next, /finding <id>, /remediate <id>, or /resolve <id>.", "dim")
    print()


def cmd_next(args: list[str]) -> None:
    if len(args) > 1:
        print("Usage: /next [target]")
        return

    target = args[0].lower() if args else None
    findings = filter_findings(load_findings(), target=target, status="open")

    if not findings:
        print("No open findings.")
        return

    cmd_finding([findings[0]["id"]])


def cmd_remediate(args: list[str]) -> None:
    if len(args) != 1:
        print("Usage: /remediate <id>")
        return

    finding = find_finding(load_findings(), args[0])

    if finding is None:
        print("Finding not found or ID prefix is ambiguous.")
        return

    body = "\n".join(
        [
            f"Target: {finding.get('target')}",
            f"Severity: {finding.get('severity')}",
            "",
            "Recommended action:",
            str(finding.get("recommendation", "")),
            "",
            "Suggested workflow:",
            "1. Confirm the finding is still present.",
            "2. Identify the responsible service, package, or configuration.",
            "3. Apply the least disruptive fix in a controlled change window.",
            "4. Retest with the same Blue Jay command or source tool.",
            "5. Mark the finding resolved only after evidence confirms the fix.",
        ]
    )
    ui_panel(f"Remediation: {finding.get('title')}", body, "green")


def cmd_explain(args: list[str]) -> None:
    if len(args) != 1:
        print("Usage: /explain <id>")
        return

    finding = find_finding(load_findings(), args[0])

    if finding is None:
        print("Finding not found or ID prefix is ambiguous.")
        return

    prompt = f"""
You are Blue Jay, a defensive cybersecurity assistant.

Explain this stored finding in beginner-friendly language.
Do not provide exploitation steps. Focus on what the evidence means,
why it matters, how to validate safely, and how to remediate.

Finding:
{json.dumps(finding, indent=2, sort_keys=True)}
"""
    with ui_status("Running local model..."):
        response = run_ollama(prompt, configured_model("explain"))
    ui_markdown(response)
    print()


def cmd_retest(args: list[str]) -> None:
    if len(args) != 1:
        print("Usage: /retest <id>")
        return

    finding = find_finding(load_findings(), args[0])

    if finding is None:
        print("Finding not found or ID prefix is ambiguous.")
        return

    finding_type = str(finding.get("type", ""))
    target = str(finding.get("target", ""))
    metadata = finding.get("metadata", {}) or {}

    print(f"Retesting finding {finding.get('id')} with the closest safe check.")

    if finding_type.startswith("web-") or finding_type.startswith("tls-"):
        run_web_check(str(metadata.get("url") or target))
    elif finding_type == "nuclei-template":
        run_nuclei_scan(str(metadata.get("matched_at") or target))
    elif finding_type == "nmap-script":
        run_safe_nmap_scan(target, scan_profile="vulnerability")
    else:
        run_safe_nmap_scan(target, scan_profile="standard")

    print("Retest complete. Review /findings and resolve the original finding when evidence confirms the fix.")


def cmd_baseline(args: list[str]) -> None:
    if len(args) > 1:
        print("Usage: /baseline [target|all]")
        return

    if not args:
        baselines = list_baselines()

        if not baselines:
            print("No baselines saved yet.")
            print("Use /baseline <target|all> after collecting findings.")
            return

        ui_table(
            "Saved Baselines",
            ["Scope", "Created", "Open findings", "File"],
            [
                [
                    baseline["scope"],
                    baseline["created_at"],
                    baseline["finding_count"],
                    baseline["path"],
                ]
                for baseline in baselines
            ],
        )
        return

    target = args[0].lower()
    snapshot = save_baseline(target)
    findings = snapshot.get("findings", [])

    ui_table(
        "Baseline Saved",
        ["Item", "Value"],
        [
            ["Scope", snapshot["scope"]],
            ["Created", snapshot["created_at"]],
            ["Open findings", snapshot["finding_count"]],
            ["Severity", format_severity_counts(findings)],
            ["File", snapshot["path"]],
        ],
    )


def cmd_diff(args: list[str]) -> None:
    if len(args) != 1:
        print("Usage: /diff <target|all>")
        return

    target = args[0].lower()
    diff = compare_to_baseline(target)

    if diff is None:
        print("No baseline found for that scope.")
        print("Create one first with /baseline <target|all>.")
        return

    report_path = save_diff_report(diff)
    new_findings = diff["new"]
    fixed_findings = diff["fixed"]
    changed_findings = diff["changed"]
    unchanged_findings = diff["unchanged"]

    ui_table(
        "Baseline Diff",
        ["Item", "Value"],
        [
            ["Scope", diff["scope"]],
            ["Baseline created", diff["baseline_created_at"]],
            ["Baseline findings", diff["baseline_count"]],
            ["Current findings", diff["current_count"]],
            ["New", len(new_findings)],
            ["Fixed or no longer open", len(fixed_findings)],
            ["Changed", len(changed_findings)],
            ["Still open", len(unchanged_findings)],
            ["Diff evidence", report_path],
        ],
    )

    if new_findings:
        ui_table("New Findings", ["ID", "Severity", "Target", "Title"], finding_rows(new_findings))

    if fixed_findings:
        ui_table("Fixed Or No Longer Open", ["ID", "Severity", "Target", "Title"], finding_rows(fixed_findings))

    if changed_findings:
        ui_table(
            "Changed Findings",
            ["ID", "Severity", "Target", "Changed fields"],
            [
                [
                    finding.get("id", ""),
                    finding.get("severity", ""),
                    finding.get("target", ""),
                    ", ".join(finding.get("changed_fields", [])),
                ]
                for finding in changed_findings[:10]
            ],
        )

    if not new_findings and not fixed_findings and not changed_findings:
        print("No changes from the saved baseline.")


def cmd_set_finding_status(args: list[str], status: str, command_name: str) -> None:
    if len(args) != 1:
        print(f"Usage: /{command_name} <id>")
        return

    findings = load_findings()
    finding = find_finding(findings, args[0])

    if finding is None:
        print("Finding not found or ID prefix is ambiguous.")
        return

    finding["status"] = status
    finding["updated_at"] = now_timestamp()
    write_findings(findings)
    print(f"Finding {finding.get('id')} marked {status}.")


def cmd_report(args: list[str]) -> None:
    if len(args) > 2:
        print("Usage: /report [technical|executive|remediation|retest|learning] [target|all]")
        return

    mode = "technical"
    target = None
    valid_modes = {"technical", "executive", "remediation", "retest", "learning"}

    if args:
        if args[0] in valid_modes:
            mode = args[0]

            if len(args) == 2 and args[1] != "all":
                target = args[1].lower()
        elif args[0] != "all":
            target = args[0].lower()

    generate_findings_report(target, mode)


def cmd_view(args: list[str]) -> None:
    if len(args) != 1:
        print("Usage: /view <number>")
        return

    if not args[0].isdigit():
        print("Report number must be a number.")
        return

    reports = list_reports()
    index = int(args[0]) - 1

    if index < 0 or index >= min(len(reports), 10):
        print("Invalid report number.")
        return

    report_path = reports[index]
    content = report_path.read_text(encoding="utf-8", errors="ignore")

    ui_panel("Report", report_path.name, "green")
    ui_markdown(content)
    print()

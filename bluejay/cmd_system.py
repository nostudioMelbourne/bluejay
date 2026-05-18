import shutil
from datetime import datetime
from pathlib import Path

from .analysis import list_files, list_reports
from .chat import list_chat_sessions, select_chat_session
from .config import default_config, load_config, normalize_model_profile, save_config, validate_model_name
from .constants import (
    ALLOWED_TARGETS_FILE,
    CHAT_CONTEXT_CHARS,
    CHAT_HISTORY_LIMIT,
    CHATS_DIR,
    COMMANDS,
    CONFIG_FILE,
    DATA_DIR,
    DB_FILE,
    FINDINGS_FILE,
    LOGS_DIR,
    MODEL_DEFAULTS,
    MODEL_NAME,
    MODEL_PROFILES,
    REPORTS_DIR,
    SCANS_DIR,
)
from .optional_deps import PROMPT_TOOLKIT_AVAILABLE, RICH_AVAILABLE
from .storage import load_assets, load_findings
from .targets import load_allowed_targets
from .ui import print_banner, ui_key_values, ui_list, ui_markdown, ui_panel, ui_print, ui_table


def cmd_help() -> None:
    rows = [
        [command, args, description]
        for command, args, description in COMMANDS
    ]
    ui_table("Blue Jay Commands", ["Command", "Args", "What it does"], rows)
    ui_print("Tip: use Tab to complete slash commands. Type normal text to chat.", "dim")
    print()


def cmd_allowed() -> None:
    targets = sorted(load_allowed_targets())

    if not targets:
        ui_print("No allowlisted targets found.", "warning")
        ui_print("Add authorised targets to allowed_targets.txt, one per line.", "muted")
        return

    ui_list("Allowlisted Targets", targets)


def cmd_status() -> None:
    findings = load_findings()
    open_findings = [finding for finding in findings if finding.get("status") == "open"]
    config = load_config()

    ui_table(
        "Blue Jay Status",
        ["Item", "Value"],
        [
            ["Chat model", config["models"].get("chat", MODEL_NAME)],
            ["Analysis model", config["models"].get("analysis", MODEL_DEFAULTS["analysis"])],
            ["Explain model", config["models"].get("explain", MODEL_DEFAULTS["explain"])],
            ["Nmap", "found" if shutil.which("nmap") else "missing"],
            ["Ollama", "found" if shutil.which("ollama") else "missing"],
            ["dig", "found" if shutil.which("dig") else "missing"],
            ["Nuclei", "found" if shutil.which("nuclei") else "missing"],
            ["Findings", f"{len(findings)} total, {len(open_findings)} open"],
            ["Assets", len(load_assets())],
            ["Rich TUI", "enabled" if RICH_AVAILABLE else "not installed"],
            ["Command picker", "enabled" if PROMPT_TOOLKIT_AVAILABLE else "not installed"],
        ],
    )
    ui_table(
        "Workspace",
        ["Path", "Location"],
        [
            ["scans", SCANS_DIR.resolve()],
            ["logs", LOGS_DIR.resolve()],
            ["reports", REPORTS_DIR.resolve()],
            ["chats", CHATS_DIR.resolve()],
            ["data", DATA_DIR.resolve()],
            ["database", DB_FILE.resolve()],
            ["findings mirror", FINDINGS_FILE.resolve()],
            ["allowlist", ALLOWED_TARGETS_FILE.resolve()],
        ],
    )


def cmd_model() -> None:
    config = load_config()
    rows = [
        [profile, config["models"].get(profile, MODEL_NAME)]
        for profile in MODEL_PROFILES
    ]
    ui_table("Ollama Model Profiles", ["Profile", "Model"], rows)
    ui_print("Use /config model <chat|analysis|explain|all> <model> to change profiles.", "dim")
    print()


def cmd_config(args: list[str]) -> None:
    if not args or args[0] == "show":
        cmd_model()
        print(f"Config file: {CONFIG_FILE}")
        return

    action = args[0]

    if action == "reset":
        if len(args) != 1:
            print("Usage: /config reset")
            return

        save_config(default_config())
        print("Model profiles reset to the default Blue Jay role models.")
        return

    if action != "model":
        print("Usage: /config show")
        print("Usage: /config model <chat|analysis|explain|all> <model>")
        print("Usage: /config reset")
        return

    if len(args) != 3:
        print("Usage: /config model <chat|analysis|explain|all> <model>")
        print("Example: /config model analysis deepseek-r1:14b")
        return

    profile_selector = args[1].lower().strip()
    model_name = args[2].strip()

    if not validate_model_name(model_name):
        print("Model names can contain letters, numbers, dots, underscores, hyphens, slashes, and tags such as qwen3:8b.")
        return

    config = load_config()

    if profile_selector == "all":
        for profile in MODEL_PROFILES:
            config["models"][profile] = model_name
        save_config(config)
        print(f"All model profiles now use: {model_name}")
        return

    profile = normalize_model_profile(profile_selector)

    if profile is None:
        print("Unknown model profile. Use one of: chat, analysis, explain, all.")
        return

    config["models"][profile] = model_name
    save_config(config)
    print(f"Model profile '{profile}' now uses: {model_name}")


def cmd_chatlog(chat_path: Path) -> None:
    ui_key_values(
        "Chat Log",
        [
            ("Current transcript", chat_path),
            ("Context budget", f"{CHAT_CONTEXT_CHARS} characters"),
            ("Stored context turns", CHAT_HISTORY_LIMIT),
        ],
    )


def cmd_resume(args: list[str]) -> Path | None:
    sessions = list_chat_sessions()

    if not sessions:
        print("No saved chat transcripts found.")
        return None

    ui_table(
        "Saved Chats",
        ["#", "Modified", "Messages", "Preview", "File"],
        [
            [
                index,
                session["modified"],
                session["messages"],
                session["preview"],
                session["name"],
            ]
            for index, session in enumerate(sessions, start=1)
        ],
    )

    if len(args) > 1:
        print("Usage: /resume [number|file]")
        return None

    if args:
        selector = args[0]

        if selector.isdigit():
            index = int(selector) - 1
            if index < 0 or index >= len(sessions):
                print("Invalid chat number.")
                return None
            return sessions[index]["path"]

        for session in sessions:
            if session["name"] == selector:
                return session["path"]

        print("Chat file not found in recent saved chats.")
        return None

    selected_path = select_chat_session(sessions)

    if selected_path is None:
        print("Resume cancelled.")
        return None

    return selected_path


def cmd_files() -> None:
    files = list_files()

    if not files:
        print("No files found in scans/ or logs/.")
        return

    ui_table(
        "Available Files",
        ["#", "Path"],
        [[index, file_path] for index, file_path in enumerate(files, start=1)],
    )


def cmd_reports() -> None:
    reports = list_reports()

    if not reports:
        print("No reports found yet.")
        return

    ui_table(
        "Recent Reports",
        ["#", "Report", "Modified"],
        [
            [
                index,
                report.name,
                datetime.fromtimestamp(report.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            ]
            for index, report in enumerate(reports[:10], start=1)
        ],
    )
    ui_print("Use /view <number> to open one.", "dim")
    print()


def cmd_clear() -> None:
    print("\033c", end="")


def cmd_about() -> None:
    ui_panel(
        "Blue Jay",
        "Local LLM-powered cyber security assistant for authorised environments.",
    )
    ui_markdown(
        """
## What It Helps Analyse

- Nmap scans and structured Nmap XML
- Stored findings, evidence, assets, and scan history
- Saved baselines and current-vs-baseline diffs
- Optional Nuclei JSONL results
- DNS, HTTP headers, TLS, cookies, and bounded site crawl checks
- SSH/auth logs, web server logs, firewall logs, and general security notes
- Normal defensive-security chat questions

## Local Workflow

Use `/scan`, `/vuln`, `/dig`, `/web`, `/site`, and `/profile` to run controlled workflows. Blue Jay stores assets, scans, findings, evidence, and status in SQLite. Use `/baseline` and `/diff` to track what changed after fixes or new scans. Plain text at the prompt is saved as a local chat transcript and sent to the configured local Ollama model.

## Safety Design

- Scans are limited to localhost, private LAN IPs, and allowlisted targets.
- Public targets must be manually added to `allowed_targets.txt`.
- Inputs are passed to tools without a shell.
- File analysis is limited to files inside this project folder.
- Findings are evidence records; model prose should be reviewed by a human.
- Long-running scans and model calls have timeouts.

Reports are saved as Markdown in `reports/`.
"""
    )

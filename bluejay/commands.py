import shlex
from pathlib import Path

from .chat import create_chat_path
from .cmd_findings import (
    cmd_asset,
    cmd_assets,
    cmd_baseline,
    cmd_diff,
    cmd_explain,
    cmd_finding,
    cmd_findings,
    cmd_history,
    cmd_next,
    cmd_remediate,
    cmd_report,
    cmd_retest,
    cmd_set_finding_status,
    cmd_triage,
    cmd_view,
)
from .cmd_system import (
    cmd_about,
    cmd_allowed,
    cmd_chatlog,
    cmd_clear,
    cmd_config,
    cmd_files,
    cmd_help,
    cmd_model,
    cmd_reports,
    cmd_resume,
    cmd_status,
)
from .cmd_workflows import (
    cmd_analyse,
    cmd_dig,
    cmd_nuclei,
    cmd_profile,
    cmd_scan,
    cmd_site,
    cmd_vuln,
    cmd_web,
)
from .ui import print_banner


def handle_command(command_line: str, chat_path: Path) -> tuple[bool, Path]:
    try:
        parts = shlex.split(command_line)
    except ValueError as error:
        print(f"Command error: {error}")
        return True, chat_path

    if not parts:
        return True, chat_path

    command = parts[0]
    args = parts[1:]

    if command == "/":
        cmd_help()
    elif command == "/help":
        cmd_help()
    elif command == "/files":
        cmd_files()
    elif command == "/allowed":
        cmd_allowed()
    elif command == "/status":
        cmd_status()
    elif command == "/model":
        cmd_model()
    elif command == "/config":
        cmd_config(args)
    elif command == "/newchat":
        chat_path = create_chat_path()
        print(f"Started new chat transcript: {chat_path}")
    elif command == "/resume":
        resumed_path = cmd_resume(args)
        if resumed_path is not None:
            chat_path = resumed_path
            print(f"Resumed chat transcript: {chat_path}")
    elif command == "/chatlog":
        cmd_chatlog(chat_path)
    elif command == "/dig":
        cmd_dig(args)
    elif command == "/web":
        cmd_web(args)
    elif command == "/site":
        cmd_site(args)
    elif command == "/nuclei":
        cmd_nuclei(args)
    elif command == "/profile":
        cmd_profile(args)
    elif command == "/scan":
        cmd_scan(args)
    elif command == "/vuln":
        cmd_vuln(args)
    elif command == "/analyse":
        cmd_analyse(args)
    elif command == "/reports":
        cmd_reports()
    elif command == "/assets":
        cmd_assets(args)
    elif command == "/asset":
        cmd_asset(args)
    elif command == "/history":
        cmd_history(args)
    elif command == "/findings":
        cmd_findings(args)
    elif command == "/finding":
        cmd_finding(args)
    elif command == "/triage":
        cmd_triage(args)
    elif command == "/next":
        cmd_next(args)
    elif command == "/remediate":
        cmd_remediate(args)
    elif command == "/explain":
        cmd_explain(args)
    elif command == "/retest":
        cmd_retest(args)
    elif command == "/baseline":
        cmd_baseline(args)
    elif command == "/diff":
        cmd_diff(args)
    elif command == "/resolve":
        cmd_set_finding_status(args, "resolved", "resolve")
    elif command == "/reopen":
        cmd_set_finding_status(args, "open", "reopen")
    elif command == "/report":
        cmd_report(args)
    elif command == "/view":
        cmd_view(args)
    elif command == "/clear":
        cmd_clear()
        print_banner()
    elif command == "/about":
        cmd_about()
    elif command == "/exit":
        print("Blue Jay closed.")
        return False, chat_path
    else:
        print(f"Unknown command: {command}")
        print("Type /help to see available commands.")

    return True, chat_path

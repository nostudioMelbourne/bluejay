import shlex
from collections.abc import Callable
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


CommandHandler = Callable[[list[str]], None]
NoArgCommandHandler = Callable[[], None]


NO_ARG_COMMANDS: dict[str, NoArgCommandHandler] = {
    "/": cmd_help,
    "/help": cmd_help,
    "/files": cmd_files,
    "/allowed": cmd_allowed,
    "/status": cmd_status,
    "/model": cmd_model,
    "/reports": cmd_reports,
    "/about": cmd_about,
}

ARG_COMMANDS: dict[str, CommandHandler] = {
    "/config": cmd_config,
    "/dig": cmd_dig,
    "/web": cmd_web,
    "/site": cmd_site,
    "/nuclei": cmd_nuclei,
    "/profile": cmd_profile,
    "/scan": cmd_scan,
    "/vuln": cmd_vuln,
    "/analyse": cmd_analyse,
    "/assets": cmd_assets,
    "/asset": cmd_asset,
    "/history": cmd_history,
    "/findings": cmd_findings,
    "/finding": cmd_finding,
    "/triage": cmd_triage,
    "/next": cmd_next,
    "/remediate": cmd_remediate,
    "/explain": cmd_explain,
    "/retest": cmd_retest,
    "/baseline": cmd_baseline,
    "/diff": cmd_diff,
    "/report": cmd_report,
    "/view": cmd_view,
}


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

    if command in NO_ARG_COMMANDS:
        NO_ARG_COMMANDS[command]()
    elif command in ARG_COMMANDS:
        ARG_COMMANDS[command](args)
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
    elif command == "/resolve":
        cmd_set_finding_status(args, "resolved", "resolve")
    elif command == "/reopen":
        cmd_set_finding_status(args, "open", "reopen")
    elif command == "/clear":
        cmd_clear()
        print_banner()
    elif command == "/exit":
        print("Blue Jay closed.")
        return False, chat_path
    else:
        print(f"Unknown command: {command}")
        print("Type /help to see available commands.")

    return True, chat_path

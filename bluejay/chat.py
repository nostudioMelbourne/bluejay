import json
import re
import sys
from datetime import datetime
from pathlib import Path

from .constants import CHATS_DIR, CHAT_HISTORY_LIMIT
from .optional_deps import PROMPT_TOOLKIT_AVAILABLE, radiolist_dialog


def create_chat_path() -> Path:
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    return CHATS_DIR / f"chat-{timestamp}.jsonl"


def append_chat_message(chat_path: Path, role: str, content: str) -> None:
    entry = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "role": role,
        "content": content,
    }

    with chat_path.open("a", encoding="utf-8") as chat_file:
        chat_file.write(json.dumps(entry) + "\n")


def summarize_chat_session(chat_path: Path) -> dict:
    messages = []

    if chat_path.exists():
        for line in chat_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue

            role = str(entry.get("role", "")).strip()
            content = str(entry.get("content", "")).strip()

            if role in {"user", "assistant"} and content:
                messages.append(entry)

    first_user = next(
        (
            str(entry.get("content", "")).strip()
            for entry in messages
            if entry.get("role") == "user"
        ),
        "",
    )
    preview = re.sub(r"\s+", " ", first_user)[:80] or "(no user message)"
    modified = datetime.fromtimestamp(chat_path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")

    return {
        "path": chat_path,
        "name": chat_path.name,
        "modified": modified,
        "messages": len(messages),
        "preview": preview,
    }


def list_chat_sessions(limit: int = 20) -> list[dict]:
    sessions = [
        summarize_chat_session(path)
        for path in sorted(
            CHATS_DIR.glob("chat-*.jsonl"),
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        )
        if path.is_file()
    ]

    sessions = [session for session in sessions if session["messages"] > 0]
    return sessions[:limit]


def select_chat_session(sessions: list[dict]) -> Path | None:
    if not sessions:
        return None

    if (
        PROMPT_TOOLKIT_AVAILABLE
        and radiolist_dialog is not None
        and sys.stdin.isatty()
        and sys.stdout.isatty()
    ):
        values = [
            (
                str(index),
                f"{index}. {session['modified']} | {session['messages']} messages | {session['preview']}",
            )
            for index, session in enumerate(sessions, start=1)
        ]
        selected = radiolist_dialog(
            title="Resume chat",
            text="Choose a saved Blue Jay chat transcript.",
            values=values,
        ).run()

        if selected is None:
            return None

        return sessions[int(selected) - 1]["path"]

    if not sys.stdin.isatty():
        print("Use /resume <number> in non-interactive mode.")
        return None

    choice = input("Resume chat number: ").strip()

    if not choice.isdigit():
        return None

    index = int(choice) - 1
    if index < 0 or index >= len(sessions):
        return None

    return sessions[index]["path"]


def load_chat_history(chat_path: Path) -> list[tuple[str, str]]:
    if not chat_path.exists():
        return []

    history = []

    for line in chat_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        role = str(entry.get("role", "")).strip()
        content = str(entry.get("content", "")).strip()

        if role in {"user", "assistant"} and content:
            history.append((role, content))

    return history[-CHAT_HISTORY_LIMIT:]

from pathlib import Path

from .chat import append_chat_message, create_chat_path, load_chat_history
from .commands import handle_command
from .model import chat_with_model
from .ui import (
    create_prompt_session,
    print_banner,
    ui_heading,
    read_command_line,
    setup_readline,
    ui_markdown,
    ui_status,
    ui_table,
)
from .workspace import ensure_dirs


def handle_chat(message: str, chat_path: Path) -> None:
    append_chat_message(chat_path, "user", message)
    history = load_chat_history(chat_path)

    with ui_status("Blue Jay is thinking..."):
        response = chat_with_model(message, history[:-1])

    if response.startswith("Error:"):
        print(response)
        return

    append_chat_message(chat_path, "assistant", response)
    ui_heading("Blue Jay")
    ui_markdown(response)
    print()


def main() -> None:
    ensure_dirs()
    setup_readline()
    print_banner()

    running = True
    chat_path = create_chat_path()
    prompt_session = create_prompt_session()
    ui_table(
        "Session",
        ["Item", "Value"],
        [
            ["Chat transcript", chat_path],
            ["Command menu", "Type / and use arrows" if prompt_session is not None else "Tab completion"],
            ["Mode", "plain text chats, slash commands run tools"],
        ],
    )

    while running:
        try:
            command_line = read_command_line(prompt_session)
        except KeyboardInterrupt:
            print("\nBlue Jay closed.")
            break
        except EOFError:
            print("\nBlue Jay closed.")
            break

        if not command_line:
            continue

        if not command_line.startswith("/"):
            handle_chat(command_line, chat_path)
            continue

        running, chat_path = handle_command(command_line, chat_path)

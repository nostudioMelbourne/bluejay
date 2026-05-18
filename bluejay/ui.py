import atexit
import os
import shutil
import sys
from contextlib import contextmanager

from .constants import COMMAND_NAMES, COMMANDS, HISTORY_FILE
from .optional_deps import (
    CompleteStyle,
    Completer,
    Completion,
    Console,
    FileHistory,
    KeyBindings,
    Markdown,
    PROMPT_TOOLKIT_AVAILABLE,
    Panel,
    PromptSession,
    RICH_AVAILABLE,
    Style,
    Table,
)

CONSOLE = Console() if RICH_AVAILABLE else None

STYLE_ALIASES = {
    "primary": "bold cyan",
    "muted": "dim",
    "success": "bold green",
    "warning": "bold yellow",
    "danger": "bold red",
}


def resolve_style(style: str | None) -> str | None:
    if style is None:
        return None
    return STYLE_ALIASES.get(style, style)


def ansi_code_for_style(style: str | None) -> str | None:
    if style is None:
        return None
    if "green" in style:
        return "1;32"
    if "red" in style:
        return "1;31"
    if "yellow" in style:
        return "1;33"
    if "cyan" in style or "bold" in style:
        return "1;36"
    if style == "dim":
        return "2"
    return None


def supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def ansi(text: str, code: str) -> str:
    if not supports_color():
        return text
    return f"\033[{code}m{text}\033[0m"


def ui_print(message: str = "", style: str | None = None) -> None:
    style = resolve_style(style)

    if RICH_AVAILABLE and CONSOLE is not None:
        CONSOLE.print(message, style=style)
        return

    code = ansi_code_for_style(style)
    if code is not None:
        print(ansi(message, code))
    else:
        print(message)


def ui_panel(title: str, body: str, style: str = "cyan") -> None:
    style = resolve_style(style) or "cyan"

    if RICH_AVAILABLE and CONSOLE is not None and Panel is not None:
        CONSOLE.print(Panel(body, title=title, border_style=style, padding=(1, 2)))
        return

    width = max(50, min(88, shutil.get_terminal_size((88, 24)).columns))
    border = "=" * width
    code = ansi_code_for_style(style) or "1;36"
    print()
    print(ansi(border, code))
    print(ansi(f" {title}", code))
    print(ansi(border, code))
    print(body)
    print(ansi(border, code))
    print()


def ui_heading(title: str, style: str = "cyan") -> None:
    style = resolve_style(style) or "cyan"

    if RICH_AVAILABLE and CONSOLE is not None:
        CONSOLE.rule(title, style=style)
        return

    width = max(50, min(88, shutil.get_terminal_size((88, 24)).columns))
    title_text = f" {title} "
    side = max(2, (width - len(title_text)) // 2)
    line = ("-" * side) + title_text + ("-" * side)
    code = ansi_code_for_style(style) or "1;36"
    print()
    print(ansi(line[:width], code))


def ui_table(title: str, columns: list[str], rows: list[list[object]]) -> None:
    if RICH_AVAILABLE and CONSOLE is not None and Table is not None:
        table = Table(
            title=title,
            title_style="bold cyan",
            header_style="bold cyan",
            border_style="cyan",
            row_styles=["", "dim"],
            expand=True,
        )
        for column in columns:
            table.add_column(column, overflow="fold")
        for row in rows:
            table.add_row(*(str(value) for value in row))
        CONSOLE.print(table)
        return

    print()
    ui_print(title, "bold cyan")

    string_rows = [[str(value) for value in row] for row in rows]
    widths = [
        max(
            len(columns[index]),
            *(len(row[index]) for row in string_rows),
        )
        for index in range(len(columns))
    ] if string_rows else [len(column) for column in columns]

    header = "  ".join(column.ljust(widths[index]) for index, column in enumerate(columns))
    print(ansi(header, "1"))
    print("  ".join("-" * width for width in widths))
    for row in string_rows:
        print("  ".join(row[index].ljust(widths[index]) for index in range(len(columns))))
    print()


def ui_key_values(title: str, rows: list[tuple[str, object]], style: str = "cyan") -> None:
    ui_panel(title, "\n".join(f"{key}: {value}" for key, value in rows), style)


def ui_list(title: str, items: list[object], style: str = "cyan") -> None:
    if not items:
        ui_panel(title, "None", style)
        return

    body = "\n".join(f"- {item}" for item in items)
    ui_panel(title, body, style)


def ui_markdown(markdown_text: str) -> None:
    if RICH_AVAILABLE and CONSOLE is not None and Markdown is not None:
        CONSOLE.print(Markdown(markdown_text))
        return
    print(markdown_text)


@contextmanager
def ui_status(message: str):
    if RICH_AVAILABLE and CONSOLE is not None:
        with CONSOLE.status(message, spinner="dots"):
            yield
        return

    ui_print(message, "dim")
    yield


def setup_readline() -> None:
    try:
        import readline
    except ImportError:
        return

    HISTORY_FILE.parent.mkdir(exist_ok=True)

    if HISTORY_FILE.exists():
        try:
            readline.read_history_file(str(HISTORY_FILE))
        except OSError:
            pass

    def complete(text: str, state: int) -> str | None:
        options = [command for command in COMMAND_NAMES if command.startswith(text)]
        if state < len(options):
            return options[state]
        return None

    readline.set_completer(complete)
    readline.parse_and_bind("tab: complete")
    atexit.register(readline.write_history_file, str(HISTORY_FILE))


def create_prompt_session():
    if (
        not PROMPT_TOOLKIT_AVAILABLE
        or PromptSession is None
        or Completion is None
        or FileHistory is None
        or KeyBindings is None
        or Style is None
        or CompleteStyle is None
        or not sys.stdin.isatty()
        or not sys.stdout.isatty()
    ):
        return None

    class SlashCommandCompleter(Completer):
        def get_completions(self, document, complete_event):
            text = document.text_before_cursor

            if not text.startswith("/") or " " in text:
                return

            for command, args, description in COMMANDS:
                display = f"{command:<12} {args}".rstrip()

                if command.startswith(text):
                    yield Completion(
                        command + (" " if args else ""),
                        start_position=-len(text),
                        display=display,
                        display_meta=description,
                    )

    style = Style.from_dict(
        {
            "prompt": "ansicyan bold",
            "completion-menu.completion": "bg:#1f2937 #d1d5db",
            "completion-menu.completion.current": "bg:#06b6d4 #111827 bold",
            "completion-menu.meta.completion": "bg:#111827 #9ca3af",
            "completion-menu.meta.completion.current": "bg:#0891b2 #111827",
            "scrollbar.background": "bg:#111827",
            "scrollbar.button": "bg:#06b6d4",
        }
    )
    key_bindings = KeyBindings()

    @key_bindings.add("enter")
    def _(event):
        buffer = event.current_buffer

        if buffer.complete_state and buffer.complete_state.current_completion:
            buffer.apply_completion(buffer.complete_state.current_completion)
            return

        buffer.validate_and_handle()

    @key_bindings.add("/")
    def _(event):
        buffer = event.current_buffer
        buffer.insert_text("/")

        if buffer.document.text_before_cursor == "/":
            buffer.start_completion(select_first=True)

    return PromptSession(
        history=FileHistory(str(HISTORY_FILE)),
        completer=SlashCommandCompleter(),
        complete_while_typing=True,
        complete_style=CompleteStyle.COLUMN,
        reserve_space_for_menu=10,
        complete_in_thread=True,
        key_bindings=key_bindings,
        style=style,
    )


def read_command_line(prompt_session) -> str:
    if prompt_session is not None:
        return prompt_session.prompt(
            [
                ("class:prompt", "bluejay"),
                ("", " > "),
            ]
        ).strip()

    return input(prompt_text()).strip()


def prompt_text() -> str:
    return ansi("bluejay", "1;36") + ansi(" > ", "2")


def print_banner() -> None:
    ui_panel(
        "Blue Jay",
        "Local AI Security Workbench\n\nType normally to chat. Use /help for commands.",
        "cyan",
    )

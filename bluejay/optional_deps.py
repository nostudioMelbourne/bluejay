try:
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    RICH_AVAILABLE = True
except ImportError:
    Console = None
    Markdown = None
    Panel = None
    Table = None
    Text = None
    RICH_AVAILABLE = False

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import Completer, Completion
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.key_binding import KeyBindings
    from prompt_toolkit.shortcuts import CompleteStyle, radiolist_dialog
    from prompt_toolkit.styles import Style

    PROMPT_TOOLKIT_AVAILABLE = True
except ImportError:
    PromptSession = None
    Completer = object
    Completion = None
    FileHistory = None
    KeyBindings = None
    radiolist_dialog = None
    Style = None
    CompleteStyle = None
    PROMPT_TOOLKIT_AVAILABLE = False

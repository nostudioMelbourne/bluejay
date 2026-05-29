"""Guidance for the external command-line tools Blue Jay shells out to.

Centralises the "this tool is missing" message so every workflow names the
tool consistently and offers macOS and Linux install hints. This module is pure
standard library; it adds no runtime dependencies.
"""

# Friendly display names for tools whose command name is not capitalised nicely.
_DISPLAY_NAMES = {
    "nmap": "Nmap",
    "ollama": "Ollama",
    "dig": "dig",
}

# Install hints per tool, keyed by an OS label.
TOOL_INSTALL_HINTS: dict[str, dict[str, str]] = {
    "nmap": {
        "macOS": "brew install nmap",
        "Linux": "sudo apt install nmap   (Debian/Kali/Ubuntu, or use your distro's package manager)",
    },
    "ollama": {
        "macOS": "download from https://ollama.com/download   (or: brew install ollama)",
        "Linux": "curl -fsSL https://ollama.com/install.sh | sh   (or download from https://ollama.com/download)",
    },
    "dig": {
        "macOS": "brew install bind   (provides dig)",
        "Linux": "sudo apt install dnsutils   (Debian/Kali/Ubuntu; bind-utils on Fedora/RHEL)",
    },
}


def tool_display_name(tool: str) -> str:
    """Return a human-friendly name for a tool, falling back to its command."""
    return _DISPLAY_NAMES.get(tool, tool)


def missing_tool_message(tool: str, *, optional: bool = False) -> str:
    """Build a multi-line help message for a missing external tool.

    The first line names the tool and notes it was not found in PATH. Optional
    tools are labelled as optional so users know Blue Jay still works without
    them. Remaining lines list macOS and Linux install hints when known.
    """
    display = tool_display_name(tool)
    suffix = " (optional)" if optional else ""
    lines = [f"{display} is not installed or not available in PATH{suffix}."]

    hints = TOOL_INSTALL_HINTS.get(tool)
    if hints:
        lines.append("Install it with:")
        lines.extend(f"  {os_label}: {command}" for os_label, command in hints.items())

    return "\n".join(lines)

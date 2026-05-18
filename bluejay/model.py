import subprocess
import re
from pathlib import Path

from .config import configured_model
from .constants import (
    CHAT_CONTEXT_CHARS,
    CHAT_HISTORY_LIMIT,
    MAX_CHAT_CHARS,
    MODEL_NAME,
    OLLAMA_TIMEOUT_SECONDS,
)


ANSI_PATTERN = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def clean_model_output(text: str) -> str:
    cleaned = ANSI_PATTERN.sub("", text)
    cleaned = re.sub(
        r"(?is)<think>.*?</think>\s*",
        "",
        cleaned,
    )
    cleaned = re.sub(
        r"(?is)\bThinking\.\.\..*?\.\.\.done thinking\.\s*",
        "",
        cleaned,
    )
    cleaned = cleaned.replace("\x1b[?2026h", "").replace("\x1b[?2026l", "")
    cleaned = cleaned.replace("\x1b[?25l", "").replace("\x1b[?25h", "")
    return cleaned.strip()


def build_prompt(file_path: Path, content: str, mode: str) -> str:
    return f"""
You are Blue Jay, a local defensive cybersecurity assistant.

The user is analysing a file from their own authorised lab, home network, or learning environment.

Analysis mode: {mode}
File name: {file_path.name}

Generate a clear Markdown security report using this structure:

# Blue Jay Security Report

## 1. Summary
Briefly explain what this file appears to show.

## 2. Key Findings
List the most important findings.

## 3. Technical Details
Explain relevant ports, services, log entries, IP addresses, errors, or suspicious patterns.
For vulnerability analysis, focus on likely exposure, outdated-looking services, missing encryption,
unsafe defaults, and defensive verification steps. Do not provide exploit instructions.
For DNS analysis, explain records, exposed infrastructure clues, and safe configuration checks.

## 4. Risk Level
Use one of: Low, Medium, High, or Unknown.
Explain why.

## 5. What This Means
Explain the result in beginner-friendly language.

## 6. Safe Defensive Next Steps
Give practical defensive steps only.

## 7. Hardening Checklist
Give a checklist the user can follow.

Important rules:
- Do not provide offensive exploitation steps.
- Do not suggest unauthorised access.
- Do not claim the system is secure based on one file.
- Be honest where there is not enough information.
- Keep the tone calm and practical.

File content:

{content}
	"""


def build_chat_prompt(message: str, history: list[tuple[str, str]]) -> str:
    history_lines = []
    context_size = 0

    for role, text in reversed(history[-CHAT_HISTORY_LIMIT:]):
        line = f"{role}: {text}"

        if context_size + len(line) > CHAT_CONTEXT_CHARS:
            break

        history_lines.append(line)
        context_size += len(line)

    history_lines.reverse()

    history_text = "\n".join(history_lines) or "No previous chat in this session."

    return f"""
You are Blue Jay, a local defensive cybersecurity and pentesting assistant.

The user is chatting with you inside the Blue Jay CLI. You can explain concepts,
help plan authorised assessments, interpret security results the user pastes in,
suggest safe next steps, and point them to Blue Jay slash commands.

Important boundaries:
- Assume the user intends legal, authorised testing, but keep guidance defensive and responsible.
- Do not provide instructions for unauthorised access, malware, credential theft, evasion,
  persistence, phishing, destructive actions, or stealth.
- Do not claim you ran scans or tools. You can only chat. The Python CLI handles tools through slash commands.
- If the user wants tool output, suggest the relevant Blue Jay command such as /scan, /vuln, /dig, or /analyse.
- Keep answers practical, clear, and beginner-friendly unless the user asks for deeper detail.

Recent chat:
{history_text}

User:
{message}
"""


def run_ollama(prompt: str, model_name: str | None = None) -> str:
    active_model = model_name or MODEL_NAME

    try:
        result = subprocess.run(
            ["ollama", "run", active_model],
            input=prompt,
            text=True,
            capture_output=True,
            timeout=OLLAMA_TIMEOUT_SECONDS,
        )
    except FileNotFoundError:
        return "Error: Ollama is not installed or not available in PATH."
    except subprocess.TimeoutExpired:
        return f"Error: Ollama model '{active_model}' timed out while generating the report."

    if result.returncode != 0:
        return f"Error: Ollama model '{active_model}' returned an error.\n{result.stderr.strip()}"

    return clean_model_output(result.stdout)


def chat_with_model(message: str, history: list[tuple[str, str]]) -> str:
    clean_message = message.strip()

    if len(clean_message) > MAX_CHAT_CHARS:
        return f"Error: Chat message is too long. Current limit: {MAX_CHAT_CHARS} characters."

    prompt = build_chat_prompt(clean_message, history)
    return run_ollama(prompt, configured_model("chat"))

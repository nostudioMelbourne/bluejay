from datetime import datetime
from pathlib import Path

from .config import configured_model
from .constants import LOGS_DIR, MAX_ANALYSIS_BYTES, REPORTS_DIR, SCANS_DIR, VALID_MODES
from .model import build_prompt, run_ollama
from .ui import ui_markdown, ui_panel, ui_status
from .utils import resolve_project_file, slugify


def save_report(input_file: Path, report: str) -> Path:
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_name = slugify(input_file.stem)
    report_path = REPORTS_DIR / f"{safe_name}-report-{timestamp}.md"
    report_path.write_text(report, encoding="utf-8")
    return report_path


def list_files() -> list[Path]:
    files = []

    for folder in [SCANS_DIR, LOGS_DIR]:
        if folder.exists():
            files.extend(path for path in folder.iterdir() if path.is_file())

    return sorted(files)


def list_reports() -> list[Path]:
    return sorted(
        REPORTS_DIR.glob("*.md"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )


def analyse_file(file_path: Path, mode: str) -> None:
    if mode not in VALID_MODES:
        print(f"Invalid mode: {mode}")
        print("Valid modes: nmap, vulnerability, dns, web-check, auth-log, web-log, firewall-log, general")
        return

    resolved_path = resolve_project_file(file_path)

    if resolved_path is None:
        print("File blocked.")
        print("Blue Jay only analyses files inside this project folder.")
        return

    if not resolved_path.exists():
        print(f"File not found: {file_path}")
        return

    if not resolved_path.is_file():
        print(f"Not a file: {file_path}")
        return

    file_size = resolved_path.stat().st_size
    if file_size > MAX_ANALYSIS_BYTES:
        print(f"File is too large to analyse safely ({file_size} bytes).")
        print(f"Current limit: {MAX_ANALYSIS_BYTES} bytes.")
        return

    content = resolved_path.read_text(encoding="utf-8", errors="ignore")

    if not content.strip():
        print("File is empty.")
        return

    print(f"\nAnalysing {resolved_path.relative_to(Path.cwd().resolve())} as {mode}...")

    prompt = build_prompt(resolved_path, content, mode)
    with ui_status("Running local model..."):
        report = run_ollama(prompt, configured_model("analysis"))

    if report.startswith("Error:"):
        print(report)
        return

    report_path = save_report(resolved_path, report)

    ui_panel("Blue Jay Report", "", "green")
    ui_markdown(report)
    print(f"Report saved to: {report_path}")
    print()

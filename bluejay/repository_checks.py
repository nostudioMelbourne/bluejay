import os
import re
from datetime import datetime
from pathlib import Path

from .constants import REPORTS_DIR
from .utils import slugify


MAX_REPOSITORY_FILES = 5_000
MAX_INSPECTED_FILE_BYTES = 1_000_000
IGNORED_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "venv",
}
MANIFEST_NAMES = {
    "cargo.lock",
    "cargo.toml",
    "go.mod",
    "go.sum",
    "package-lock.json",
    "package.json",
    "pipfile",
    "pipfile.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "pyproject.toml",
    "requirements.txt",
    "yarn.lock",
}
SAFE_ENV_SUFFIXES = {".dist", ".example", ".sample", ".template"}


def _is_manifest(name: str) -> bool:
    lowered = name.lower()
    return lowered in MANIFEST_NAMES or (
        lowered.startswith("requirements") and lowered.endswith(".txt")
    )


def _is_secret_env_file(name: str) -> bool:
    lowered = name.lower()
    return lowered.startswith(".env") and not any(
        lowered.endswith(suffix) for suffix in SAFE_ENV_SUFFIXES
    )


def inspect_repository(root: Path) -> str:
    """Return a bounded, local-only inventory and set of repository checks."""
    root = root.resolve()
    manifests: list[str] = []
    dockerfiles: list[Path] = []
    env_files: list[str] = []
    visited_files = 0
    truncated = False

    for current_root, directories, filenames in os.walk(root, followlinks=False):
        directories[:] = sorted(
            name for name in directories
            if name not in IGNORED_DIRECTORIES
            and not (Path(current_root) / name).is_symlink()
        )
        for filename in sorted(filenames):
            file_path = Path(current_root) / filename
            if file_path.is_symlink():
                continue
            visited_files += 1
            if visited_files > MAX_REPOSITORY_FILES:
                truncated = True
                break

            relative_path = file_path.relative_to(root).as_posix()
            if _is_manifest(filename):
                manifests.append(relative_path)
            if filename.lower() == "dockerfile" or filename.lower().startswith("dockerfile."):
                dockerfiles.append(file_path)
            if _is_secret_env_file(filename):
                env_files.append(relative_path)

        if truncated:
            break

    findings: list[str] = []
    if env_files:
        findings.append(
            "Review environment files that may contain secrets: "
            + ", ".join(f"`{path}`" for path in env_files)
        )

    for dockerfile in dockerfiles:
        try:
            if dockerfile.stat().st_size > MAX_INSPECTED_FILE_BYTES:
                continue
            contents = dockerfile.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        relative_path = dockerfile.relative_to(root).as_posix()
        from_lines = [
            line.strip() for line in contents.splitlines()
            if re.match(r"^\s*FROM\s+", line, re.IGNORECASE)
        ]
        if any(re.search(r":latest(?:\s|$|@)", line, re.IGNORECASE) for line in from_lines):
            findings.append(f"`{relative_path}` uses a `latest` base-image tag; pin a reviewed version or digest.")

        user_lines = [
            line.strip() for line in contents.splitlines()
            if re.match(r"^\s*USER\s+", line, re.IGNORECASE)
        ]
        if not user_lines or any(
            re.match(r"USER\s+(?:0|root)(?:\s|$)", line, re.IGNORECASE)
            for line in user_lines
        ):
            findings.append(f"`{relative_path}` may run the application as root; review its final `USER` setting.")

    lines = [
        "# Blue Jay Repository Checks",
        "",
        f"Generated: {datetime.now().isoformat(timespec='seconds')}",
        f"Repository: `{root.name or root}`",
        f"Files inspected: {min(visited_files, MAX_REPOSITORY_FILES)}",
        "",
        "## Dependency and Build Files",
        "",
    ]
    if manifests:
        lines.extend(f"- `{path}`" for path in manifests)
    else:
        lines.append("No supported dependency or build manifests were found.")

    lines.extend(["", "## Review Items", ""])
    if findings:
        lines.extend(f"- {finding}" for finding in findings)
    else:
        lines.append("No issues were identified by these local checks.")
    if truncated:
        lines.extend(["", f"Traversal stopped at the {MAX_REPOSITORY_FILES}-file limit."])
    lines.extend([
        "",
        "These checks are heuristic and do not replace dependency or container scanners.",
        "",
    ])
    return "\n".join(lines)


def run_repository_checks(root: Path) -> Path:
    report = inspect_repository(root)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    report_path = REPORTS_DIR / f"repo-checks-{slugify(root.name)}-{timestamp}.md"
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report, encoding="utf-8")
    print(report)
    print(f"Repository check report saved to: {report_path}")
    return report_path
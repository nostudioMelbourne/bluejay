import json
import re
from datetime import datetime
from pathlib import Path


def now_timestamp() -> str:
    return datetime.now().isoformat(timespec="seconds")


def json_dumps(value: object) -> str:
    return json.dumps(value, sort_keys=True)


def json_loads(value: str, fallback: object) -> object:
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return fallback


def slugify(value: str) -> str:
    safe_value = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip().lower())
    return safe_value.strip("-") or "bluejay"


def resolve_project_file(file_path: Path) -> Path | None:
    try:
        resolved_path = file_path.expanduser().resolve()
        project_root = Path.cwd().resolve()
        resolved_path.relative_to(project_root)
    except (RuntimeError, ValueError):
        return None

    return resolved_path

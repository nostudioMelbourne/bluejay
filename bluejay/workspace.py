from .constants import (
    ALLOWED_TARGETS_FILE,
    BASELINES_DIR,
    CHATS_DIR,
    DATA_DIR,
    LOGS_DIR,
    REPORTS_DIR,
    SCANS_DIR,
)
from .storage import init_database


def ensure_dirs() -> None:
    SCANS_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    CHATS_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    BASELINES_DIR.mkdir(parents=True, exist_ok=True)

    if not ALLOWED_TARGETS_FILE.exists():
        ALLOWED_TARGETS_FILE.write_text(
            "# Blue Jay authorised scan targets\n"
            "# Add one target per line.\n\n"
            "scanme.nmap.org\n"
            "localhost\n"
            "127.0.0.1\n",
            encoding="utf-8",
        )

    init_database()

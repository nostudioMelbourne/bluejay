import hashlib
import json
import re
import sqlite3
from datetime import datetime
from pathlib import Path

from .constants import DB_FILE, FINDINGS_FILE, SEVERITY_ORDER
from .utils import json_dumps, json_loads, now_timestamp, slugify


def db_connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_FILE)
    connection.row_factory = sqlite3.Row
    return connection


def init_database() -> None:
    with db_connect() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS assets (
                target TEXT PRIMARY KEY,
                asset_type TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                metadata TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                target TEXT NOT NULL,
                profile TEXT NOT NULL,
                tool TEXT NOT NULL,
                status TEXT NOT NULL,
                command TEXT NOT NULL,
                output_path TEXT NOT NULL,
                xml_path TEXT NOT NULL,
                metadata TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                status TEXT NOT NULL,
                target TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                type TEXT NOT NULL,
                confidence TEXT NOT NULL,
                evidence TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                cves TEXT NOT NULL,
                source TEXT NOT NULL,
                metadata TEXT NOT NULL,
                times_seen INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                source TEXT NOT NULL,
                content TEXT NOT NULL,
                FOREIGN KEY(finding_id) REFERENCES findings(id)
            );

            CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
            CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
            """
        )
    migrate_jsonl_findings()


def get_metadata_value(key: str) -> str | None:
    with db_connect() as connection:
        row = connection.execute(
            "SELECT value FROM metadata WHERE key = ?",
            (key,),
        ).fetchone()

    return str(row["value"]) if row else None


def set_metadata_value(key: str, value: str) -> None:
    with db_connect() as connection:
        connection.execute(
            """
            INSERT INTO metadata(key, value)
            VALUES(?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, value),
        )


def finding_fingerprint(finding: dict) -> str:
    metadata = finding.get("metadata", {}) or {}
    stable_metadata = {
        key: metadata.get(key)
        for key in [
            "port",
            "protocol",
            "service",
            "script_id",
            "url",
            "missing_headers",
            "template_id",
            "matched_at",
        ]
        if key in metadata
    }
    basis = {
        "target": str(finding.get("target", "")).lower(),
        "type": str(finding.get("type", "")),
        "title": str(finding.get("title", "")).lower(),
        "cves": finding.get("cves", []),
        "metadata": stable_metadata,
    }
    digest = hashlib.sha256(json_dumps(basis).encode("utf-8")).hexdigest()
    return digest


def finding_from_row(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "fingerprint": row["fingerprint"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "status": row["status"],
        "target": row["target"],
        "title": row["title"],
        "severity": row["severity"],
        "type": row["type"],
        "confidence": row["confidence"],
        "evidence": row["evidence"],
        "recommendation": row["recommendation"],
        "cves": json_loads(row["cves"], []),
        "source": row["source"],
        "metadata": json_loads(row["metadata"], {}),
        "times_seen": row["times_seen"],
    }


def upsert_asset(target: str, asset_type: str = "host", metadata: dict | None = None) -> None:
    timestamp = now_timestamp()
    with db_connect() as connection:
        connection.execute(
            """
            INSERT INTO assets(target, asset_type, first_seen, last_seen, metadata)
            VALUES(?, ?, ?, ?, ?)
            ON CONFLICT(target) DO UPDATE SET
                asset_type = excluded.asset_type,
                last_seen = excluded.last_seen,
                metadata = excluded.metadata
            """,
            (target, asset_type, timestamp, timestamp, json_dumps(metadata or {})),
        )


def record_scan(
    target: str,
    profile: str,
    tool: str,
    status: str,
    command: list[str],
    output_path: Path | str = "",
    xml_path: Path | str = "",
    metadata: dict | None = None,
) -> None:
    scan_id = f"SCAN-{datetime.now().strftime('%Y%m%d%H%M%S%f')}-{slugify(target)[:24]}"
    upsert_asset(target)

    with db_connect() as connection:
        connection.execute(
            """
            INSERT INTO scans(
                id, created_at, target, profile, tool, status, command,
                output_path, xml_path, metadata
            )
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                now_timestamp(),
                target,
                profile,
                tool,
                status,
                " ".join(command),
                str(output_path),
                str(xml_path),
                json_dumps(metadata or {}),
            ),
        )


def migrate_jsonl_findings() -> None:
    if get_metadata_value("jsonl_findings_migrated") == "true":
        return

    if not FINDINGS_FILE.exists():
        set_metadata_value("jsonl_findings_migrated", "true")
        return

    migrated = []
    for line in FINDINGS_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
        try:
            finding = json.loads(line)
        except json.JSONDecodeError:
            continue

        if isinstance(finding, dict) and finding.get("id"):
            migrated.append(finding)

    if migrated:
        append_findings(migrated)
        with FINDINGS_FILE.open("w", encoding="utf-8") as findings_file:
            for finding in load_findings():
                findings_file.write(json.dumps(finding, sort_keys=True) + "\n")

    set_metadata_value("jsonl_findings_migrated", "true")


def extract_cves(text: str) -> list[str]:
    return sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text.upper())))


def make_finding(
    target: str,
    title: str,
    severity: str,
    finding_type: str,
    evidence: str,
    source: str,
    recommendation: str,
    confidence: str = "Medium",
    cves: list[str] | None = None,
    metadata: dict | None = None,
) -> dict:
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
    finding_id = f"GP-{timestamp}-{slugify(target)[:24]}"

    return {
        "id": finding_id,
        "created_at": now_timestamp(),
        "updated_at": now_timestamp(),
        "first_seen": now_timestamp(),
        "last_seen": now_timestamp(),
        "status": "open",
        "target": target,
        "title": title,
        "severity": severity,
        "type": finding_type,
        "confidence": confidence,
        "evidence": evidence,
        "recommendation": recommendation,
        "cves": cves or [],
        "source": source,
        "metadata": metadata or {},
        "times_seen": 1,
    }


def load_findings() -> list[dict]:
    with db_connect() as connection:
        rows = connection.execute(
            "SELECT * FROM findings"
        ).fetchall()

    return [finding_from_row(row) for row in rows]


def write_findings(findings: list[dict]) -> None:
    with db_connect() as connection:
        connection.execute("DELETE FROM evidence")
        connection.execute("DELETE FROM findings")

    append_findings(findings)

    with FINDINGS_FILE.open("w", encoding="utf-8") as findings_file:
        for finding in findings:
            findings_file.write(json.dumps(finding, sort_keys=True) + "\n")


def append_findings(findings: list[dict]) -> None:
    if not findings:
        return

    with db_connect() as connection:
        for finding in findings:
            timestamp = now_timestamp()
            target = str(finding.get("target", "unknown"))
            fingerprint = finding.get("fingerprint") or finding_fingerprint(finding)
            existing = connection.execute(
                "SELECT * FROM findings WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()

            connection.execute(
                """
                INSERT INTO assets(target, asset_type, first_seen, last_seen, metadata)
                VALUES(?, 'host', ?, ?, '{}')
                ON CONFLICT(target) DO UPDATE SET last_seen = excluded.last_seen
                """,
                (target, timestamp, timestamp),
            )

            if existing:
                finding_id = existing["id"]
                connection.execute(
                    """
                    UPDATE findings SET
                        updated_at = ?,
                        last_seen = ?,
                        status = 'open',
                        severity = ?,
                        confidence = ?,
                        evidence = ?,
                        recommendation = ?,
                        cves = ?,
                        source = ?,
                        metadata = ?,
                        times_seen = times_seen + 1
                    WHERE id = ?
                    """,
                    (
                        timestamp,
                        timestamp,
                        finding.get("severity", existing["severity"]),
                        finding.get("confidence", existing["confidence"]),
                        finding.get("evidence", existing["evidence"]),
                        finding.get("recommendation", existing["recommendation"]),
                        json_dumps(finding.get("cves", [])),
                        finding.get("source", existing["source"]),
                        json_dumps(finding.get("metadata", {})),
                        finding_id,
                    ),
                )
            else:
                finding_id = str(finding.get("id") or f"GP-{datetime.now().strftime('%Y%m%d%H%M%S%f')}-{slugify(target)[:24]}")
                connection.execute(
                    """
                    INSERT INTO findings(
                        id, fingerprint, created_at, updated_at, first_seen, last_seen,
                        status, target, title, severity, type, confidence, evidence,
                        recommendation, cves, source, metadata, times_seen
                    )
                    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        finding_id,
                        fingerprint,
                        finding.get("created_at", timestamp),
                        finding.get("updated_at", timestamp),
                        finding.get("first_seen", timestamp),
                        finding.get("last_seen", timestamp),
                        finding.get("status", "open"),
                        target,
                        finding.get("title", "Untitled finding"),
                        finding.get("severity", "Unknown"),
                        finding.get("type", "general"),
                        finding.get("confidence", "Medium"),
                        finding.get("evidence", ""),
                        finding.get("recommendation", ""),
                        json_dumps(finding.get("cves", [])),
                        finding.get("source", ""),
                        json_dumps(finding.get("metadata", {})),
                        int(finding.get("times_seen", 1)),
                    ),
                )

            connection.execute(
                """
                INSERT INTO evidence(finding_id, created_at, source, content)
                VALUES(?, ?, ?, ?)
                """,
                (
                    finding_id,
                    timestamp,
                    finding.get("source", ""),
                    str(finding.get("evidence", "")),
                ),
            )

    with FINDINGS_FILE.open("a", encoding="utf-8") as findings_file:
        for finding in findings:
            findings_file.write(json.dumps(finding, sort_keys=True) + "\n")


def record_findings(findings: list[dict], label: str) -> None:
    if not findings:
        print(f"No structured findings recorded from {label}.")
        return

    append_findings(findings)
    print(f"Recorded {len(findings)} structured finding(s) from {label}.")


def sorted_findings(findings: list[dict]) -> list[dict]:
    return sorted(
        findings,
        key=lambda finding: (
            SEVERITY_ORDER.get(str(finding.get("severity", "Unknown")), -1),
            str(finding.get("created_at", "")),
        ),
        reverse=True,
    )


def filter_findings(
    findings: list[dict],
    target: str | None = None,
    status: str | None = None,
) -> list[dict]:
    filtered = findings

    if target and target != "all":
        clean_target = target.lower()
        filtered = [
            finding for finding in filtered
            if str(finding.get("target", "")).lower() == clean_target
        ]

    if status and status != "all":
        filtered = [
            finding for finding in filtered
            if str(finding.get("status", "")).lower() == status.lower()
        ]

    return sorted_findings(filtered)


def load_assets() -> list[dict]:
    with db_connect() as connection:
        rows = connection.execute(
            "SELECT * FROM assets ORDER BY last_seen DESC"
        ).fetchall()

    return [
        {
            "target": row["target"],
            "asset_type": row["asset_type"],
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "metadata": json_loads(row["metadata"], {}),
        }
        for row in rows
    ]


def load_scan_history(target: str | None = None, limit: int = 20) -> list[dict]:
    with db_connect() as connection:
        if target:
            rows = connection.execute(
                """
                SELECT * FROM scans
                WHERE lower(target) = lower(?)
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (target, limit),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT * FROM scans
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

    return [
        {
            "id": row["id"],
            "created_at": row["created_at"],
            "target": row["target"],
            "profile": row["profile"],
            "tool": row["tool"],
            "status": row["status"],
            "command": row["command"],
            "output_path": row["output_path"],
            "xml_path": row["xml_path"],
            "metadata": json_loads(row["metadata"], {}),
        }
        for row in rows
    ]

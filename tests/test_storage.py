import tempfile
import unittest
from pathlib import Path

import bluejay.storage as storage


class StorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self._original_db_file = storage.DB_FILE
        self._original_findings_file = storage.FINDINGS_FILE
        self._temp_dir = tempfile.TemporaryDirectory()
        temp_path = Path(self._temp_dir.name)
        storage.DB_FILE = temp_path / "nested" / "bluejay.db"
        storage.FINDINGS_FILE = temp_path / "nested" / "findings.jsonl"

    def tearDown(self) -> None:
        storage.DB_FILE = self._original_db_file
        storage.FINDINGS_FILE = self._original_findings_file
        self._temp_dir.cleanup()

    def test_storage_initializes_missing_parent_directories(self) -> None:
        storage.init_database()

        self.assertTrue(storage.DB_FILE.exists())
        self.assertTrue(storage.DB_FILE.parent.exists())

    def test_append_and_load_findings_round_trip(self) -> None:
        storage.init_database()
        finding = storage.make_finding(
            target="localhost",
            title="Open service: 22/tcp ssh",
            severity="Low",
            finding_type="open-service",
            evidence="22/tcp open: ssh",
            source="scan.xml",
            recommendation="Confirm SSH is expected and patched.",
            confidence="High",
            metadata={"port": "22", "protocol": "tcp", "service": "ssh"},
        )

        storage.append_findings([finding])
        loaded = storage.load_findings()

        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0]["title"], finding["title"])
        self.assertEqual(loaded[0]["metadata"]["port"], "22")
        self.assertTrue(storage.FINDINGS_FILE.exists())

    def test_make_finding_uses_consistent_timestamps(self) -> None:
        finding = storage.make_finding(
            target="localhost",
            title="Test finding",
            severity="Info",
            finding_type="test",
            evidence="evidence",
            source="source",
            recommendation="recommendation",
        )

        self.assertEqual(finding["created_at"], finding["updated_at"])
        self.assertEqual(finding["created_at"], finding["first_seen"])
        self.assertEqual(finding["created_at"], finding["last_seen"])


if __name__ == "__main__":
    unittest.main()

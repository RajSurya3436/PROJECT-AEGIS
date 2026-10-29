"""Validate the bundled demo dataset: every record must normalize and match the manifest."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import DEMO_DATA_DIR, Settings
from app.ingestion.demo import ingest_demo, load_manifest
from app.ingestion.service import IngestionService
from app.storage.db import open_database


def main() -> int:
    manifest = load_manifest()
    conn = open_database(":memory:")
    service = IngestionService(conn, Settings())
    results = ingest_demo(service)
    ok = True
    for entry, result in zip(manifest["files"], results, strict=True):
        expected = entry["expected_records"]
        status = "OK " if result.inserted == expected and result.quarantined == 0 else "FAIL"
        ok &= status == "OK "
        print(
            f"{status} {entry['path']}: expected={expected} inserted={result.inserted} "
            f"quarantined={result.quarantined} duplicates={result.duplicates}"
        )
    ioc_rows = sum(
        1 for _ in (DEMO_DATA_DIR / "local_iocs.csv").read_text(encoding="utf-8").splitlines()[1:]
    )
    expected_iocs = manifest["ioc_files"][0]["expected_records"]
    print(f"{'OK ' if ioc_rows == expected_iocs else 'FAIL'} local_iocs.csv: {ioc_rows} rows")
    ok &= ioc_rows == expected_iocs
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

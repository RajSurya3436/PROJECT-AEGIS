"""Load a local IOC list (CSV) into the database."""

from __future__ import annotations

import csv
import io
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

from app.config import DEMO_DATA_DIR
from app.domain.models import Ioc
from app.ingestion.demo import load_manifest
from app.ingestion.parsers import decode_bytes
from app.storage.alerts import IocRepository

SUPPORTED_TYPES = frozenset({"ip", "domain", "sha256"})
MAX_IOC_ROWS = 100_000


@dataclass
class IocLoadResult:
    loaded: int = 0
    errors: list[str] = field(default_factory=list)


def parse_iocs(content: bytes) -> tuple[list[Ioc], list[str]]:
    iocs: list[Ioc] = []
    errors: list[str] = []
    reader = csv.DictReader(io.StringIO(decode_bytes(content)))
    for line, row in enumerate(reader, start=2):
        if line - 1 > MAX_IOC_ROWS:
            errors.append(f"stopped after {MAX_IOC_ROWS:,} rows")
            break
        indicator = (row.get("indicator") or "").strip()
        ioc_type = (row.get("type") or "").strip().lower()
        if not indicator or ioc_type not in SUPPORTED_TYPES:
            errors.append(f"line {line}: missing indicator or unsupported type {ioc_type!r}")
            continue
        if ioc_type == "ip":
            try:
                indicator = str(ipaddress.ip_address(indicator))
            except ValueError:
                errors.append(f"line {line}: invalid IP {indicator!r}")
                continue
        else:
            indicator = indicator.lower()
        iocs.append(
            Ioc(
                indicator=indicator,
                ioc_type=ioc_type,
                source=(row.get("source") or "unknown").strip() or "unknown",
                confidence=(row.get("confidence") or "medium").strip().lower() or "medium",
                description=(row.get("description") or "").strip(),
                added=(row.get("added") or "").strip() or None,
            )
        )
    return iocs, errors


def load_iocs(repo: IocRepository, content: bytes) -> IocLoadResult:
    iocs, errors = parse_iocs(content)
    return IocLoadResult(loaded=repo.upsert_many(iocs), errors=errors)


def load_demo_iocs(repo: IocRepository, demo_dir: Path = DEMO_DATA_DIR) -> IocLoadResult:
    result = IocLoadResult()
    for entry in load_manifest(demo_dir).get("ioc_files", []):
        part = load_iocs(repo, (demo_dir / entry["path"]).read_bytes())
        result.loaded += part.loaded
        result.errors.extend(part.errors)
    return result

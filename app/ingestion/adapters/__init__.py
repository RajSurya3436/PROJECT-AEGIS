"""Record adapters: reshape a vendor's records (a SIEM's alert JSON, say) into keys the alias
table understands, before normalisation. The record as received is always what is stored.

To support another SIEM, add an adapter here; every source (upload, file tail, HTTP) can use it.
"""

from __future__ import annotations

from app.domain.errors import UnsupportedInputError
from app.ingestion.adapters.base import GenericAdapter, RecordAdapter
from app.ingestion.adapters.wazuh import WazuhAlertAdapter

ADAPTERS: dict[str, RecordAdapter] = {
    adapter.name: adapter for adapter in (GenericAdapter(), WazuhAlertAdapter())
}


def get_adapter(name: str | None) -> RecordAdapter:
    adapter = ADAPTERS.get(name or "generic")
    if adapter is None:
        raise UnsupportedInputError(f"unknown adapter {name!r}; known: {', '.join(ADAPTERS)}")
    return adapter


__all__ = ["ADAPTERS", "GenericAdapter", "RecordAdapter", "WazuhAlertAdapter", "get_adapter"]

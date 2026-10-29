"""Offline indicator lookup against the local IOC list."""

from __future__ import annotations

import ipaddress

from app.domain.models import Ioc
from app.storage.alerts import IocRepository

IOC_TYPES = ("ip", "domain", "sha256")


def lookup_local_ioc(repo: IocRepository, indicator: str, ioc_type: str = "ip") -> Ioc | None:
    """Exact match after the same normalisation the IOC loader applies. Invalid input
    returns None rather than raising."""
    if ioc_type not in IOC_TYPES:
        raise ValueError(f"unsupported IOC type {ioc_type!r}")
    value = indicator.strip()
    if ioc_type == "ip":
        try:
            value = str(ipaddress.ip_address(value))
        except ValueError:
            return None
    else:
        value = value.lower()
    return repo.get(value, ioc_type) if value else None

"""The development lab scope (docs/lab.md), for the CLI and manual runs on Kali."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cybrx import config
from cybrx.scope import Scope


def lab_scope(authorised_by: str, hours: int = 4, now: datetime | None = None) -> Scope:
    """A scope covering the lab networks minus the lab deny-list, valid for `hours`.

    Example: lab_scope("Ahad") -> allow 192.168.56.0/24, deny .1 and .100, valid for 4 hours.
    """
    start = now or datetime.now(timezone.utc)
    return Scope(
        allow=tuple(str(n) for n in config.LAB_NETWORKS),
        deny=config.LAB_DENY,
        starts_at=start - timedelta(minutes=1),
        ends_at=start + timedelta(hours=hours),
        authorised_by=authorised_by,
        authorised_at=start - timedelta(minutes=1),
    )

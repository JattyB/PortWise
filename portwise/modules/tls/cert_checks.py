from __future__ import annotations

from datetime import datetime, timezone

CERT_TIME_FORMAT = "%b %d %H:%M:%S %Y %Z"


def parse_cert_time(value: str) -> datetime:
    return datetime.strptime(value, CERT_TIME_FORMAT).replace(tzinfo=timezone.utc)


def days_until(value: datetime) -> int:
    return int((value - datetime.now(timezone.utc)).total_seconds() // 86400)

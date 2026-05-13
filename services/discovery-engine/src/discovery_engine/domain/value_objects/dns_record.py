"""DNS record value object."""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel


class RecordType(StrEnum):
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    NS = "NS"
    TXT = "TXT"
    PTR = "PTR"
    SOA = "SOA"


class DNSRecord(BaseModel, frozen=True):
    """Immutable DNS resource record as discovered by passive DNS sources."""

    name: str           # FQDN queried (normalised, no trailing dot)
    record_type: RecordType
    value: str          # resolved value (IP, FQDN, or raw TXT)
    ttl: int = 0
    source: str = "unknown"
    first_seen: datetime | None = None
    last_seen: datetime | None = None

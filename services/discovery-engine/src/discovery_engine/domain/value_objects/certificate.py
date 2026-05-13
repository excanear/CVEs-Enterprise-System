"""Certificate value object — a TLS certificate from CT logs."""
from __future__ import annotations

from datetime import datetime, timezone

from pydantic import BaseModel


class Certificate(BaseModel, frozen=True):
    """Immutable TLS certificate as returned by Certificate Transparency sources."""

    serial: str
    issuer_cn: str
    subject_cn: str
    sans: tuple[str, ...]           # Subject Alternative Names
    not_before: datetime
    not_after: datetime
    log_name: str = "crt.sh"
    crt_sh_id: int | None = None

    @property
    def all_domains(self) -> frozenset[str]:
        """All unique domain names covered by this certificate."""
        all_d: set[str] = set(self.sans)
        if self.subject_cn:
            all_d.add(self.subject_cn.lstrip("*."))
        return frozenset(d.lstrip("*.").lower() for d in all_d if d)

    @property
    def is_expired(self) -> bool:
        return self.not_after < datetime.now(timezone.utc)

    @property
    def days_to_expiry(self) -> int:
        delta = self.not_after - datetime.now(timezone.utc)
        return int(delta.total_seconds() / 86400)

    @property
    def is_expiring_soon(self) -> bool:
        return self.days_to_expiry < 30

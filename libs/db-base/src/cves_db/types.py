"""UUID v7 (time-ordered) generator and typed ID aliases.

Python 3.13+ has built-in UUID v7 support via uuid.uuid7().
For 3.12 compatibility we implement the RFC 9562 algorithm manually.
"""
from __future__ import annotations

import os
import time
import uuid


def uuid7() -> uuid.UUID:
    """Generate a UUID v7 (time-ordered, RFC 9562).

    Format (128 bits):
        48 bits  unix_ts_ms  big-endian milliseconds since epoch
         4 bits  version     0b0111 (7)
        12 bits  rand_a      random
         2 bits  variant     0b10
        62 bits  rand_b      random
    """
    ts_ms = int(time.time() * 1000) & 0xFFFFFFFFFFFF  # 48 bits
    rand = int.from_bytes(os.urandom(10), "big")       # 80 random bits

    version_and_rand_a = (0x7000) | ((rand >> 68) & 0x0FFF)  # 4-bit ver + 12-bit rand_a
    variant_and_rand_b = (0x8000_0000_0000_0000) | (rand & 0x3FFF_FFFF_FFFF_FFFF)

    int_val = (
        (ts_ms << 80)
        | (version_and_rand_a << 64)
        | variant_and_rand_b
    )
    return uuid.UUID(int=int_val)


# Typed ID aliases — distinct types prevent mix-ups at type-check time
class _TypedUUID(uuid.UUID):
    """Base for typed UUID wrappers."""

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)

    @classmethod
    def generate(cls) -> "type[_TypedUUID]":
        return cls(int=uuid7().int)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({str(self)!r})"


# Re-export for convenience
UUIDv7 = uuid7


class TenantId(_TypedUUID):
    """Typed UUID for Tenant aggregates."""


class AssetId(_TypedUUID):
    """Typed UUID for Asset aggregates."""


class ScanId(_TypedUUID):
    """Typed UUID for Scan aggregates."""


class TechId(_TypedUUID):
    """Typed UUID for Technology aggregates."""


class CveId(str):
    """Typed string for CVE identifiers (CVE-YYYY-NNNN).

    Not UUID-based — CVE IDs are externally assigned strings.
    """

    _PATTERN = "CVE-"

    def __new__(cls, value: str) -> "CveId":
        v = value.strip().upper()
        if not v.startswith(cls._PATTERN):
            raise ValueError(f"Invalid CVE ID format: {value!r}. Expected 'CVE-YYYY-NNNN'.")
        parts = v.split("-")
        if len(parts) != 3 or not parts[1].isdigit() or not parts[2].isdigit():
            raise ValueError(f"Invalid CVE ID format: {value!r}. Expected 'CVE-YYYY-NNNN'.")
        return super().__new__(cls, v)

    def __repr__(self) -> str:
        return f"CveId({str(self)!r})"


class ExposureId(_TypedUUID):
    """Typed UUID for Exposure aggregates."""


class WorkflowId(_TypedUUID):
    """Typed UUID for Saga workflow instances."""


class AlertId(_TypedUUID):
    """Typed UUID for Alert aggregates."""


class EvidenceId(_TypedUUID):
    """Typed UUID for Evidence entities."""


class CorrelationId(_TypedUUID):
    """Typed UUID for event correlation chains."""

"""Value objects for scan configuration and adaptive rate limiting."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

# ── ScanConfig ────────────────────────────────────────────────────────────────

_DEFAULT_TIMEOUT: Final[int] = 30
_DEFAULT_MAX_RETRIES: Final[int] = 3


@dataclass(frozen=True)
class PortRange:
    """A TCP/UDP port range, e.g. '1-1024', '80', '443'."""

    raw: str

    def __post_init__(self) -> None:
        parts = self.raw.split("-")
        if len(parts) > 2:
            raise ValueError(f"Invalid port range: {self.raw!r}")
        for p in parts:
            port = int(p)
            if not (1 <= port <= 65535):
                raise ValueError(f"Port {port} out of range 1–65535")

    def to_nmap_format(self) -> str:
        return self.raw


@dataclass(frozen=True)
class ScanConfig:
    """Immutable configuration applied to a scan at submission time.

    Captured as a snapshot — changes after submission do not affect in-flight scans.
    """

    # Concurrency
    max_concurrent_tasks: int = 50          # across all workers for this scan
    max_concurrent_per_target: int = 5      # per individual target host
    worker_pool_size: int = 10              # workers reserved for this scan type

    # Timing
    task_timeout_seconds: int = _DEFAULT_TIMEOUT
    inter_task_delay_ms: int = 100          # minimum gap between tasks to same target

    # Retries
    max_retries: int = _DEFAULT_MAX_RETRIES
    retry_backoff_base_seconds: float = 2.0
    retry_backoff_max_seconds: float = 60.0
    retry_jitter: bool = True

    # Rate limiting
    initial_rps_per_target: float = 10.0
    min_rps_per_target: float = 0.5
    max_rps_per_target: float = 100.0

    # Scan specifics
    port_ranges: tuple[str, ...] = ("1-1024", "8080", "8443", "9090", "3000")
    scan_techniques: tuple[str, ...] = ("SYN",)
    follow_redirects: bool = True
    max_redirect_depth: int = 5
    user_agent: str = "CVEs-Enterprise-Scanner/1.0"

    def as_dict(self) -> dict:
        return {
            "max_concurrent_tasks": self.max_concurrent_tasks,
            "max_concurrent_per_target": self.max_concurrent_per_target,
            "worker_pool_size": self.worker_pool_size,
            "task_timeout_seconds": self.task_timeout_seconds,
            "inter_task_delay_ms": self.inter_task_delay_ms,
            "max_retries": self.max_retries,
            "retry_backoff_base_seconds": self.retry_backoff_base_seconds,
            "retry_backoff_max_seconds": self.retry_backoff_max_seconds,
            "retry_jitter": self.retry_jitter,
            "initial_rps_per_target": self.initial_rps_per_target,
            "min_rps_per_target": self.min_rps_per_target,
            "max_rps_per_target": self.max_rps_per_target,
            "port_ranges": list(self.port_ranges),
            "scan_techniques": list(self.scan_techniques),
            "follow_redirects": self.follow_redirects,
            "max_redirect_depth": self.max_redirect_depth,
            "user_agent": self.user_agent,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ScanConfig":
        return cls(
            max_concurrent_tasks=data.get("max_concurrent_tasks", 50),
            max_concurrent_per_target=data.get("max_concurrent_per_target", 5),
            worker_pool_size=data.get("worker_pool_size", 10),
            task_timeout_seconds=data.get("task_timeout_seconds", _DEFAULT_TIMEOUT),
            inter_task_delay_ms=data.get("inter_task_delay_ms", 100),
            max_retries=data.get("max_retries", _DEFAULT_MAX_RETRIES),
            retry_backoff_base_seconds=data.get("retry_backoff_base_seconds", 2.0),
            retry_backoff_max_seconds=data.get("retry_backoff_max_seconds", 60.0),
            retry_jitter=data.get("retry_jitter", True),
            initial_rps_per_target=data.get("initial_rps_per_target", 10.0),
            min_rps_per_target=data.get("min_rps_per_target", 0.5),
            max_rps_per_target=data.get("max_rps_per_target", 100.0),
            port_ranges=tuple(data.get("port_ranges", ["1-1024"])),
            scan_techniques=tuple(data.get("scan_techniques", ["SYN"])),
            follow_redirects=data.get("follow_redirects", True),
            max_redirect_depth=data.get("max_redirect_depth", 5),
            user_agent=data.get("user_agent", "CVEs-Enterprise-Scanner/1.0"),
        )


# ── WorkerCapacity ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class WorkerCapacity:
    """Describes a worker's current load capacity."""

    worker_id: str
    worker_type: str
    max_concurrent: int
    current_load: int

    @property
    def available_slots(self) -> int:
        return max(0, self.max_concurrent - self.current_load)

    @property
    def is_available(self) -> bool:
        return self.available_slots > 0

    @property
    def load_pct(self) -> float:
        if not self.max_concurrent:
            return 100.0
        return round(self.current_load / self.max_concurrent * 100, 2)

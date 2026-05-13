"""Distributed scheduler with Redis-based leader election.

Guarantees that only ONE instance of the service runs a scheduled scan
at any given time, even when multiple replicas are running.

Leader election: Redis SET NX with TTL (poor-man's Redlock for single-node).
  Key: "scheduler:leader:{job_id}"  Value: instance_id  TTL: heartbeat_interval * 3

Recurring schedules are stored as:
  HSET "scheduler:jobs" job_id  <json>

On startup, the scheduler:
  1. Loads existing jobs from Redis.
  2. Starts two background tasks:
     a. _leader_heartbeat  — renews leadership every heartbeat_interval seconds.
     b. _schedule_loop     — polls job schedules and fires due scans.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Final

import redis.asyncio as aioredis

try:
    from croniter import croniter  # type: ignore[import-untyped]
except ImportError:
    croniter = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)

_JOBS_KEY: Final[str] = "scheduler:jobs"
_LEADER_TTL_FACTOR: Final[int] = 3          # leader key TTL = interval * factor
_SCHEDULE_POLL: Final[float] = 5.0          # seconds between schedule checks


@dataclass
class ScheduledJob:
    job_id: str
    name: str
    cron_expression: str
    payload: dict                            # passed to fire_callback
    enabled: bool = True
    last_run_at: float = 0.0

    def to_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "name": self.name,
            "cron_expression": self.cron_expression,
            "payload": self.payload,
            "enabled": self.enabled,
            "last_run_at": self.last_run_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ScheduledJob":
        return cls(
            job_id=data["job_id"],
            name=data["name"],
            cron_expression=data["cron_expression"],
            payload=data.get("payload", {}),
            enabled=data.get("enabled", True),
            last_run_at=data.get("last_run_at", 0.0),
        )


FireCallback = Callable[[ScheduledJob], Awaitable[None]]


class DistributedScheduler:
    """Leader-elected recurring scan scheduler backed by Redis.

    Usage::

        scheduler = DistributedScheduler(redis, instance_id="pod-1", fire_callback=submit_fn)
        await scheduler.register_job(ScheduledJob(...))
        await scheduler.start()
        ...
        await scheduler.stop()
    """

    def __init__(
        self,
        redis: aioredis.Redis,
        *,
        instance_id: str | None = None,
        fire_callback: FireCallback,
        heartbeat_interval: float = 10.0,
    ) -> None:
        if croniter is None:
            raise ImportError("python-croniter is required. Install it: pip install python-croniter")
        self._redis = redis
        self._instance_id = instance_id or str(uuid.uuid4())
        self._fire_callback = fire_callback
        self._heartbeat_interval = heartbeat_interval
        self._leader_ttl = int(heartbeat_interval * _LEADER_TTL_FACTOR)
        self._jobs: dict[str, ScheduledJob] = {}
        self._is_leader = False
        self._tasks: list[asyncio.Task] = []

    # ── Lifecycle ─────────────────────────────────────────────────────────

    async def start(self) -> None:
        await self._load_jobs()
        self._tasks = [
            asyncio.create_task(self._leader_heartbeat(), name="scheduler:heartbeat"),
            asyncio.create_task(self._schedule_loop(), name="scheduler:loop"),
        ]
        logger.info("scheduler.started", extra={"instance_id": self._instance_id})

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        await self._release_leadership_for_all_jobs()
        logger.info("scheduler.stopped")

    # ── Job management ────────────────────────────────────────────────────

    async def register_job(self, job: ScheduledJob) -> None:
        self._jobs[job.job_id] = job
        await self._redis.hset(_JOBS_KEY, job.job_id, json.dumps(job.to_dict()))
        logger.info("scheduler.job_registered", extra={"job_id": job.job_id, "cron": job.cron_expression})

    async def unregister_job(self, job_id: str) -> None:
        self._jobs.pop(job_id, None)
        await self._redis.hdel(_JOBS_KEY, job_id)

    async def enable_job(self, job_id: str) -> None:
        job = self._jobs.get(job_id)
        if job:
            job.enabled = True
            await self._persist_job(job)

    async def disable_job(self, job_id: str) -> None:
        job = self._jobs.get(job_id)
        if job:
            job.enabled = False
            await self._persist_job(job)

    def list_jobs(self) -> list[dict]:
        return [j.to_dict() for j in self._jobs.values()]

    # ── Background loops ──────────────────────────────────────────────────

    async def _leader_heartbeat(self) -> None:
        while True:
            try:
                # Try to acquire/renew leadership for each job independently
                for job_id in list(self._jobs.keys()):
                    leader_key = f"scheduler:leader:{job_id}"
                    acquired = await self._redis.set(
                        leader_key,
                        self._instance_id,
                        nx=True,
                        ex=self._leader_ttl,
                    )
                    if acquired:
                        logger.debug("scheduler.leader_acquired", extra={"job_id": job_id})
                    else:
                        # Renew if we are already the leader
                        current = await self._redis.get(leader_key)
                        if current and current.decode() == self._instance_id:
                            await self._redis.expire(leader_key, self._leader_ttl)
            except Exception as exc:
                logger.error("scheduler.heartbeat_error", extra={"error": str(exc)})
            await asyncio.sleep(self._heartbeat_interval)

    async def _schedule_loop(self) -> None:
        while True:
            try:
                import time

                now = time.time()
                for job in list(self._jobs.values()):
                    if not job.enabled:
                        continue
                    if not await self._is_leader_for(job.job_id):
                        continue
                    if self._is_due(job, now):
                        await self._fire_job(job, now)
            except Exception as exc:
                logger.error("scheduler.loop_error", extra={"error": str(exc)})
            await asyncio.sleep(_SCHEDULE_POLL)

    # ── Internal ──────────────────────────────────────────────────────────

    def _is_due(self, job: ScheduledJob, now: float) -> bool:
        """Return True if the job should fire at `now` given last_run_at."""
        try:
            cron = croniter(job.cron_expression, job.last_run_at or (now - _SCHEDULE_POLL * 2))
            next_run = cron.get_next(float)
            return next_run <= now
        except Exception as exc:
            logger.error("scheduler.cron_parse_error", extra={"job_id": job.job_id, "error": str(exc)})
            return False

    async def _fire_job(self, job: ScheduledJob, now: float) -> None:
        logger.info("scheduler.job_firing", extra={"job_id": job.job_id, "name": job.name})
        try:
            await self._fire_callback(job)
            job.last_run_at = now
            await self._persist_job(job)
        except Exception as exc:
            logger.error(
                "scheduler.job_error",
                extra={"job_id": job.job_id, "error": str(exc)},
                exc_info=True,
            )

    async def _is_leader_for(self, job_id: str) -> bool:
        leader_key = f"scheduler:leader:{job_id}"
        current = await self._redis.get(leader_key)
        return bool(current and current.decode() == self._instance_id)

    async def _load_jobs(self) -> None:
        raw = await self._redis.hgetall(_JOBS_KEY)
        for _, v in raw.items():
            try:
                job = ScheduledJob.from_dict(json.loads(v))
                self._jobs[job.job_id] = job
            except Exception as exc:
                logger.warning("scheduler.load_job_error", extra={"error": str(exc)})
        logger.info("scheduler.jobs_loaded", extra={"count": len(self._jobs)})

    async def _persist_job(self, job: ScheduledJob) -> None:
        await self._redis.hset(_JOBS_KEY, job.job_id, json.dumps(job.to_dict()))

    async def _release_leadership_for_all_jobs(self) -> None:
        for job_id in self._jobs:
            leader_key = f"scheduler:leader:{job_id}"
            current = await self._redis.get(leader_key)
            if current and current.decode() == self._instance_id:
                await self._redis.delete(leader_key)

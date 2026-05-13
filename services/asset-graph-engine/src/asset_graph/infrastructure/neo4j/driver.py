"""Async Neo4j driver wrapper for Asset Graph Engine.

Uses the official `neo4j` Python driver >= 5.27 which ships with native async
support via `AsyncGraphDatabase.driver()`. No `asyncio.to_thread` needed.

Usage::

    driver = AsyncNeo4jDriver.from_env()
    async with driver:
        await driver.bootstrap_constraints()
        async with driver.session() as session:
            await session.run(...)
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import AsyncIterator

import structlog
from neo4j import AsyncDriver, AsyncGraphDatabase, AsyncSession

from asset_graph.infrastructure.neo4j.cypher_queries import (
    BOOTSTRAP_CONSTRAINTS,
    BOOTSTRAP_INDEXES,
)

log = structlog.get_logger(__name__)

_DEFAULT_URI = "bolt://localhost:7687"
_DEFAULT_USER = "neo4j"
_DEFAULT_PASSWORD = "neo4j_secret"


class AsyncNeo4jDriver:
    """Thin wrapper around the official neo4j async driver.

    Handles connection lifecycle and exposes a context-manager session factory.
    """

    def __init__(
        self,
        uri: str,
        user: str,
        password: str,
        *,
        max_connection_pool_size: int = 20,
    ) -> None:
        self._uri = uri
        self._driver: AsyncDriver = AsyncGraphDatabase.driver(
            uri,
            auth=(user, password),
            max_connection_pool_size=max_connection_pool_size,
        )

    # ── Factory ────────────────────────────────────────────────────────────

    @classmethod
    def from_env(cls) -> "AsyncNeo4jDriver":
        return cls(
            uri=os.environ.get("NEO4J_URL", _DEFAULT_URI),
            user=os.environ.get("NEO4J_USER", _DEFAULT_USER),
            password=os.environ.get("NEO4J_PASSWORD", _DEFAULT_PASSWORD),
        )

    # ── Session factory ────────────────────────────────────────────────────

    @asynccontextmanager
    async def session(self, database: str = "neo4j") -> AsyncIterator[AsyncSession]:
        async with self._driver.session(database=database) as s:
            yield s

    # ── Bootstrap ──────────────────────────────────────────────────────────

    async def bootstrap_constraints(self) -> None:
        """Create constraints and indexes if they don't already exist.

        Safe to call on every startup (IF NOT EXISTS guards idempotency).
        """
        async with self.session() as s:
            for cypher in BOOTSTRAP_CONSTRAINTS:
                try:
                    await s.run(cypher)
                    log.debug("age.neo4j.constraint_applied", cypher=cypher[:60])
                except Exception as exc:
                    log.warning(
                        "age.neo4j.constraint_failed",
                        cypher=cypher[:60],
                        error=str(exc),
                    )
            for cypher in BOOTSTRAP_INDEXES:
                try:
                    await s.run(cypher)
                    log.debug("age.neo4j.index_applied", cypher=cypher[:60])
                except Exception as exc:
                    log.warning(
                        "age.neo4j.index_failed",
                        cypher=cypher[:60],
                        error=str(exc),
                    )
        log.info("age.neo4j.bootstrap_complete")

    # ── Health check ───────────────────────────────────────────────────────

    async def ping(self) -> bool:
        try:
            async with self.session() as s:
                result = await s.run("RETURN 1 AS ok")
                record = await result.single()
                return record is not None and record["ok"] == 1
        except Exception:
            return False

    # ── Lifecycle ──────────────────────────────────────────────────────────

    async def close(self) -> None:
        await self._driver.close()
        log.info("age.neo4j.driver_closed")

    async def __aenter__(self) -> "AsyncNeo4jDriver":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

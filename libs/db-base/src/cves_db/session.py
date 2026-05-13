"""Async SQLAlchemy session factory with per-request lifecycle management."""
from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

logger = logging.getLogger(__name__)


class AsyncSessionFactory:
    """Thread-safe async session factory.

    Usage:
        factory = AsyncSessionFactory.from_url("postgresql+asyncpg://...")
        async with factory.session() as session:
            result = await session.execute(...)
    """

    def __init__(self, engine: AsyncEngine, session_maker: async_sessionmaker[AsyncSession]) -> None:
        self._engine = engine
        self._session_maker = session_maker

    @classmethod
    def from_url(
        cls,
        url: str,
        *,
        pool_size: int = 20,
        max_overflow: int = 10,
        pool_pre_ping: bool = True,
        pool_recycle: int = 3600,
        echo: bool = False,
        connect_args: dict[str, Any] | None = None,
    ) -> "AsyncSessionFactory":
        """Create factory from a DSN string.

        Args:
            url: asyncpg DSN, e.g. 'postgresql+asyncpg://user:pass@host/db'
            pool_size: number of persistent connections in pool
            max_overflow: extra connections allowed above pool_size
            pool_pre_ping: test connections before checkout
            pool_recycle: seconds before recycling idle connections
            echo: emit SQL to logger (dev only)
            connect_args: extra kwargs forwarded to asyncpg connect()
        """
        engine = create_async_engine(
            url,
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_pre_ping=pool_pre_ping,
            pool_recycle=pool_recycle,
            echo=echo,
            connect_args=connect_args or {},
        )
        session_maker = async_sessionmaker(
            bind=engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
            autocommit=False,
        )
        return cls(engine, session_maker)

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        """Yield a session; rolls back on unhandled exception."""
        async with self._session_maker() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise

    @asynccontextmanager
    async def transaction(self) -> AsyncGenerator[AsyncSession, None]:
        """Yield a session inside an explicit transaction; commits on success."""
        async with self.session() as session:
            async with session.begin():
                yield session

    @property
    def engine(self) -> AsyncEngine:
        return self._engine

    async def dispose(self) -> None:
        """Close all pool connections. Call on application shutdown."""
        await self._engine.dispose()
        logger.info("db_pool_disposed")


# ---------------------------------------------------------------------------
# FastAPI / dependency-injection helpers
# ---------------------------------------------------------------------------

_factory: AsyncSessionFactory | None = None


def configure_session_factory(factory: AsyncSessionFactory) -> None:
    """Register the global session factory (call once at startup)."""
    global _factory
    _factory = factory


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: yields a session per request."""
    if _factory is None:
        raise RuntimeError(
            "AsyncSessionFactory not configured. "
            "Call configure_session_factory() at startup."
        )
    async with _factory.session() as session:
        yield session

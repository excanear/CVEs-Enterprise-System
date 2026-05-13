"""Keyset (cursor) pagination — O(1) regardless of offset depth.

Avoids the N+offset scan that OFFSET-based pagination incurs on large tables.
Works by encoding the last-seen sort key as an opaque cursor.
"""
from __future__ import annotations

import base64
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Generic, TypeVar

from sqlalchemy import Select, asc, desc, select
from sqlalchemy.ext.asyncio import AsyncSession

T = TypeVar("T")


class SortDirection(str, Enum):
    ASC = "asc"
    DESC = "desc"


@dataclass(frozen=True)
class CursorPage(Generic[T]):
    """A single page of results with a cursor for the next page."""

    items: list[T]
    next_cursor: str | None
    has_next: bool
    total_hint: int | None = None  # cheap count if available; None = unknown


@dataclass
class CursorPagination:
    """Stateless keyset paginator.

    Usage::

        paginator = CursorPagination(limit=50, sort_column="created_at", sort_dir=SortDirection.DESC)
        page = await paginator.paginate(session, base_stmt, cursor=request_cursor)
    """

    limit: int = 50
    sort_column: str = "created_at"
    sort_dir: SortDirection = SortDirection.DESC
    # Secondary sort for stable ordering when sort_column has duplicates
    tiebreak_column: str = "id"

    # Cursor encoding / decoding ------------------------------------------------

    @staticmethod
    def _encode_cursor(values: dict[str, Any]) -> str:
        raw = json.dumps(values, default=str)
        return base64.urlsafe_b64encode(raw.encode()).decode()

    @staticmethod
    def _decode_cursor(cursor: str) -> dict[str, Any]:
        try:
            raw = base64.urlsafe_b64decode(cursor.encode()).decode()
            return json.loads(raw)
        except Exception as exc:
            raise ValueError(f"Invalid pagination cursor: {cursor!r}") from exc

    # Public API ----------------------------------------------------------------

    async def paginate(
        self,
        session: AsyncSession,
        stmt: Select[tuple[T]],
        *,
        cursor: str | None = None,
        model: type | None = None,
    ) -> CursorPage[T]:
        """Execute paginated query and return a CursorPage.

        Args:
            session: active async SQLAlchemy session.
            stmt: base SELECT statement (no ORDER BY, no LIMIT/OFFSET).
            cursor: opaque cursor string from previous page; None for first page.
            model: ORM model class (for column resolution); optional if stmt is self-contained.
        """
        from sqlalchemy import Column

        # Apply ordering
        order_col = getattr(model, self.sort_column) if model else self.sort_column
        tie_col = getattr(model, self.tiebreak_column) if model else self.tiebreak_column

        order_fn = asc if self.sort_dir == SortDirection.ASC else desc
        stmt = stmt.order_by(order_fn(order_col), asc(tie_col))

        # Apply cursor filter (keyset)
        if cursor:
            decoded = self._decode_cursor(cursor)
            sort_val = decoded.get("sort_val")
            tie_val = decoded.get("tie_val")
            if self.sort_dir == SortDirection.DESC:
                stmt = stmt.where(
                    (order_col < sort_val)
                    | ((order_col == sort_val) & (tie_col > tie_val))
                )
            else:
                stmt = stmt.where(
                    (order_col > sort_val)
                    | ((order_col == sort_val) & (tie_col > tie_val))
                )

        # Fetch limit + 1 to detect next page
        stmt = stmt.limit(self.limit + 1)
        result = await session.execute(stmt)
        rows = list(result.scalars().all())

        has_next = len(rows) > self.limit
        items = rows[: self.limit]

        next_cursor: str | None = None
        if has_next and items:
            last = items[-1]
            sort_val = getattr(last, self.sort_column, None)
            tie_val = getattr(last, self.tiebreak_column, None)
            next_cursor = self._encode_cursor(
                {"sort_val": sort_val, "tie_val": tie_val}
            )

        return CursorPage(items=items, next_cursor=next_cursor, has_next=has_next)

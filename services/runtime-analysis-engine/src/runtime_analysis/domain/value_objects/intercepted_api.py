from __future__ import annotations

from pydantic import BaseModel, Field

_MAX_BODY_BYTES = 4096


class InterceptedAPI(BaseModel, frozen=True):
    """Value object for a single API call observed during browser instrumentation."""

    url: str
    method: str
    is_graphql: bool = False
    status_code: int | None = None
    request_body_sample: str = Field(default="", max_length=_MAX_BODY_BYTES)
    response_body_sample: str = Field(default="", max_length=_MAX_BODY_BYTES)
    params: tuple[str, ...] = ()

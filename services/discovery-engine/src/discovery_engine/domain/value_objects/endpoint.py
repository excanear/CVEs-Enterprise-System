"""Endpoint value object — an HTTP endpoint discovered during crawling."""
from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel


class HttpMethod(StrEnum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"
    UNKNOWN = "UNKNOWN"


class Endpoint(BaseModel, frozen=True):
    url: str
    path: str
    method: HttpMethod = HttpMethod.GET
    status_code: int | None = None
    content_type: str | None = None
    discovered_from: str | None = None   # URL that linked here
    source: str = "CRAWLER"              # CRAWLER | ROBOTS_TXT | SITEMAP | JS_FETCH | …
    parameters: tuple[str, ...] = ()     # query parameter names found
    is_api_endpoint: bool = False

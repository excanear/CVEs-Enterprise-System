from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from runtime_analysis.domain.value_objects.intercepted_api import InterceptedAPI

_GRAPHQL_PATTERN = re.compile(r'"(query|mutation)\s*[\w\s(]*\{', re.IGNORECASE)
_MAX_BODY = 4096


class APIAnalyzer:
    """
    Post-processes raw network call records captured by the browser instrumentation.
    Deduplicates by (base_path, method), classifies GraphQL, extracts params.
    """

    def classify(self, raw_calls: list[dict]) -> list[InterceptedAPI]:
        seen: dict[tuple[str, str], InterceptedAPI] = {}

        for call in raw_calls:
            url = call.get("url", "")
            method = (call.get("method") or "GET").upper()
            status = call.get("status")
            req_body = call.get("requestBody", "")[:_MAX_BODY]
            res_body = call.get("responseBody", "")[:_MAX_BODY]

            base_path = self._base_path(url)
            key = (base_path, method)

            is_graphql = self._detect_graphql(url, method, req_body)
            params = self._extract_params(url, req_body, method)

            if key not in seen:
                seen[key] = InterceptedAPI(
                    url=url,
                    method=method,
                    is_graphql=is_graphql,
                    status_code=status,
                    request_body_sample=req_body,
                    response_body_sample=res_body,
                    params=tuple(params),
                )

        return list(seen.values())

    # ------------------------------------------------------------------

    def _base_path(self, url: str) -> str:
        try:
            parsed = urlparse(url)
            # Strip trailing slash and query string for dedup key
            return parsed.scheme + "://" + parsed.netloc + parsed.path.rstrip("/")
        except Exception:
            return url

    def _detect_graphql(self, url: str, method: str, req_body: str) -> bool:
        if "graphql" in url.lower() or "gql" in url.lower():
            return True
        if method == "POST" and req_body:
            if '"query"' in req_body or '"mutation"' in req_body:
                return True
            if _GRAPHQL_PATTERN.search(req_body):
                return True
        return False

    def _extract_params(self, url: str, req_body: str, method: str) -> list[str]:
        params: list[str] = []
        try:
            parsed = urlparse(url)
            if parsed.query:
                for part in parsed.query.split("&"):
                    if "=" in part:
                        params.append(part.split("=", 1)[0])
        except Exception:
            pass

        if method == "POST" and req_body:
            try:
                body = json.loads(req_body)
                if isinstance(body, dict):
                    params.extend(list(body.keys())[:20])
            except Exception:
                pass

        return list(dict.fromkeys(params))  # deduplicate preserving order

from __future__ import annotations

import ipaddress
import logging
import re
import socket
from urllib.parse import urlparse

from playwright.async_api import Page, Request, Route

from runtime_analysis.domain.value_objects.intercepted_api import InterceptedAPI

log = logging.getLogger(__name__)

# Same private ranges as discovery-engine crawler
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / metadata
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

# Patterns indicating an API endpoint worth capturing
_API_PATTERNS = re.compile(
    r"(/api/|/graphql|/v\d+/|/rest/|/gql|/query)", re.IGNORECASE
)

_BLOCKED_SCHEMES = {"file", "data", "blob"}

_MAX_BODY = 4096


def _is_private(hostname: str) -> bool:
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(hostname))
        return any(ip in net for net in _PRIVATE_NETS)
    except Exception:
        return False


def _is_blocked_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme in _BLOCKED_SCHEMES:
            return True
        if parsed.hostname and _is_private(parsed.hostname):
            return True
    except Exception:
        pass
    return False


class NetworkInterceptor:
    """
    Intercepts all page network traffic via page.route().
    - Blocks requests to private IPs / metadata endpoints (SSRF guard)
    - Captures API calls matching known patterns
    """

    def __init__(self) -> None:
        self._intercepted: list[InterceptedAPI] = []

    async def install(self, page: Page) -> None:
        await page.route("**/*", self._handle_route)

    async def _handle_route(self, route: Route) -> None:
        request: Request = route.request
        url = request.url

        if _is_blocked_url(url):
            log.debug("network_interceptor.blocked", extra={"url": url})
            await route.abort("addressunreachable")
            return

        # Capture API calls (non-blocking — let request continue)
        if _API_PATTERNS.search(url):
            try:
                req_body = ""
                if request.post_data:
                    req_body = request.post_data[:_MAX_BODY]

                response = await route.fetch()
                res_body = ""
                try:
                    res_body = (await response.text())[:_MAX_BODY]
                except Exception:
                    pass

                params = tuple(
                    k for k in urlparse(url).query.split("&")
                    if "=" in k
                    for k, _ in [k.split("=", 1)]
                )

                self._intercepted.append(
                    InterceptedAPI(
                        url=url,
                        method=request.method,
                        status_code=response.status,
                        request_body_sample=req_body,
                        response_body_sample=res_body,
                        params=params,
                    )
                )
                await route.fulfill(response=response)
            except Exception as exc:
                log.debug(
                    "network_interceptor.capture_error",
                    extra={"url": url, "error": str(exc)},
                )
                await route.continue_()
        else:
            await route.continue_()

    @property
    def intercepted_apis(self) -> list[InterceptedAPI]:
        return list(self._intercepted)

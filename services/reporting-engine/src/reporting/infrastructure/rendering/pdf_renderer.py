"""PDF renderer — uses weasyprint when available, falls back to HTML bytes."""
from __future__ import annotations

import structlog

log = structlog.get_logger(__name__)

try:
    from weasyprint import HTML as _WeasyprintHTML  # type: ignore[import-untyped]
    _WEASYPRINT_AVAILABLE = True
except Exception:
    _WEASYPRINT_AVAILABLE = False
    log.warning("re.pdf_renderer.weasyprint_unavailable", fallback="html")


def render_pdf(html_content: str) -> bytes:
    """Convert HTML to PDF. Returns PDF bytes or HTML bytes if weasyprint unavailable."""
    if _WEASYPRINT_AVAILABLE:
        try:
            return _WeasyprintHTML(string=html_content).write_pdf()  # type: ignore[union-attr]
        except Exception as exc:
            log.warning("re.pdf_renderer.render_failed", error=str(exc))

    return html_content.encode("utf-8")


def content_type() -> str:
    return "application/pdf" if _WEASYPRINT_AVAILABLE else "text/html; charset=utf-8"

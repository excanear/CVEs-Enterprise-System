"""MiddlewareFindings — security headers and CORS analysis."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class MiddlewareFindings(BaseModel):
    model_config = ConfigDict(frozen=True)

    csp_present: bool = False
    hsts_present: bool = False
    x_frame_options: str | None = None
    cors_allows_wildcard: bool = False
    cors_allows_credentials_with_wildcard: bool = False
    x_content_type_nosniff: bool = False
    referrer_policy: str | None = None
    missing_headers: tuple[str, ...] = Field(default_factory=tuple)
    score: float = Field(default=0.0, ge=0.0, le=1.0)

    @classmethod
    def from_headers(cls, headers: dict[str, str]) -> "MiddlewareFindings":
        """Analyze a response header dict and return findings."""
        h = {k.lower(): v for k, v in headers.items()}

        csp = "content-security-policy" in h
        hsts = "strict-transport-security" in h
        xfo = h.get("x-frame-options")
        xcto = h.get("x-content-type-options", "").lower() == "nosniff"
        rp = h.get("referrer-policy")

        acao = h.get("access-control-allow-origin", "")
        acac = h.get("access-control-allow-credentials", "").lower() == "true"
        cors_wildcard = acao == "*"
        cors_cred_wild = cors_wildcard and acac

        expected = ["content-security-policy", "strict-transport-security",
                    "x-frame-options", "x-content-type-options", "referrer-policy"]
        missing = tuple(name for name in expected if name not in h)

        present_count = sum([csp, hsts, bool(xfo), xcto, bool(rp)])
        score = present_count / len(expected)

        return cls(
            csp_present=csp,
            hsts_present=hsts,
            x_frame_options=xfo,
            cors_allows_wildcard=cors_wildcard,
            cors_allows_credentials_with_wildcard=cors_cred_wild,
            x_content_type_nosniff=xcto,
            referrer_policy=rp,
            missing_headers=missing,
            score=round(score, 3),
        )

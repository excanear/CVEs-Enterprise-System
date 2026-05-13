"""Certificate Transparency log source via crt.sh.

Queries crt.sh for all certificates issued to a domain (wildcard search).
Parses SANs to extract subdomain names, deduplicates by crt.sh entry ID,
and emits Certificate VOs plus the raw set of discovered FQDNs.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Final

import httpx

from ...domain.value_objects.certificate import Certificate

logger = logging.getLogger(__name__)

_CRTSH_URL: Final = "https://crt.sh/"
# crt.sh can be slow — use a generous timeout
_DEFAULT_TIMEOUT: Final = 30.0


class CTLogsSource:
    """Queries Certificate Transparency logs via crt.sh (public API)."""

    def __init__(self, *, timeout: float = _DEFAULT_TIMEOUT) -> None:
        self._timeout = timeout

    async def query(self, domain: str) -> tuple[list[Certificate], set[str]]:
        """Return (certificates, discovered_fqdns) for *domain*.

        Makes two queries: ``%.domain`` (subdomains) and ``domain`` (exact),
        then merges results.
        """
        certificates: list[Certificate] = []
        fqdns: set[str] = set()

        async with httpx.AsyncClient(
            timeout=self._timeout,
            follow_redirects=True,
            verify=True,
            headers={"User-Agent": "CVEs-Discovery/1.0"},
        ) as client:
            for q in [f"%.{domain}", domain]:
                certs = await self._query_crtsh(client, q)
                for cert in certs:
                    certificates.append(cert)
                    for san in cert.all_domains:
                        san_clean = san.lstrip("*.")
                        if san_clean == domain or san_clean.endswith(f".{domain}"):
                            fqdns.add(san_clean)

        # Detect certificates expiring soon and tag them
        for cert in certificates:
            if cert.is_expiring_soon:
                logger.info(
                    "ct_logs.cert_expiring_soon",
                    extra={"subject": cert.subject_cn, "days": cert.days_to_expiry},
                )

        return certificates, fqdns

    async def _query_crtsh(
        self, client: httpx.AsyncClient, query: str
    ) -> list[Certificate]:
        certs: list[Certificate] = []
        seen_ids: set[int] = set()

        try:
            resp = await client.get(
                _CRTSH_URL,
                params={"q": query, "output": "json"},
                headers={"Accept": "application/json"},
            )
        except httpx.TimeoutException:
            logger.warning("ct_logs.crtsh_timeout", extra={"query": query})
            return certs
        except Exception as exc:
            logger.error("ct_logs.crtsh_request_failed", extra={"error": str(exc)})
            return certs

        if resp.status_code != 200:
            logger.warning("ct_logs.crtsh_non200", extra={"status": resp.status_code, "query": query})
            return certs

        try:
            entries: list[dict] = resp.json()
        except Exception:
            logger.warning("ct_logs.crtsh_bad_json", extra={"query": query})
            return certs

        for entry in entries:
            entry_id = entry.get("id") or 0
            if entry_id in seen_ids:
                continue
            seen_ids.add(entry_id)

            try:
                name_value: str = entry.get("name_value", "")
                # name_value can be newline- or comma-separated
                raw_names = [
                    n.strip().lower()
                    for n in name_value.replace("\n", ",").split(",")
                    if n.strip()
                ]
                sans = tuple(raw_names)

                not_before = _parse_dt(entry.get("not_before"))
                not_after = _parse_dt(entry.get("not_after"))
                if not not_before or not not_after:
                    continue

                certs.append(Certificate(
                    serial=str(entry.get("serial_number", "")),
                    issuer_cn=str(entry.get("issuer_ca_id", "")),
                    subject_cn=entry.get("common_name", "").lower().strip(),
                    sans=sans,
                    not_before=not_before,
                    not_after=not_after,
                    log_name="crt.sh",
                    crt_sh_id=entry_id or None,
                ))
            except Exception:
                continue

        return certs


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
    except Exception:
        return None

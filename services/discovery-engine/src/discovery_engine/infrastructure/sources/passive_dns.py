"""Passive DNS aggregator — queries CIRCL PDNS, Hackertarget, VirusTotal.

Each source is queried concurrently. Failures are isolated per-source so a
single unavailable provider never blocks the pipeline.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Final

import httpx

from ...domain.value_objects.dns_record import DNSRecord, RecordType

logger = logging.getLogger(__name__)

_CIRCL_BASE: Final = "https://www.circl.lu/pdns/query"
_HACKERTARGET_BASE: Final = "https://api.hackertarget.com/hostsearch/"
_VT_BASE: Final = "https://www.virustotal.com/api/v3/domains"

# VirusTotal returns max 40 items per page; this is sufficient for discovery
_VT_LIMIT: Final = 40


class PassiveDNSSource:
    """Aggregate passive DNS data from multiple public/commercial providers."""

    def __init__(
        self,
        *,
        timeout: float = 20.0,
        virustotal_api_key: str | None = None,
        securitytrails_api_key: str | None = None,
    ) -> None:
        self._timeout = timeout
        self._vt_key = virustotal_api_key
        self._st_key = securitytrails_api_key

    async def query(self, domain: str) -> tuple[list[DNSRecord], set[str]]:
        """Query all providers in parallel.

        Returns (dns_records, discovered_fqdns).
        """
        all_records: list[DNSRecord] = []
        all_fqdns: set[str] = set()

        async with httpx.AsyncClient(
            timeout=self._timeout,
            follow_redirects=True,
            verify=True,
            headers={"User-Agent": "CVEs-Discovery/1.0"},
        ) as client:
            sources = [
                self._query_circl(client, domain),
                self._query_hackertarget(client, domain),
            ]
            if self._vt_key:
                sources.append(self._query_virustotal(client, domain))

            results = await asyncio.gather(*sources, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.warning("passive_dns.source_error", extra={"error": str(result)})
                continue
            records, fqdns = result
            all_records.extend(records)
            all_fqdns.update(fqdns)

        # Always include the root domain itself
        all_fqdns.add(domain.lower())
        return all_records, all_fqdns

    # ── CIRCL PDNS ────────────────────────────────────────────────────────

    async def _query_circl(
        self, client: httpx.AsyncClient, domain: str
    ) -> tuple[list[DNSRecord], set[str]]:
        """CIRCL Passive DNS — public, no auth, returns NDJSON."""
        records: list[DNSRecord] = []
        fqdns: set[str] = set()
        try:
            resp = await client.get(
                f"{_CIRCL_BASE}/{domain}",
                headers={"Accept": "application/json"},
            )
            if resp.status_code != 200:
                return records, fqdns

            for line in resp.text.strip().splitlines():
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue

                rtype_raw = entry.get("rrtype", "").upper()
                try:
                    rtype = RecordType(rtype_raw)
                except ValueError:
                    continue

                rrname = entry.get("rrname", "").rstrip(".").lower()
                rdata = entry.get("rdata", "").rstrip(".").lower()
                if not rrname or not rdata:
                    continue

                records.append(DNSRecord(
                    name=rrname,
                    record_type=rtype,
                    value=rdata,
                    source="circl_pdns",
                ))

                if rtype in (RecordType.A, RecordType.AAAA, RecordType.CNAME):
                    if rrname == domain or rrname.endswith(f".{domain}"):
                        fqdns.add(rrname)

        except Exception as exc:
            raise RuntimeError(f"CIRCL PDNS query failed: {exc}") from exc

        return records, fqdns

    # ── Hackertarget ──────────────────────────────────────────────────────

    async def _query_hackertarget(
        self, client: httpx.AsyncClient, domain: str
    ) -> tuple[list[DNSRecord], set[str]]:
        """Hackertarget host search — free tier, CSV output."""
        records: list[DNSRecord] = []
        fqdns: set[str] = set()
        try:
            resp = await client.get(_HACKERTARGET_BASE, params={"q": domain})
            body = resp.text.strip()
            if resp.status_code != 200 or not body or body.startswith("error"):
                return records, fqdns

            for line in body.splitlines():
                if "," not in line:
                    continue
                host, ip = line.split(",", 1)
                host = host.strip().lower()
                ip = ip.strip()
                if not host or not ip:
                    continue
                if host == domain or host.endswith(f".{domain}"):
                    fqdns.add(host)
                    records.append(DNSRecord(
                        name=host,
                        record_type=RecordType.A,
                        value=ip,
                        source="hackertarget",
                    ))

        except Exception as exc:
            raise RuntimeError(f"Hackertarget query failed: {exc}") from exc

        return records, fqdns

    # ── VirusTotal ────────────────────────────────────────────────────────

    async def _query_virustotal(
        self, client: httpx.AsyncClient, domain: str
    ) -> tuple[list[DNSRecord], set[str]]:
        """VirusTotal passive DNS — requires API key."""
        records: list[DNSRecord] = []
        fqdns: set[str] = set()
        try:
            resp = await client.get(
                f"{_VT_BASE}/{domain}/subdomains",
                headers={"x-apikey": self._vt_key},
                params={"limit": _VT_LIMIT},
            )
            if resp.status_code != 200:
                return records, fqdns

            for item in resp.json().get("data", []):
                subdomain = item.get("id", "").lower()
                if subdomain and (subdomain == domain or subdomain.endswith(f".{domain}")):
                    fqdns.add(subdomain)
                    records.append(DNSRecord(
                        name=subdomain,
                        record_type=RecordType.A,
                        value="",           # VT subdomain list has no IPs in this endpoint
                        source="virustotal",
                    ))

        except Exception as exc:
            raise RuntimeError(f"VirusTotal query failed: {exc}") from exc

        return records, fqdns

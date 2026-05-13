"""Asset correlator — builds correlation links between discovered assets.

Correlation strategies:
  1. Shared IP         — two FQDNs resolving to the same IP address.
  2. Certificate SANs  — two FQDNs sharing a TLS certificate.
  3. CNAME chain       — domain A CNAMEs to domain B.
  4. Parent domain     — sub.example.com → example.com.
  5. NS correlation    — domains sharing the same authoritative nameservers.
"""
from __future__ import annotations

import ipaddress
import uuid
from collections import defaultdict

from ..domain.entities.discovered_asset import AssetType, DiscoveredAsset
from ..domain.value_objects.certificate import Certificate
from ..domain.value_objects.dns_record import DNSRecord, RecordType


# (asset_id_a, asset_id_b, reason)
Correlation = tuple[uuid.UUID, uuid.UUID, str]


class AssetCorrelator:
    def correlate(
        self,
        assets: list[DiscoveredAsset],
        dns_records: list[DNSRecord],
        certificates: list[Certificate],
    ) -> list[Correlation]:
        correlations: list[Correlation] = []
        asset_by_value: dict[str, DiscoveredAsset] = {a.value: a for a in assets}

        # ── 1. Shared IP ──────────────────────────────────────────────────
        ip_to_domains: dict[str, list[DiscoveredAsset]] = defaultdict(list)
        cname_map: dict[str, str] = {}
        ns_to_domains: dict[str, list[DiscoveredAsset]] = defaultdict(list)

        for record in dns_records:
            rtype = record.record_type
            name = record.name.lower().rstrip(".")
            value = record.value.lower().rstrip(".")

            if rtype in (RecordType.A, RecordType.AAAA):
                if name in asset_by_value:
                    ip_to_domains[value].append(asset_by_value[name])

            elif rtype == RecordType.CNAME:
                cname_map[name] = value

            elif rtype == RecordType.NS:
                if name in asset_by_value:
                    ns_to_domains[value].append(asset_by_value[name])

        for ip, domains in ip_to_domains.items():
            for i in range(len(domains)):
                for j in range(i + 1, len(domains)):
                    correlations.append((
                        domains[i].asset_id,
                        domains[j].asset_id,
                        f"shared_ip:{ip}",
                    ))

        # ── 2. Certificate SANs ───────────────────────────────────────────
        for cert in certificates:
            cert_assets = [
                asset_by_value[d]
                for d in cert.all_domains
                if d in asset_by_value
            ]
            for i in range(len(cert_assets)):
                for j in range(i + 1, len(cert_assets)):
                    correlations.append((
                        cert_assets[i].asset_id,
                        cert_assets[j].asset_id,
                        f"shared_cert:{cert.serial[:16]}",
                    ))

        # ── 3. CNAME chain ────────────────────────────────────────────────
        for domain, canonical in cname_map.items():
            if domain in asset_by_value and canonical in asset_by_value:
                correlations.append((
                    asset_by_value[domain].asset_id,
                    asset_by_value[canonical].asset_id,
                    "cname_chain",
                ))

        # ── 4. Parent domain ──────────────────────────────────────────────
        for asset in assets:
            if asset.asset_type == AssetType.DOMAIN:
                parts = asset.value.split(".")
                if len(parts) > 2:
                    parent = ".".join(parts[1:])
                    if parent in asset_by_value:
                        correlations.append((
                            asset.asset_id,
                            asset_by_value[parent].asset_id,
                            "parent_domain",
                        ))

        # ── 5. Shared NS (same infrastructure) ───────────────────────────
        for ns, domains in ns_to_domains.items():
            if len(domains) >= 2:
                for i in range(len(domains)):
                    for j in range(i + 1, len(domains)):
                        correlations.append((
                            domains[i].asset_id,
                            domains[j].asset_id,
                            f"shared_ns:{ns}",
                        ))

        # Deduplicate (order-independent)
        seen: set[frozenset] = set()
        unique: list[Correlation] = []
        for a, b, reason in correlations:
            key = frozenset({a, b})
            if key not in seen:
                seen.add(key)
                unique.append((a, b, reason))

        return unique

    @staticmethod
    def classify(value: str) -> AssetType:
        """Heuristic asset type classification from a raw string value."""
        try:
            ipaddress.ip_address(value)
            return AssetType.HOST
        except ValueError:
            pass
        if value.startswith(("http://", "https://")):
            return AssetType.URL
        if value.startswith("/"):
            return AssetType.ENDPOINT
        parts = value.split(".")
        return AssetType.DOMAIN if len(parts) <= 2 else AssetType.DOMAIN

from __future__ import annotations

import base64
import json
import logging
from urllib.parse import urljoin, urlparse

from js_intelligence.domain.value_objects.source_map_entry import SourceMapEntry

log = logging.getLogger(__name__)

# Base64 characters used in VLQ encoding
_B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_B64_VALUES = {c: i for i, c in enumerate(_B64_CHARS)}

_VLQ_CONTINUATION = 0x20  # bit 5
_VLQ_SIGN_BIT = 0x01       # bit 0 of first group
_VLQ_VALUE_BITS = 0x1F     # bits 0-4


class VLQDecoder:
    """Pure-Python Base64 VLQ decoder for source map `mappings` fields.

    Reference: https://docs.google.com/document/d/1U1RGAehQwRypUTovF1KRlpiOFze0b-_2gc6fAH0KY0k
    """

    @staticmethod
    def decode(segment: str) -> list[int]:
        """Decode a VLQ-encoded segment string into a list of integers.

        Each encoded integer maps to:
        [generated_column, sources_index, original_line, original_column, names_index]
        """
        result: list[int] = []
        shift = 0
        value = 0

        for char in segment:
            digit = _B64_VALUES.get(char)
            if digit is None:
                raise ValueError(f"Invalid Base64 VLQ character: {char!r}")

            continuation = digit & _VLQ_CONTINUATION
            digit &= _VLQ_VALUE_BITS

            if shift == 0:
                # First group: bit 0 is sign bit
                digit_without_sign = digit >> 1
                negative = bool(digit & _VLQ_SIGN_BIT)
                value = digit_without_sign
                shift = 4
            else:
                value |= digit << shift
                shift += 5

            if not continuation:
                result.append(-value if negative else value)  # type: ignore[possibly-undefined]
                shift = 0
                value = 0
                negative = False

        return result


class SourceMapParser:
    """Parses a v3 source map JSON and reconstructs SourceMapEntry objects."""

    @staticmethod
    def parse(map_json: dict, generated_url: str) -> list[SourceMapEntry]:
        """Reconstruct source entries from a source map.

        Args:
            map_json: Parsed source map JSON (v3 format).
            generated_url: Absolute URL of the generated JS file (for relative source resolution).

        Returns:
            List of SourceMapEntry, one per unique (generated_file, original_file) pair.
        """
        sources: list[str] = map_json.get("sources", [])
        names: list[str] = map_json.get("names", [])
        mappings_str: str = map_json.get("mappings", "")
        sources_content: list[str | None] = map_json.get("sourcesContent", [])

        if not sources or not mappings_str:
            return []

        base_url = generated_url
        resolved_sources = [_resolve_source(s, base_url) for s in sources]

        # Track which names map to which (generated_file, original_file) pair
        # Key: (generated_file, original_file), Value: set of symbol names
        entry_map: dict[tuple[str, str], set[str]] = {}

        # State for relative VLQ deltas
        original_line = 0
        original_column = 0
        sources_idx = 0
        names_idx = 0

        groups = mappings_str.split(";")  # each group is a generated line
        generated_file = generated_url

        for group in groups:
            generated_column = 0  # reset per line
            if not group:
                continue
            segments = group.split(",")
            for seg in segments:
                if not seg:
                    continue
                try:
                    decoded = VLQDecoder.decode(seg)
                except ValueError as exc:
                    log.debug("source_map.vlq_decode_error", extra={"err": str(exc)})
                    continue

                if len(decoded) < 4:
                    continue  # no source mapping for this segment

                generated_column += decoded[0]
                sources_idx += decoded[1]
                original_line += decoded[2]
                original_column += decoded[3]

                if sources_idx < 0 or sources_idx >= len(resolved_sources):
                    continue

                original_file = resolved_sources[sources_idx]
                key = (generated_file, original_file)

                if key not in entry_map:
                    entry_map[key] = set()

                if len(decoded) >= 5:
                    name_idx = names_idx + decoded[4]
                    names_idx = name_idx
                    if 0 <= name_idx < len(names):
                        entry_map[key].add(names[name_idx])

        return [
            SourceMapEntry(
                generated_file=gen,
                original_file=orig,
                symbols=tuple(sorted(syms)),
            )
            for (gen, orig), syms in entry_map.items()
        ]

    @staticmethod
    def parse_json_bytes(raw: bytes, generated_url: str) -> list[SourceMapEntry]:
        """Convenience: parse raw bytes (JSON or data URI) into SourceMapEntry list."""
        text = raw.decode("utf-8", errors="replace").strip()

        # Handle inline data URI: data:application/json;base64,...
        if text.startswith("data:"):
            try:
                _, encoded = text.split(",", 1)
                text = base64.b64decode(encoded).decode("utf-8", errors="replace")
            except Exception as exc:
                log.debug("source_map.data_uri_decode_error", extra={"err": str(exc)})
                return []

        try:
            map_json = json.loads(text)
        except json.JSONDecodeError as exc:
            log.debug("source_map.json_parse_error", extra={"err": str(exc)})
            return []

        return SourceMapParser.parse(map_json, generated_url)


def _resolve_source(source: str, base_url: str) -> str:
    """Resolve a source path relative to the generated file's URL."""
    if source.startswith(("http://", "https://", "data:")):
        return source
    if source.startswith("//"):
        parsed = urlparse(base_url)
        return f"{parsed.scheme}:{source}"
    return urljoin(base_url, source)

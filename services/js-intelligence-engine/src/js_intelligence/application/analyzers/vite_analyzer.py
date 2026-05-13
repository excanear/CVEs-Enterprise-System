from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

# Vite __vite__mapDeps([n1, n2, ...]) — chunk index array for lazy loading
_VITE_MAP_DEPS_RE = re.compile(r"__vite__mapDeps\(\s*\[([^\]]*)\]", re.DOTALL)

# Vite manifest entry: "src/main.ts": { "file": "assets/main-abc123.js", "imports": [...] }
_VITE_MANIFEST_FILE_RE = re.compile(
    r'"([^"]+\.(?:js|ts|tsx|jsx|mjs))"[^{]*\{[^}]*"file"\s*:\s*"([^"]+)"'
)


@dataclass
class ViteManifest:
    """Extracted Vite bundle structure."""

    entry_points: list[str] = field(default_factory=list)
    chunks: dict[str, list[str]] = field(default_factory=dict)  # source → [output files]
    map_deps_indices: list[list[int]] = field(default_factory=list)


class ViteAnalyzer:
    """Extracts Vite manifest information from JS content and manifest JSON."""

    def analyze(self, content: str, manifest_json: dict | None) -> ViteManifest:
        result = ViteManifest()

        # Parse __vite__mapDeps calls from bundle content
        for m in _VITE_MAP_DEPS_RE.finditer(content):
            raw = m.group(1).strip()
            if not raw:
                continue
            try:
                indices = [int(x.strip()) for x in raw.split(",") if x.strip().lstrip("-").isdigit()]
                if indices:
                    result.map_deps_indices.append(indices)
            except ValueError:
                pass

        # Parse Vite /assets/manifest.json if available
        if manifest_json:
            self._parse_manifest(manifest_json, result)
        else:
            # Fallback: regex scan of raw bundle content
            for m in _VITE_MANIFEST_FILE_RE.finditer(content):
                source = m.group(1)
                output = m.group(2)
                result.chunks.setdefault(source, []).append(output)

        return result

    def _parse_manifest(self, manifest: dict, result: ViteManifest) -> None:
        """Parse structured Vite manifest.json."""
        for source_file, entry in manifest.items():
            if not isinstance(entry, dict):
                continue
            output_file = entry.get("file", "")
            if output_file:
                result.chunks.setdefault(source_file, []).append(output_file)

            # Entry points have "isEntry": true
            if entry.get("isEntry"):
                result.entry_points.append(source_file)

            # imports lists lazy chunks
            for imp in entry.get("imports", []):
                if isinstance(imp, str):
                    result.chunks.setdefault(source_file, []).append(imp)

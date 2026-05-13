from __future__ import annotations

import re
from dataclasses import dataclass, field

from js_intelligence.infrastructure.ast.tree_sitter_parser import ParseResult

# Webpack 5 module registry: __webpack_modules__ = { "moduleId": function(...) { ... } }
_WP5_MODULES_RE = re.compile(
    r"__webpack_modules__\s*=\s*\{([^}]{1,50000})\}", re.DOTALL
)
# Module ID keys in the registry (string or numeric)
_WP_MODULE_KEY_RE = re.compile(r"""(?:^|,)\s*["']?(\w[\w/.\-]*)["']?\s*:""", re.MULTILINE)

# Webpack 5 chunk manifest: __webpack_require__.u = function(chunkId) { return chunkId + "." + {...}[chunkId] + ".js" }
# Simplified: capture numeric or string chunk-id → filename patterns
_WP5_CHUNK_MAP_RE = re.compile(
    r'\{([^}]{1,20000})\}\s*\[chunkId\]', re.DOTALL
)
_WP_CHUNK_ENTRY_RE = re.compile(r"""["']?(\w+)["']?\s*:\s*["']([^"']+)["']""")

# Webpack 4: webpackJsonp([ [chunkId], {...modules...} ])
_WP4_CHUNK_ID_RE = re.compile(r"webpackJsonp\(\s*\[\s*(\d+)\s*\]")


@dataclass
class WebpackManifest:
    """Extracted webpack bundle structure."""

    modules: dict[str, str] = field(default_factory=dict)  # moduleId → label
    chunks: dict[str, list[str]] = field(default_factory=dict)  # chunkId → [filename]
    is_webpack4: bool = False


class WebpackAnalyzer:
    """Extracts webpack module and chunk manifests from JS content."""

    def analyze(self, content: str, ast_result: ParseResult) -> WebpackManifest:
        manifest = WebpackManifest()

        # Try Webpack 5 module registry
        wp5_match = _WP5_MODULES_RE.search(content)
        if wp5_match:
            registry_text = wp5_match.group(1)
            for m in _WP_MODULE_KEY_RE.finditer(registry_text):
                mod_id = m.group(1).strip()
                if mod_id:
                    manifest.modules[mod_id] = mod_id

        # Try Webpack 5 chunk map (chunkId → filename)
        for chunk_map_m in _WP5_CHUNK_MAP_RE.finditer(content):
            chunk_block = chunk_map_m.group(1)
            for entry_m in _WP_CHUNK_ENTRY_RE.finditer(chunk_block):
                chunk_id = entry_m.group(1)
                filename = entry_m.group(2)
                manifest.chunks.setdefault(chunk_id, []).append(filename)

        # Try Webpack 4 chunk IDs
        for wp4_m in _WP4_CHUNK_ID_RE.finditer(content):
            chunk_id = wp4_m.group(1)
            if chunk_id not in manifest.chunks:
                manifest.chunks[chunk_id] = []
                manifest.is_webpack4 = True

        # Supplement with AST dynamic imports (webpackChunkName magic comments)
        for chunk_name in ast_result.webpack_chunk_names:
            if chunk_name and chunk_name not in manifest.chunks:
                manifest.chunks[chunk_name] = []

        return manifest

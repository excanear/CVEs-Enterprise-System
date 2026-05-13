from __future__ import annotations

import re
from dataclasses import dataclass, field

import tree_sitter_javascript as tslang
from tree_sitter import Language, Node, Parser

# Compile the JS grammar once at module level
_JS_LANGUAGE = Language(tslang.language())

# String patterns that look like URL paths (router paths)
_URL_PATH_RE = re.compile(r"^/[a-zA-Z0-9_/\-:.*]+$")

# Webpack magic comment: /* webpackChunkName: "name" */
_WEBPACK_CHUNK_NAME_RE = re.compile(
    r"/\*\s*webpackChunkName\s*:\s*['\"]([^'\"]+)['\"]\s*\*/"
)

# Route object pattern in source text (fast pre-filter)
_ROUTE_PROP_RE = re.compile(r"""["']?path["']?\s*:\s*["']([^"']+)["']""")


@dataclass
class ParseResult:
    """Extracted information from a single JS file AST traversal."""

    source_url: str
    import_paths: list[str] = field(default_factory=list)
    require_paths: list[str] = field(default_factory=list)
    dynamic_import_paths: list[str] = field(default_factory=list)
    webpack_chunk_names: list[str] = field(default_factory=list)
    url_path_strings: list[str] = field(default_factory=list)
    route_path_strings: list[str] = field(default_factory=list)
    # raw text content for regex-based pattern matching
    raw_text: str = ""


class TreeSitterJSParser:
    """Singleton JS parser backed by tree-sitter-javascript.

    Call ``initialize()`` once at startup; then use ``parse()`` per file.
    CPU-bound — wrap in asyncio.to_thread when called from async context.
    """

    _instance: "TreeSitterJSParser | None" = None

    def __init__(self) -> None:
        self._parser = Parser(_JS_LANGUAGE)

    @classmethod
    def initialize(cls) -> "TreeSitterJSParser":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def get(cls) -> "TreeSitterJSParser":
        if cls._instance is None:
            raise RuntimeError("TreeSitterJSParser not initialized. Call initialize() first.")
        return cls._instance

    def parse(self, content: bytes, source_url: str = "") -> ParseResult:
        """Parse JS content and extract structural information.

        This is CPU-bound; call via asyncio.to_thread in async contexts.
        """
        result = ParseResult(source_url=source_url)
        raw_text = content.decode("utf-8", errors="replace")
        result.raw_text = raw_text

        # Fast regex pass for webpack magic comments (survives minification)
        result.webpack_chunk_names = _WEBPACK_CHUNK_NAME_RE.findall(raw_text)

        # Fast regex pass for route path props
        for m in _ROUTE_PROP_RE.finditer(raw_text):
            path = m.group(1)
            if _URL_PATH_RE.match(path):
                result.route_path_strings.append(path)

        # AST-based extraction
        try:
            tree = self._parser.parse(content)
            self._walk(tree.root_node, result)
        except Exception:
            # tree-sitter is error-tolerant; if it still fails, fall back to regex only
            pass

        # Deduplicate while preserving order
        result.import_paths = list(dict.fromkeys(result.import_paths))
        result.require_paths = list(dict.fromkeys(result.require_paths))
        result.dynamic_import_paths = list(dict.fromkeys(result.dynamic_import_paths))
        result.url_path_strings = list(dict.fromkeys(result.url_path_strings))
        result.route_path_strings = list(dict.fromkeys(result.route_path_strings))

        return result

    def _walk(self, node: Node, result: ParseResult) -> None:
        """Recursively walk AST nodes and extract relevant strings."""
        node_type = node.type

        if node_type == "import_statement":
            self._handle_import(node, result)
        elif node_type == "call_expression":
            self._handle_call(node, result)

        for child in node.children:
            self._walk(child, result)

    def _handle_import(self, node: Node, result: ParseResult) -> None:
        """Extract static import paths: import X from '...'"""
        for child in node.children:
            if child.type == "string":
                path = _strip_quotes(child.text)
                if path:
                    result.import_paths.append(path)

    def _handle_call(self, node: Node, result: ParseResult) -> None:
        """Extract require(), import(), and URL-like string arguments."""
        children = node.children
        if not children:
            return

        func = children[0]

        # require('...')
        if func.type == "identifier" and func.text == b"require":
            args = _get_args(node)
            for arg in args:
                if arg.type == "string":
                    path = _strip_quotes(arg.text)
                    if path:
                        result.require_paths.append(path)
            return

        # import('...') — dynamic import
        if func.type == "import":
            args = _get_args(node)
            for arg in args:
                if arg.type == "string":
                    path = _strip_quotes(arg.text)
                    if path:
                        result.dynamic_import_paths.append(path)
            return

        # Any call with a string argument that looks like a URL path
        args = _get_args(node)
        for arg in args:
            if arg.type == "string":
                val = _strip_quotes(arg.text)
                if val and _URL_PATH_RE.match(val):
                    result.url_path_strings.append(val)


def _get_args(call_node: Node) -> list[Node]:
    """Return argument nodes from a call_expression."""
    for child in call_node.children:
        if child.type == "arguments":
            return [c for c in child.children if c.type not in {"(", ")", ","}]
    return []


def _strip_quotes(text: bytes | None) -> str:
    """Strip surrounding quotes from a string node's text."""
    if not text:
        return ""
    s = text.decode("utf-8", errors="replace").strip()
    if len(s) >= 2 and s[0] in ('"', "'", "`") and s[-1] in ('"', "'", "`"):
        return s[1:-1]
    return s

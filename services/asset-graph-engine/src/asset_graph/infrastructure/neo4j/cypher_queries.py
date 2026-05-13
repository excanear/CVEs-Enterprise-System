"""All Cypher query strings for Asset Graph Engine.

Centralised here so graph_repository.py stays clean and queries
can be reviewed / tuned in one place.

Conventions:
  - Parameters use $param_name (camelCase for multi-word: $tenantId → $tid)
  - MERGE uses business keys stored as node properties (node_id)
  - All queries filter by tenant_id to enforce logical tenant isolation
"""
from __future__ import annotations

# ── Bootstrap ──────────────────────────────────────────────────────────────────

BOOTSTRAP_CONSTRAINTS: list[str] = [
    # Uniqueness constraints (also create backing indexes automatically)
    "CREATE CONSTRAINT asset_node_id IF NOT EXISTS FOR (n:Asset) REQUIRE n.node_id IS UNIQUE",
    "CREATE CONSTRAINT endpoint_node_id IF NOT EXISTS FOR (n:Endpoint) REQUIRE n.node_id IS UNIQUE",
    "CREATE CONSTRAINT service_node_id IF NOT EXISTS FOR (n:Service) REQUIRE n.node_id IS UNIQUE",
    "CREATE CONSTRAINT dependency_node_id IF NOT EXISTS FOR (n:Dependency) REQUIRE n.node_id IS UNIQUE",
    "CREATE CONSTRAINT route_node_id IF NOT EXISTS FOR (n:Route) REQUIRE n.node_id IS UNIQUE",
    "CREATE CONSTRAINT tenant_node_id IF NOT EXISTS FOR (n:Tenant) REQUIRE n.node_id IS UNIQUE",
]

BOOTSTRAP_INDEXES: list[str] = [
    "CREATE INDEX asset_tenant_idx IF NOT EXISTS FOR (n:Asset) ON (n.tenant_id)",
    "CREATE INDEX endpoint_tenant_idx IF NOT EXISTS FOR (n:Endpoint) ON (n.tenant_id)",
    "CREATE INDEX endpoint_verdict_idx IF NOT EXISTS FOR (n:Endpoint) ON (n.verdict)",
    "CREATE INDEX route_tenant_idx IF NOT EXISTS FOR (n:Route) ON (n.tenant_id)",
    "CREATE INDEX dependency_name_idx IF NOT EXISTS FOR (n:Dependency) ON (n.name)",
]

# ── Node upsert ────────────────────────────────────────────────────────────────

UPSERT_ASSET = """
MERGE (n:Asset {node_id: $node_id})
SET n += {
    tenant_id: $tenant_id,
    url: $url,
    host: $host,
    port: $port,
    scheme: $scheme,
    asset_type: $asset_type,
    updated_at: datetime()
}
"""

UPSERT_ENDPOINT = """
MERGE (n:Endpoint {node_id: $node_id})
SET n += {
    tenant_id: $tenant_id,
    url: $url,
    path: $path,
    method: $method,
    exposure_type: $exposure_type,
    verdict: $verdict,
    confidence: $confidence,
    poc_triggered: $poc_triggered,
    updated_at: datetime()
}
"""

UPSERT_SERVICE = """
MERGE (n:Service {node_id: $node_id})
SET n += {
    tenant_id: $tenant_id,
    host: $host,
    port: $port,
    protocol: $protocol,
    internal: $internal,
    updated_at: datetime()
}
"""

UPSERT_DEPENDENCY = """
MERGE (n:Dependency {node_id: $node_id})
SET n += {
    tenant_id: $tenant_id,
    name: $name,
    version: $version,
    ecosystem: $ecosystem,
    updated_at: datetime()
}
"""

UPSERT_ROUTE = """
MERGE (n:Route {node_id: $node_id})
SET n += {
    tenant_id: $tenant_id,
    path: $path,
    router_type: $router_type,
    component_hint: $component_hint,
    updated_at: datetime()
}
"""

# Generic: only used when label is not one of the specific types above
UPSERT_GENERIC_NODE = """
MERGE (n {node_id: $node_id})
SET n += $properties
"""

# ── Edge upsert ────────────────────────────────────────────────────────────────

UPSERT_EDGE = """
MATCH (a {node_id: $from_id})
MATCH (b {node_id: $to_id})
MERGE (a)-[r:{edge_type}]->(b)
SET r += $properties
SET r.updated_at = datetime()
"""

# ── Update ─────────────────────────────────────────────────────────────────────

UPDATE_ENDPOINT_CONFIDENCE = """
MATCH (n:Endpoint {node_id: $endpoint_id})
SET n.confidence = $confidence,
    n.verdict = $verdict,
    n.updated_at = datetime()
"""

# ── Attack Paths ───────────────────────────────────────────────────────────────

ATTACK_PATHS = """
MATCH (src:Endpoint {tenant_id: $tid, verdict: 'TRUE_POSITIVE'})
MATCH (dst:Asset {tenant_id: $tid})
MATCH p = allShortestPaths((src)-[*..8]->(dst))
WHERE length(p) > 0
  AND all(n IN nodes(p) WHERE
    (n:Endpoint AND n.tenant_id = $tid) OR
    (n:Asset    AND n.tenant_id = $tid) OR
    (n:Service  AND n.tenant_id = $tid)
  )
WITH p, length(p) AS hops,
     src.node_id AS src_id,
     dst.node_id AS dst_id
RETURN src_id, dst_id, hops,
       [n IN nodes(p) | {node_id: n.node_id, label: head(labels(n)), url: n.url, host: n.host}] AS path_nodes
ORDER BY hops ASC
LIMIT $max_paths
"""

# ── Trust Chains ───────────────────────────────────────────────────────────────

TRUST_CHAINS = """
MATCH (root:Asset {node_id: $asset_id, tenant_id: $tid})
MATCH p = (root)-[:TRUSTS*1..$max_depth]->(leaf:Asset)
WHERE leaf.tenant_id = $tid
WITH p, length(p) AS depth,
     [r IN relationships(p) | {
         from_asset_id: startNode(r).node_id,
         to_asset_id:   endNode(r).node_id,
         trust_type:    coalesce(r.trust_type, 'UNKNOWN'),
         origin:        r.origin
     }] AS links,
     collect(leaf.node_id) AS terminals
RETURN depth, links, terminals
ORDER BY depth ASC
LIMIT 50
"""

# ── Exposure Propagation (APOC) ────────────────────────────────────────────────

EXPOSURE_PROPAGATION_APOC = """
MATCH (start:Endpoint {tenant_id: $tid, verdict: 'TRUE_POSITIVE'})
CALL apoc.path.subgraphNodes(start, {
    relationshipFilter: 'CALLS>|TRUSTS>',
    maxLevel: $max_depth,
    labelFilter: '+Asset'
}) YIELD node
WHERE node.tenant_id = $tid
WITH start, node,
     apoc.algo.dijkstra(start, node, 'CALLS>|TRUSTS>', 'weight') AS path_info
RETURN start.node_id AS origin_endpoint_id,
       node.node_id  AS asset_id,
       node.url      AS asset_url,
       node.host     AS asset_host
"""

# Fallback without APOC (variable-length match)
EXPOSURE_PROPAGATION_NATIVE = """
MATCH (start:Endpoint {tenant_id: $tid, verdict: 'TRUE_POSITIVE'})
MATCH p = (start)-[:CALLS|TRUSTS*1..$max_depth]->(asset:Asset)
WHERE asset.tenant_id = $tid
WITH start.node_id AS origin_endpoint_id,
     asset.node_id AS asset_id,
     asset.url     AS asset_url,
     asset.host    AS asset_host,
     length(p)     AS hop_distance,
     last(relationships(p)).type AS reached_via
RETURN DISTINCT origin_endpoint_id, asset_id, asset_url, asset_host, hop_distance, reached_via
ORDER BY hop_distance ASC
LIMIT 200
"""

# ── Dependency Risk ────────────────────────────────────────────────────────────

DEPENDENCY_RISKS = """
MATCH (a:Asset {tenant_id: $tid})-[r:DEPENDS_ON]->(d:Dependency)
OPTIONAL MATCH (d)-[:HAS_CVE]->(cve)
RETURN a.node_id AS asset_id,
       a.url     AS asset_url,
       d.node_id AS dep_id,
       d.name    AS name,
       d.version AS version,
       d.ecosystem AS ecosystem,
       collect(cve.cve_id) AS cve_ids,
       max(cve.cvss)       AS max_cvss
ORDER BY asset_id, name
"""

# ── Infra Map ──────────────────────────────────────────────────────────────────

INFRA_MAP = """
MATCH (a:Asset {tenant_id: $tid})-[:HOSTED_ON]->(s:Service)
OPTIONAL MATCH (s)-[:CONNECTS_TO]->(s2:Service)
RETURN a.node_id AS asset_id,
       a.url     AS asset_url,
       s.node_id AS service_id,
       s.host    AS service_host,
       s.port    AS service_port,
       s.protocol AS service_protocol,
       s.internal AS service_internal,
       collect({
           node_id:  s2.node_id,
           host:     s2.host,
           port:     s2.port,
           protocol: s2.protocol
       }) AS connected_services
ORDER BY a.url
"""

# ── Stats ──────────────────────────────────────────────────────────────────────

GRAPH_STATS = """
CALL apoc.meta.stats() YIELD labels, relTypesCount
RETURN labels, relTypesCount
"""

GRAPH_STATS_NATIVE = """
MATCH (n)
WHERE n.tenant_id = $tid
WITH labels(n)[0] AS label, count(n) AS cnt
RETURN collect({label: label, count: cnt}) AS label_counts

UNION ALL

MATCH (a {tenant_id: $tid})-[r]->(b {tenant_id: $tid})
RETURN collect({type: type(r), count: count(r)}) AS label_counts
"""

# Per-tenant counts (safer — no APOC needed)
STATS_NODES = """
MATCH (n)
WHERE n.tenant_id = $tid
RETURN labels(n)[0] AS label, count(n) AS cnt
"""

STATS_EDGES = """
MATCH (a {tenant_id: $tid})-[r]->(b)
RETURN type(r) AS edge_type, count(r) AS cnt
"""

# ── Asset List ─────────────────────────────────────────────────────────────────

LIST_ASSETS = """
MATCH (a:Asset {tenant_id: $tid})
RETURN a.node_id   AS node_id,
       a.url       AS url,
       a.host      AS host,
       a.port      AS port,
       a.scheme    AS scheme,
       a.asset_type AS asset_type
ORDER BY a.url
SKIP $offset
LIMIT $limit
"""

"""HTML renderer using Jinja2 with professional inline CSS."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from jinja2 import Environment, select_autoescape

_TIER_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#ca8a04",
    "LOW": "#16a34a",
}

_BASE_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>{{ title }}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #f1f5f9; color: #1e293b; }
  header { background: #0f172a; color: #fff; padding: 32px 48px; }
  header h1 { font-size: 1.9rem; font-weight: 700; letter-spacing: 0.02em; }
  header p  { font-size: 0.9rem; color: #94a3b8; margin-top: 6px; }
  .content  { max-width: 1100px; margin: 40px auto; padding: 0 24px 60px; }
  .card     { background: #fff; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,.08);
               padding: 28px; margin-bottom: 28px; }
  .card h2  { font-size: 1.15rem; font-weight: 600; border-bottom: 2px solid #e2e8f0;
               padding-bottom: 10px; margin-bottom: 18px; color: #0f172a; }
  .kpi-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px,1fr)); gap: 16px; }
  .kpi      { background: #f8fafc; border-radius: 8px; padding: 18px; text-align: center;
               border: 1px solid #e2e8f0; }
  .kpi .num { font-size: 2rem; font-weight: 700; }
  .kpi .lbl { font-size: 0.78rem; color: #64748b; margin-top: 4px; }
  .tier-CRITICAL { color: #dc2626; }
  .tier-HIGH     { color: #ea580c; }
  .tier-MEDIUM   { color: #ca8a04; }
  .tier-LOW      { color: #16a34a; }
  table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
  th { background: #0f172a; color: #fff; padding: 10px 14px; text-align: left; }
  td { padding: 9px 14px; border-bottom: 1px solid #e2e8f0; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #f8fafc; }
  .badge { display: inline-block; border-radius: 4px; padding: 2px 8px;
            font-size: 0.75rem; font-weight: 600; color: #fff; }
  .badge-CRITICAL { background:#dc2626; }
  .badge-HIGH     { background:#ea580c; }
  .badge-MEDIUM   { background:#ca8a04; }
  .badge-LOW      { background:#16a34a; }
  footer { text-align: center; font-size: 0.78rem; color: #94a3b8; margin-top: 40px; }
  pre { background: #0f172a; color: #e2e8f0; padding: 16px; border-radius: 6px;
        overflow-x: auto; font-size: 0.82rem; white-space: pre-wrap; word-break: break-all; }
  ol { padding-left: 20px; }
  ol li { margin: 6px 0; }
</style>
</head>
<body>
<header>
  <h1>{{ title }}</h1>
  <p>Tenant: {{ tenant_id }} &nbsp;|&nbsp; Generated: {{ generated_at }}</p>
</header>
<div class="content">
{{ body }}
</div>
<footer>CVEs Enterprise System &copy; {{ year }} &mdash; Confidential</footer>
</body>
</html>"""

_ENV = Environment(autoescape=select_autoescape(["html"]))


def _render_base(title: str, tenant_id: str, body: str) -> str:
    tmpl = _ENV.from_string(_BASE_TEMPLATE)
    return tmpl.render(
        title=title,
        tenant_id=tenant_id,
        body=body,
        generated_at=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        year=datetime.now(UTC).year,
    )


def render_executive(tenant_id: str, data: dict) -> str:
    exposures: list[dict] = data.get("exposures", [])
    clusters: list[dict] = data.get("clusters", [])

    tier_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for e in exposures:
        t = e.get("tier", "LOW")
        tier_counts[t] = tier_counts.get(t, 0) + 1

    kpis = "".join(
        f'<div class="kpi"><div class="num tier-{tier}">{count}</div>'
        f'<div class="lbl">{tier}</div></div>'
        for tier, count in tier_counts.items()
    )
    top5 = sorted(exposures, key=lambda x: x.get("composite_score", 0), reverse=True)[:5]
    rows = "".join(
        f'<tr><td>{e.get("target_url","")}</td>'
        f'<td><span class="badge badge-{e.get("tier","LOW")}">{e.get("tier","LOW")}</span></td>'
        f'<td>{e.get("exposure_type","")}</td>'
        f'<td>{e.get("composite_score",0):.2f}</td></tr>'
        for e in top5
    )
    body = f"""
<div class="card">
  <h2>Risk Summary</h2>
  <div class="kpi-grid">
    <div class="kpi"><div class="num">{len(exposures)}</div><div class="lbl">Total Findings</div></div>
    <div class="kpi"><div class="num">{len(clusters)}</div><div class="lbl">Clusters</div></div>
    {kpis}
  </div>
</div>
<div class="card">
  <h2>Top 5 Critical Findings</h2>
  <table>
    <thead><tr><th>URL</th><th>Tier</th><th>Type</th><th>Score</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>"""
    return _render_base("Executive Security Report", tenant_id, body)


def render_technical(tenant_id: str, data: dict) -> str:
    exposures: list[dict] = data.get("exposures", [])
    paths: list[dict] = data.get("paths", [])

    rows = "".join(
        f'<tr><td>{e.get("target_url","")}</td>'
        f'<td><span class="badge badge-{e.get("tier","LOW")}">{e.get("tier","LOW")}</span></td>'
        f'<td>{e.get("exposure_type","")}</td>'
        f'<td>{e.get("composite_score",0):.3f}</td>'
        f'<td>{e.get("rationale","")}</td></tr>'
        for e in exposures
    )
    path_html = ""
    for p in paths[:20]:
        nodes = " → ".join(p.get("nodes", []) if isinstance(p.get("nodes"), list) else [])
        score = p.get("risk_score", p.get("score", 0))
        path_html += f'<p style="margin:6px 0"><strong>{score:.2f}</strong> &nbsp; {nodes}</p>'

    body = f"""
<div class="card">
  <h2>All Findings ({len(exposures)})</h2>
  <table>
    <thead><tr><th>URL</th><th>Tier</th><th>Type</th><th>Score</th><th>Rationale</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>
<div class="card">
  <h2>Top Attack Paths</h2>
  {path_html or '<p>No attack paths recorded.</p>'}
</div>"""
    return _render_base("Technical Security Report", tenant_id, body)


def render_remediation(tenant_id: str, data: dict) -> str:
    remediations: list[dict] = data.get("remediations", [])
    exposures: list[dict] = data.get("exposures", [])

    # build tier→exposure_type mapping
    tier_map: dict[str, list[dict]] = {}
    for e in exposures:
        tier_map.setdefault(e.get("tier", "LOW"), []).append(e)

    blocks = ""
    for tier in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        tier_exps = tier_map.get(tier, [])
        if not tier_exps:
            continue
        exp_types = {e.get("exposure_type") for e in tier_exps}
        matched = [r for r in remediations if r.get("exposure_type") in exp_types]
        if not matched:
            continue
        items = ""
        for rem in matched:
            steps_html = "<ol>" + "".join(f"<li>{s}</li>" for s in rem.get("steps", [])) + "</ol>"
            narrative = rem.get("llm_narrative", "")
            items += (
                f'<div style="margin-bottom:18px">'
                f'<strong>{rem.get("exposure_type","")}</strong>'
                f'{"<p style=\'margin:8px 0;color:#475569\'>" + narrative + "</p>" if narrative else ""}'
                f'{steps_html}</div>'
            )
        blocks += f'<div class="card"><h2><span class="badge badge-{tier}">{tier}</span> Tier</h2>{items}</div>'

    body = blocks or '<div class="card"><p>No remediation data available.</p></div>'
    return _render_base("Remediation Guidance Report", tenant_id, body)


def render_compliance(tenant_id: str, data: dict) -> str:
    findings: list[dict] = data.get("compliance_findings", [])

    rows = ""
    for f in findings:
        owasp = ", ".join(f.get("owasp_top10", []))
        cwe   = ", ".join(f.get("cwe_ids", []))
        pci   = ", ".join(f.get("pci_dss_40", []))
        iso   = ", ".join(f.get("iso_27001_2022", []))
        nist  = ", ".join(f.get("nist_csf_20", []))
        rows += (
            f'<tr><td>{f.get("target_url","")}</td>'
            f'<td><span class="badge badge-{f.get("tier","LOW")}">{f.get("tier","LOW")}</span></td>'
            f'<td>{f.get("exposure_type","")}</td>'
            f'<td>{owasp}</td><td>{cwe}</td><td>{pci}</td>'
            f'<td>{iso}</td><td>{nist}</td></tr>'
        )

    body = f"""
<div class="card">
  <h2>Compliance Mapping ({len(findings)} findings)</h2>
  <table>
    <thead><tr>
      <th>URL</th><th>Tier</th><th>Type</th>
      <th>OWASP 2021</th><th>CWE</th><th>PCI-DSS 4.0</th>
      <th>ISO 27001:2022</th><th>NIST CSF 2.0</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>
</div>"""
    return _render_base("Compliance Mapping Report", tenant_id, body)

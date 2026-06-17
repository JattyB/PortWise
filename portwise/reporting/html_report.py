from __future__ import annotations

import html
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from portwise.utils.files import ensure_text, make_json_safe

_VERSION = "1.0"

_SEV_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#2563eb",
    "info": "#64748b",
    "informational": "#64748b",
}
_SEV_ORDER = ["critical", "high", "medium", "low", "info", "informational"]
_CONF_COLORS = {
    "confirmed": "#059669",
    "likely": "#2563eb",
    "possible": "#d97706",
    "needs_manual_validation": "#64748b",
    "needs manual validation": "#64748b",
}
_CAT_COLORS = {
    "vulnerability": "#ea580c",
    "best_practice": "#2563eb",
    "best practice": "#2563eb",
    "information": "#64748b",
    "hygiene": "#64748b",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def write_html_report(data: dict[str, Any], output_path: Path) -> Path:
    data = make_json_safe(data)
    findings = data.get("findings", [])
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    page = "\n".join([
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>PortWise — {esc(data.get('project', 'Report'))}</title>",
        f"<style>{_css()}</style>",
        "</head>",
        "<body>",
        _render_header(data, ts),
        _render_stat_cards(data),
        _render_executive_summary(data),
        _render_charts(findings),
        _render_retest_diff(data),
        _render_filter_and_table(findings),
        _render_sections(data),
        _render_footer(ts),
        f"<script>{_js()}</script>",
        "</body>",
        "</html>",
    ])
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(page, encoding="utf-8")
    return output_path


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

def _css() -> str:
    return """
:root{
--bg:#eef1f6;--surface:#ffffff;--surface-2:#f8fafc;--border:#e2e8f0;--border-2:#edf1f6;
--ink:#0f172a;--ink-2:#334155;--muted:#64748b;--accent:#4f46e5;--accent-soft:#eef2ff;
--critical:#dc2626;--high:#ea580c;--medium:#d97706;--low:#2563eb;--info:#64748b;
--ok:#059669;
--mono:'SFMono-Regular',ui-monospace,'JetBrains Mono','Cascadia Code',Menlo,Consolas,monospace;
--sans:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
--shadow:0 1px 2px rgba(15,23,42,.04),0 4px 12px rgba(15,23,42,.06);
}
*{box-sizing:border-box;margin:0;padding:0}
html{background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:14px;line-height:1.55;-webkit-font-smoothing:antialiased}
body{min-height:100vh;max-width:1180px;margin:0 auto;padding-bottom:40px}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
/* header */
.site-header{background:linear-gradient(120deg,#1e1b4b 0%,#312e81 55%,#4338ca 100%);
color:#fff;padding:30px 36px;display:flex;align-items:center;gap:24px;flex-wrap:wrap;
border-radius:0 0 14px 14px;box-shadow:var(--shadow)}
.logo{font-size:24px;font-weight:800;letter-spacing:-.5px;color:#fff;flex-shrink:0;display:flex;align-items:center;gap:10px}
.logo::before{content:'';width:14px;height:14px;border-radius:4px;background:#a5b4fc;box-shadow:0 0 0 4px rgba(165,180,252,.25)}
.header-meta{flex:1;color:#c7d2fe;font-size:12.5px;line-height:1.9}
.header-meta strong{color:#fff;font-weight:600}
.badge-confidential{background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.4);
color:#fff;padding:6px 14px;border-radius:6px;font-size:10.5px;font-weight:700;letter-spacing:1.5px;white-space:nowrap}
/* stat cards */
.stat-section{padding:26px 36px 6px}
.stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:14px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;
padding:18px 18px;box-shadow:var(--shadow);position:relative;overflow:hidden}
.stat-card::before{content:'';position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--accent);opacity:.85}
.stat-card.sev-critical::before{background:var(--critical)}
.stat-card.sev-high::before{background:var(--high)}
.stat-card.sev-medium::before{background:var(--medium)}
.stat-card.sev-low::before{background:var(--low)}
.stat-value{font-size:32px;font-weight:800;line-height:1.05;margin-bottom:4px;letter-spacing:-1px}
.stat-label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;font-weight:600}
/* charts */
.charts-section{padding:22px 36px}
.charts-row{display:flex;gap:18px;flex-wrap:wrap}
.chart-wrap{background:var(--surface);border:1px solid var(--border);border-radius:12px;
padding:20px 22px;flex:1;min-width:240px;box-shadow:var(--shadow)}
.chart-title{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;font-weight:700;margin-bottom:16px}
.chart-inner{display:flex;align-items:center;gap:22px;flex-wrap:wrap}
.chart-legend{display:flex;flex-direction:column;gap:7px}
.legend-item{display:flex;align-items:center;gap:8px;font-size:12px}
.legend-dot{width:11px;height:11px;border-radius:3px;flex-shrink:0}
.legend-label{color:var(--ink-2);min-width:96px}
.legend-count{color:var(--ink);font-weight:600;font-variant-numeric:tabular-nums}
/* filter bar */
.findings-section{padding:12px 36px 30px}
.findings-header{display:flex;align-items:center;gap:12px;margin-bottom:16px}
.findings-header h2{font-size:16px;font-weight:700;letter-spacing:-.2px;color:var(--ink)}
.visible-count{font-size:12px;color:var(--muted);margin-left:auto}
.filter-row{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;align-items:center}
.filter-label{font-size:10.5px;color:var(--muted);text-transform:uppercase;letter-spacing:.7px;font-weight:700;margin-right:4px;white-space:nowrap}
.filter-btn{background:var(--surface);border:1px solid var(--border);color:var(--ink-2);
padding:5px 14px;border-radius:8px;font-size:12px;cursor:pointer;transition:all .12s;font-family:var(--sans);font-weight:500;white-space:nowrap}
.filter-btn:hover{border-color:var(--accent);color:var(--accent)}
.filter-btn.active{border-color:var(--accent);color:#fff;background:var(--accent)}
.search-box{background:var(--surface);border:1px solid var(--border);color:var(--ink);
padding:7px 14px;border-radius:8px;font-size:13px;font-family:var(--sans);outline:none;width:230px;transition:border-color .12s}
.search-box:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
/* findings table */
.table-wrap{overflow-x:auto;border:1px solid var(--border);border-radius:12px;box-shadow:var(--shadow);background:var(--surface)}
.findings-table{width:100%;border-collapse:collapse}
.findings-table thead th{background:var(--surface-2);color:var(--muted);font-size:10.5px;
font-weight:700;text-transform:uppercase;letter-spacing:.7px;padding:12px 14px;
border-bottom:1px solid var(--border);text-align:left;white-space:nowrap}
.findings-table td{padding:11px 14px;border-bottom:1px solid var(--border-2);vertical-align:middle;font-size:13px}
.finding-row{cursor:pointer;transition:background .1s}
.finding-row:hover{background:var(--accent-soft)}
.finding-detail td{background:var(--surface-2);padding:0}
.detail-inner{padding:18px 22px;border-left:3px solid var(--accent)}
.detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:10px}
.detail-field label{font-size:10.5px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;font-weight:700;display:block;margin-bottom:4px}
.detail-field p{font-size:13px;color:var(--ink-2);line-height:1.6}
.cve-list{margin-top:12px;display:flex;flex-direction:column;gap:7px}
.cve-item{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:9px 13px;font-size:12px}
.cve-id{color:var(--accent);font-weight:700}
.kev-badge{background:#fef2f2;border:1px solid var(--critical);color:var(--critical);
padding:1px 7px;border-radius:5px;font-size:9.5px;font-weight:700;letter-spacing:.4px;margin-left:6px}
.evidence-items{margin-top:6px;display:flex;flex-direction:column;gap:5px}
.evidence-item{font-size:12px;color:var(--ink-2);padding:6px 10px;background:var(--surface);border:1px solid var(--border-2);border-radius:6px}
.evidence-transcript,.cmd-block{background:#0f172a;border:1px solid #1e293b;border-radius:8px;
padding:11px 14px;font-size:12px;color:#a5f3c0;overflow-x:auto;margin:6px 0;
white-space:pre-wrap;word-break:break-word;font-family:var(--mono);line-height:1.5}
/* badges */
.badge{display:inline-block;padding:3px 9px;border-radius:6px;font-size:10.5px;
font-weight:700;text-transform:uppercase;letter-spacing:.4px;white-space:nowrap}
.badge-critical{background:#fef2f2;color:#b91c1c;border:1px solid #fecaca}
.badge-high{background:#fff7ed;color:#c2410c;border:1px solid #fed7aa}
.badge-medium{background:#fffbeb;color:#b45309;border:1px solid #fde68a}
.badge-low{background:#eff6ff;color:#1d4ed8;border:1px solid #bfdbfe}
.badge-info,.badge-informational{background:#f1f5f9;color:#475569;border:1px solid #e2e8f0}
.badge-vulnerability{background:#fff7ed;color:#c2410c;border:1px solid #fed7aa}
.badge-best_practice,.badge-best-practice{background:#eff6ff;color:#1d4ed8;border:1px solid #bfdbfe}
.badge-information{background:#f1f5f9;color:#475569;border:1px solid #e2e8f0}
.badge-hygiene{background:#f1f5f9;color:#64748b;border:1px solid #e2e8f0}
.badge-confirmed{background:#ecfdf5;color:#047857;border:1px solid #a7f3d0}
.badge-likely{background:#eff6ff;color:#1d4ed8;border:1px solid #bfdbfe}
.badge-possible{background:#fffbeb;color:#b45309;border:1px solid #fde68a}
.badge-needs_manual_validation,.badge-needs-manual-validation{background:#f1f5f9;color:#64748b;border:1px solid #e2e8f0}
/* sections (collapsible) */
.section-wrap{padding:0 36px 16px}
details.collapsible{background:var(--surface);border:1px solid var(--border);border-radius:12px;overflow:hidden;margin-bottom:12px;box-shadow:var(--shadow)}
details.collapsible>summary{padding:15px 20px;cursor:pointer;font-weight:700;font-size:13.5px;
color:var(--ink);list-style:none;display:flex;align-items:center;gap:10px}
details.collapsible>summary::-webkit-details-marker{display:none}
details.collapsible>summary::before{content:'\25B8';color:var(--muted);transition:transform .15s;display:inline-block}
details.collapsible[open]>summary::before{transform:rotate(90deg)}
.section-count{background:var(--accent-soft);color:var(--accent);border-radius:20px;padding:1px 10px;font-size:11px;font-weight:700;margin-left:auto}
.section-content{padding:6px 20px 18px}
.asset-table,.mini-table{width:100%;border-collapse:collapse}
.asset-table th,.mini-table th{font-size:10.5px;color:var(--muted);text-transform:uppercase;
letter-spacing:.6px;padding:9px 12px;border-bottom:1px solid var(--border);text-align:left;font-weight:700}
.asset-table td,.mini-table td{padding:9px 12px;border-bottom:1px solid var(--border-2);vertical-align:top;font-size:12.5px}
.asset-table tr:last-child td,.mini-table tr:last-child td{border-bottom:none}
.svc-pill{display:inline-block;background:var(--surface-2);border:1px solid var(--border);
border-radius:6px;padding:2px 8px;font-size:11px;margin:2px 3px 2px 0;font-family:var(--mono);color:var(--ink-2)}
.empty-msg{color:var(--muted);font-size:13px;padding:12px 0;font-style:italic}
/* footer */
.site-footer{border-top:1px solid var(--border);padding:22px 36px;margin-top:18px;
color:var(--muted);font-size:12px;display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px}
.footer-tagline{color:var(--accent);font-weight:600}
.text-accent{color:var(--accent)}
.text-muted{color:var(--muted)}
.monospace{font-family:var(--mono)}
.str-bar{display:inline-block;height:7px;background:var(--accent);border-radius:4px;opacity:.85;vertical-align:middle;margin-right:6px}
/* executive summary */
.exec-section{padding:8px 36px 4px}
.exec-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:22px 24px;box-shadow:var(--shadow)}
.exec-title{font-size:15px;font-weight:800;letter-spacing:-.2px;margin-bottom:12px;color:var(--ink)}
.exec-chips{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px}
.exec-chip{font-size:11px;font-weight:700;border-radius:20px;padding:3px 12px;background:var(--surface-2);border:1px solid var(--border);color:var(--ink-2)}
.exec-critical{background:#fef2f2;color:#b91c1c;border-color:#fecaca}
.exec-high{background:#fff7ed;color:#c2410c;border-color:#fed7aa}
.exec-medium{background:#fffbeb;color:#b45309;border-color:#fde68a}
.exec-low{background:#eff6ff;color:#1d4ed8;border-color:#bfdbfe}
.exec-drivers{font-size:13px;color:var(--ink-2);margin-bottom:8px}
.exec-narrative{font-size:13px;color:var(--ink-2);line-height:1.7;margin-bottom:8px}
.exec-toplabel{font-size:10.5px;color:var(--muted);text-transform:uppercase;letter-spacing:.7px;font-weight:700;margin:10px 0 6px}
.exec-top{margin:0 0 0 18px;display:flex;flex-direction:column;gap:6px}
.exec-top li{font-size:13px;color:var(--ink-2)}
/* retest diff */
.retest-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px;margin-bottom:12px}
.retest-stat{border:1px solid var(--border);border-radius:10px;padding:12px 14px;background:var(--surface-2)}
.retest-stat .n{font-size:24px;font-weight:800}
.retest-fixed .n{color:var(--ok)}.retest-new .n{color:var(--high)}.retest-open .n{color:var(--medium)}
.exploit-badge{background:#fef2f2;border:1px solid var(--critical);color:var(--critical);padding:1px 7px;border-radius:5px;font-size:9.5px;font-weight:700;letter-spacing:.4px;margin-left:6px}
@media print{body{max-width:none}.filter-row,.search-box,.findings-header .visible-count{display:none}details.collapsible{break-inside:avoid}.site-header{border-radius:0}}
"""



# ---------------------------------------------------------------------------
# JS
# ---------------------------------------------------------------------------

def _js() -> str:
    return """
(function(){
var state={sev:'all',cat:'all',conf:'all'};
function norm(s){return(s||'').toLowerCase().replace(/\\s+/g,'_')}
function applyFilters(){
  var q=document.getElementById('pw-search').value.toLowerCase();
  var rows=document.querySelectorAll('.finding-row');
  var n=0;
  rows.forEach(function(row){
    var ds=row.dataset;
    var ok=(state.sev==='all'||norm(ds.severity)===state.sev)&&
            (state.cat==='all'||norm(ds.category)===state.cat)&&
            (state.conf==='all'||norm(ds.confidence)===state.conf)&&
            (!q||ds.title.toLowerCase().indexOf(q)>=0||ds.asset.toLowerCase().indexOf(q)>=0);
    row.style.display=ok?'':'none';
    var nxt=row.nextElementSibling;
    if(nxt&&nxt.classList.contains('finding-detail'))nxt.style.display='none';
    if(ok)n++;
  });
  var vc=document.getElementById('pw-count');
  if(vc)vc.textContent=n;
}
function setFilter(dim,val){
  state[dim]=val;
  document.querySelectorAll('[data-fdim="'+dim+'"]').forEach(function(b){
    b.classList.toggle('active',b.dataset.fval===val);
  });
  applyFilters();
}
function toggleDetail(row){
  var nxt=row.nextElementSibling;
  if(nxt&&nxt.classList.contains('finding-detail')){
    nxt.style.display=(nxt.style.display===''||nxt.style.display==='table-row')?'none':'';
  }
}
window.pw={setFilter:setFilter,toggleDetail:toggleDetail};
var si=document.getElementById('pw-search');
if(si)si.addEventListener('input',applyFilters);
})();
"""


# ---------------------------------------------------------------------------
# Page sections
# ---------------------------------------------------------------------------

def _render_header(data: dict[str, Any], ts: str) -> str:
    proj = esc(data.get("project") or "PortWise Assessment")
    prof = esc(data.get("profile") or "—")
    return (
        f'<header class="site-header">'
        f'<div class="logo">PortWise</div>'
        f'<div class="header-meta">'
        f'<strong>{proj}</strong> &nbsp;|&nbsp; Profile: {prof}'
        f'<br>Generated: {esc(ts)}'
        f'</div>'
        f'<div class="badge-confidential">CONFIDENTIAL — AUTHORIZED AUDIT ONLY</div>'
        f'</header>'
    )


def _render_stat_cards(data: dict[str, Any]) -> str:
    state = data.get("metadata", {}).get("state", {})
    findings = data.get("findings", [])
    targets = state.get("targets_loaded", [])
    live = state.get("live_hosts", [])
    services = sum(len(v) for v in state.get("services_by_host", {}).values())

    vulns = sum(1 for f in findings if _norm(f.get("category", "")) == "vulnerability")
    best_p = sum(1 for f in findings if _norm(f.get("category", "")) in {"best_practice", "best practice"})
    confirmed = sum(1 for f in findings if _norm(f.get("confidence", "")) == "confirmed")
    needs_val = sum(1 for f in findings if _norm(f.get("confidence", "")) in {"needs_manual_validation", "needs manual validation"})

    cards = [
        ("Targets", len(targets), "var(--muted)"),
        ("Live Hosts", len(live), "var(--low)"),
        ("Services", services, "var(--muted)"),
        ("Total Findings", len(findings), "var(--text)"),
        ("Vulnerabilities", vulns, "var(--high)"),
        ("Best Practice", best_p, "var(--low)"),
        ("Confirmed", confirmed, "var(--accent)"),
        ("Needs Validation", needs_val, "var(--medium)"),
    ]

    html_cards = "".join(
        f'<div class="stat-card">'
        f'<div class="stat-value" style="color:{c}">{v}</div>'
        f'<div class="stat-label">{esc(label)}</div>'
        f'</div>'
        for label, v, c in cards
    )
    return f'<section class="stat-section"><div class="stat-grid">{html_cards}</div></section>'


def _render_executive_summary(data: dict[str, Any]) -> str:
    from portwise.reporting.narrative import executive_summary_html
    return executive_summary_html(data, esc)


def _render_retest_diff(data: dict[str, Any]) -> str:
    retest = data.get("retest")
    if not isinstance(retest, dict) or not retest:
        return ""
    # Build a per-section rollup (Fixed / Still Open / New).
    stat_cells: list[str] = []
    fixed = sum(len(v.get("Fixed", [])) for v in retest.values() if isinstance(v, dict))
    still = sum(len(v.get("Still Open", [])) for v in retest.values() if isinstance(v, dict))
    new = sum(len(v.get("New", [])) for v in retest.values() if isinstance(v, dict))
    stat_cells.append(f'<div class="retest-stat retest-fixed"><div class="n">{fixed}</div><div class="stat-label">Fixed</div></div>')
    stat_cells.append(f'<div class="retest-stat retest-open"><div class="n">{still}</div><div class="stat-label">Still Open</div></div>')
    stat_cells.append(f'<div class="retest-stat retest-new"><div class="n">{new}</div><div class="stat-label">New</div></div>')

    rows: list[str] = []
    for section, statuses in retest.items():
        if not isinstance(statuses, dict):
            continue
        rows.append(
            f'<tr><td><strong>{esc(section)}</strong></td>'
            f'<td>{len(statuses.get("Fixed", []))}</td>'
            f'<td>{len(statuses.get("Still Open", []))}</td>'
            f'<td>{len(statuses.get("New", []))}</td></tr>'
        )
    new_items = []
    for section, statuses in retest.items():
        if isinstance(statuses, dict):
            for item in statuses.get("New", [])[:20]:
                new_items.append(f'<div class="evidence-item">{esc(section)}: {esc(str(item))}</div>')

    table = (
        '<table class="mini-table"><thead><tr><th>Section</th><th>Fixed</th><th>Still Open</th><th>New</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
    )
    new_block = (f'<div class="exec-toplabel">New since previous run</div>{"".join(new_items)}' if new_items else "")
    content = f'<div class="retest-grid">{"".join(stat_cells)}</div>{table}{new_block}'
    return f'<div class="section-wrap">{_collapsible("Retest Diff (vs previous run)", content, fixed + still + new, open_=True)}</div>'


def _render_charts(findings: list[dict[str, Any]]) -> str:
    sev_counts: dict[str, int] = {}
    for s in _SEV_ORDER:
        n = sum(1 for f in findings if _norm(f.get("severity", "")) in {s, s.rstrip("ational")})
        if n:
            sev_counts[s.capitalize()] = n

    conf_keys = ["Confirmed", "Likely", "Possible", "Needs Validation"]
    conf_map = {"Confirmed": "confirmed", "Likely": "likely", "Possible": "possible",
                "Needs Validation": "needs_manual_validation"}
    conf_counts: dict[str, int] = {}
    for k in conf_keys:
        n = sum(1 for f in findings if _norm(f.get("confidence", "")) in {conf_map[k], k.lower()})
        if n:
            conf_counts[k] = n

    donut_colors = {k.lower(): v for k, v in [
        ("critical", "#dc2626"), ("high", "#ea580c"), ("medium", "#d97706"),
        ("low", "#2563eb"), ("info", "#64748b"), ("informational", "#64748b"),
    ]}
    conf_colors = {
        "confirmed": "#059669", "likely": "#2563eb",
        "possible": "#d97706", "needs validation": "#64748b",
    }

    return (
        '<section class="charts-section">'
        '<div class="charts-row">'
        + _donut_chart(sev_counts, donut_colors, "Findings by Severity")
        + _bars_chart(conf_counts, conf_colors, "Findings by Confidence")
        + '</div></section>'
    )


def _donut_chart(counts: dict[str, int], colors: dict[str, str], title: str) -> str:
    total = sum(counts.values())
    r, cx, cy, sw = 68, 100, 100, 20
    circ = 2 * math.pi * r

    if total == 0:
        circle = (f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#1f2933" '
                  f'stroke-width="{sw}"/>'
                  f'<text x="{cx}" y="{cy}" text-anchor="middle" dominant-baseline="middle" '
                  f'fill="#64748b" font-size="14" font-family="monospace">0</text>')
        return (f'<div class="chart-wrap">'
                f'<div class="chart-title">{esc(title)}</div>'
                f'<div class="chart-inner"><svg width="200" height="200" viewBox="0 0 200 200">'
                f'{circle}</svg></div></div>')

    segments: list[str] = []
    legend_items: list[str] = []
    cumulative = 0.0
    for label, count in counts.items():
        color = colors.get(label.lower(), "#64748b")
        frac = count / total
        dash = frac * circ
        dashoffset = circ / 4 - cumulative
        segments.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{color}" '
            f'stroke-width="{sw}" stroke-dasharray="{dash:.2f} {circ:.2f}" '
            f'stroke-dashoffset="{dashoffset:.2f}"/>'
        )
        cumulative += dash
        pct = f"{frac * 100:.0f}%"
        legend_items.append(
            f'<div class="legend-item">'
            f'<span class="legend-dot" style="background:{color}"></span>'
            f'<span class="legend-label">{esc(label)}</span>'
            f'<span class="legend-count">{count} ({pct})</span>'
            f'</div>'
        )

    center = (
        f'<text x="{cx}" y="{cy - 8}" text-anchor="middle" dominant-baseline="middle" '
        f'fill="#e2e8f0" font-size="22" font-weight="700" font-family="monospace">{total}</text>'
        f'<text x="{cx}" y="{cy + 13}" text-anchor="middle" dominant-baseline="middle" '
        f'fill="#64748b" font-size="9" font-family="monospace">TOTAL</text>'
    )

    return (
        f'<div class="chart-wrap">'
        f'<div class="chart-title">{esc(title)}</div>'
        f'<div class="chart-inner">'
        f'<svg width="200" height="200" viewBox="0 0 200 200">'
        + "".join(segments) + center
        + '</svg>'
        + f'<div class="chart-legend">{"".join(legend_items)}</div>'
        + '</div></div>'
    )


def _bars_chart(counts: dict[str, int], colors: dict[str, str], title: str) -> str:
    if not counts:
        return (f'<div class="chart-wrap"><div class="chart-title">{esc(title)}</div>'
                f'<div class="empty-msg">No data</div></div>')

    max_val = max(counts.values(), default=1)
    bar_h, gap, label_w, bar_max = 18, 8, 148, 160
    total_w = label_w + bar_max + 36

    rows: list[str] = []
    y = 4
    for label, count in counts.items():
        color = colors.get(label.lower(), "#64748b")
        w = int(count / max_val * bar_max) if max_val else 0
        rows.append(
            f'<text x="{label_w - 6}" y="{y + bar_h - 4}" text-anchor="end" '
            f'fill="#64748b" font-size="11" font-family="monospace">{esc(label[:22])}</text>'
            f'<rect x="{label_w}" y="{y}" width="{w}" height="{bar_h}" fill="{color}" rx="2"/>'
            f'<text x="{label_w + w + 5}" y="{y + bar_h - 4}" fill="#e2e8f0" '
            f'font-size="11" font-family="monospace">{count}</text>'
        )
        y += bar_h + gap

    svg_h = y + 4
    return (
        f'<div class="chart-wrap">'
        f'<div class="chart-title">{esc(title)}</div>'
        f'<svg width="{total_w}" height="{svg_h}" viewBox="0 0 {total_w} {svg_h}">'
        + "".join(rows)
        + '</svg></div>'
    )


def _render_filter_and_table(findings: list[dict[str, Any]]) -> str:
    total = len(findings)
    sorted_findings = sorted(findings, key=lambda f: (
        _SEV_ORDER.index(_norm(f.get("severity", "info")).replace("ational", ""))
        if _norm(f.get("severity", "info")).replace("ational", "") in _SEV_ORDER else 99,
        str(f.get("priority", "P9")),
    ))

    sev_vals = sorted(set(_norm(f.get("severity", "info")) for f in findings))
    cat_vals = sorted(set(_norm(f.get("category", "")) for f in findings if f.get("category")))
    _conf_vals = sorted(set(_norm(f.get("confidence", "")) for f in findings if f.get("confidence")))

    def _filter_btns(dim: str, vals: list[str], label: str) -> str:
        btns = [f'<button class="filter-btn active" data-fdim="{dim}" data-fval="all" '
                f'onclick="pw.setFilter(\'{dim}\',\'all\')">All</button>']
        for v in vals:
            display = v.replace("_", " ").title()
            btns.append(
                f'<button class="filter-btn" data-fdim="{dim}" data-fval="{esc(v)}" '
                f'onclick="pw.setFilter(\'{dim}\',\'{esc(v)}\')">{esc(display)}</button>'
            )
        return f'<div class="filter-row"><span class="filter-label">{esc(label)}</span>{"".join(btns)}</div>'

    rows: list[str] = []
    for idx, f in enumerate(sorted_findings):
        rows.extend(_finding_row_pair(f, idx))

    table = (
        f'<div class="table-wrap">'
        f'<table class="findings-table">'
        f'<thead><tr>'
        f'<th>Severity</th><th>Title</th><th>Asset : Port</th>'
        f'<th>Category</th><th>Confidence</th>'
        f'<th title="Evidence Strength">Str.</th>'
        f'<th title="False Positive Risk">FP</th>'
        f'<th>Module</th>'
        f'</tr></thead>'
        f'<tbody id="findings-body">{"".join(rows)}</tbody>'
        f'</table></div>'
    )

    return (
        f'<section class="findings-section">'
        f'<div class="findings-header">'
        f'<h2>All Findings</h2>'
        f'<span class="visible-count"><span id="pw-count">{total}</span> shown</span>'
        f'</div>'
        + _filter_btns("sev", sev_vals, "Severity")
        + '<div class="filter-row">'
        + ('<span class="filter-label">Category</span>'
           + "".join(
               f'<button class="filter-btn{"" if i else " active"}" data-fdim="cat" data-fval="{esc(v) if i else "all"}" '
               f'onclick="pw.setFilter(\'cat\',\'{esc(v) if i else "all"}\')">{"All" if not i else esc(v.replace("_"," ").title())}</button>'
               for i, v in enumerate([""] + cat_vals)
           )
           if cat_vals else "")
        + '</div>'
        + '<div class="filter-row"><span class="filter-label">Search</span>'
          '<input id="pw-search" class="search-box" type="text" placeholder="title or asset…"></div>'
        + table
        + '</section>'
    )


def _finding_row_pair(f: dict[str, Any], idx: int) -> list[str]:
    sev = _norm(f.get("severity", "info"))
    cat = _norm(f.get("category", "information"))
    conf = _norm(f.get("confidence", ""))
    title = esc(f.get("title", "—"))
    asset = esc(str(f.get("asset", "—")))
    port = esc(str(f.get("port", "")))
    module = esc(str(f.get("module", "—")))
    fp = esc(str(f.get("false_positive_risk", "—")))
    es = int(f.get("evidence_strength", 0) or 0)
    str_bar = f'<span class="str-bar" style="width:{max(es * 12, 4)}px"></span>{es}/10'

    _conf_dash = '<span class="text-muted">—</span>'
    _em_dash = "<em class=\"text-muted\">—</em>"
    row = (
        f'<tr class="finding-row" '
        f'data-severity="{esc(sev)}" data-category="{esc(cat)}" data-confidence="{esc(conf)}" '
        f'data-title="{title}" data-asset="{asset}" '
        f'onclick="pw.toggleDetail(this)">'
        f'<td>{_sev_badge(sev)}</td>'
        f'<td>{title}</td>'
        f'<td>{asset}{(":" + port) if port else ""}</td>'
        f'<td>{_cat_badge(cat)}</td>'
        f'<td>{_conf_badge(conf) if conf else _conf_dash}</td>'
        f'<td>{str_bar}</td>'
        f'<td class="text-muted">{fp}</td>'
        f'<td class="text-muted">{module}</td>'
        f'</tr>'
    )

    desc = esc(f.get("description", ""))
    rec = esc(f.get("recommendation", ""))
    cves_html = _cves_html(f.get("cves", []) or [])
    evidence_html = _evidence_html(f.get("evidence", []) or [])
    exploit_html = _exploit_html(f)
    tags = ", ".join(esc(t) for t in (f.get("tags") or []))

    detail = (
        f'<tr class="finding-detail" style="display:none">'
        f'<td colspan="8"><div class="detail-inner">'
        f'<div class="detail-grid">'
        f'<div class="detail-field"><label>Description</label><p>{desc or _em_dash}</p></div>'
        f'<div class="detail-field"><label>Recommendation</label><p>{rec or _em_dash}</p></div>'
        f'</div>'
        + (f'<div class="detail-field" style="margin-top:10px"><label>Evidence</label>{evidence_html}</div>' if evidence_html else "")
        + exploit_html
        + (f'<div style="margin-top:8px"><span class="text-muted" style="font-size:10px">TAGS: </span>{tags}</div>' if tags else "")
        + cves_html
        + '</div></td></tr>'
    )

    return [row, detail]


def _exploit_html(f: dict[str, Any]) -> str:
    if not f.get("exploit_available"):
        return ""
    refs = f.get("exploit_refs") or []
    items = "".join(f'<div class="evidence-item">{esc(str(r))}</div>' for r in refs[:8])
    if not items:
        items = '<div class="evidence-item">A public exploit is known.</div>'
    return (
        '<div class="detail-field" style="margin-top:10px">'
        '<label>Exploit Availability <span class="exploit-badge">EXPLOIT AVAILABLE</span></label>'
        f'<div class="evidence-items">{items}</div>'
        '</div>'
    )


def _cves_html(cves: list[dict[str, Any]]) -> str:
    if not cves:
        return ""
    items: list[str] = []
    for c in cves[:10]:
        cid = esc(c.get("cve_id", ""))
        cvss = c.get("cvss_score")
        epss = c.get("epss_score")
        kev = c.get("kev", False)
        desc = esc(c.get("description", "")[:200])
        refs = c.get("references", []) or []
        kev_badge = '<span class="kev-badge">KEV</span>' if kev else ""
        scores = " ".join(filter(None, [
            f'CVSS {cvss:.1f}' if isinstance(cvss, (int, float)) else "",
            f'EPSS {float(epss):.3f}' if epss is not None else "",
        ]))
        ref_links = " ".join(
            f'<a href="{esc(r)}" target="_blank" rel="noopener">ref</a>'
            for r in (refs[:3] if isinstance(refs, list) else [])
            if isinstance(r, str) and r.startswith("http")
        )
        items.append(
            f'<div class="cve-item">'
            f'<span class="cve-id">{cid}</span>{kev_badge}'
            + (f' <span class="text-muted">{esc(scores)}</span>' if scores else "")
            + (f' {ref_links}' if ref_links else "")
            + (f'<br><span class="text-muted">{desc}</span>' if desc else "")
            + '</div>'
        )
    return '<div class="cve-list">' + "".join(items) + "</div>"


def _evidence_html(evidence: list[dict[str, Any]]) -> str:
    if not evidence:
        return ""
    items: list[str] = []
    for e in evidence[:5]:
        src = esc(e.get("source", e.get("type", "")))
        desc = esc(e.get("description", "")[:160])
        transcript = (e.get("data") or {}).get("transcript")
        if isinstance(transcript, dict):
            req = transcript.get("request", {})
            resp = transcript.get("response", {})
            probe = esc(str(req.get("probe") or req.get("method", "") + " " + req.get("url", "")))
            status = esc(str(resp.get("status", "")))
            body = esc(str(resp.get("body_excerpt", ""))[:400])
            timing = esc(str(transcript.get("timing_ms", "")))
            panel = (
                f'<div class="evidence-transcript">'
                f'<div><strong>Probe:</strong> {probe}</div>'
                f'<div><strong>Status:</strong> {status}'
                + (f' &nbsp; <strong>Timing:</strong> {timing}ms' if timing else "")
                + f'</div>'
                f'<pre style="margin:4px 0;font-size:10px;white-space:pre-wrap;word-break:break-all">{body}</pre>'
                f'</div>'
            )
            items.append(f'<div class="evidence-item"><strong>{src}</strong>: {desc}{panel}</div>')
        else:
            items.append(f'<div class="evidence-item"><strong>{src}</strong>: {desc}</div>')
    return f'<div class="evidence-items">{"".join(items)}</div>'


def _render_sections(data: dict[str, Any]) -> str:
    findings = data.get("findings", [])
    state = data.get("metadata", {}).get("state", {})

    vulns = [f for f in findings if _norm(f.get("category", "")) == "vulnerability"]
    best_p = [f for f in findings if _norm(f.get("category", "")) in {"best_practice", "best practice"}]
    cve_f = [f for f in findings if f.get("cves")]
    tls_f = [f for f in findings if f.get("module") == "tls"]
    http_f = [f for f in findings if f.get("module") == "http"]
    exp_f = [f for f in findings if f.get("module") == "exposure"]
    skipped = state.get("skipped_phases", []) + data.get("skipped_checks", [])
    failed = state.get("failed_phases", []) + data.get("failed_checks", [])
    commands = data.get("commands", [])
    services = state.get("services_by_host", {})

    by_host = _per_host_view(findings)
    sections: list[str] = []
    sections.append(_collapsible("Findings by Host",
        by_host[0], by_host[1], open_=True))
    sections.append(_collapsible("Confirmed Vulnerabilities",
        _mini_table(sorted(vulns, key=lambda f: str(f.get("priority", "P9")))),
        len(vulns), open_=True))
    sections.append(_collapsible("Best-Practice / Hardening",
        _mini_table(best_p), len(best_p)))
    sections.append(_collapsible("CVE Findings",
        _cve_section(cve_f), len(cve_f)))
    sections.append(_collapsible("TLS Findings",
        _mini_table(tls_f), len(tls_f)))
    sections.append(_collapsible("HTTP Findings",
        _mini_table(http_f), len(http_f)))
    sections.append(_collapsible("Exposure Findings",
        _mini_table(exp_f), len(exp_f)))
    sections.append(_collapsible("Asset Inventory",
        _asset_inventory(services), len(services)))
    sections.append(_collapsible("Skipped & Failed Checks",
        _skipped_html(skipped, failed), len(skipped) + len(failed)))
    sections.append(_collapsible("Commands Executed",
        _commands_html(commands), len(commands)))

    return f'<div class="section-wrap">{"".join(sections)}</div>'


def _per_host_view(findings: list[dict[str, Any]]) -> tuple[str, int]:
    """Group findings by host with a per-host severity rollup. Returns (html, host_count)."""
    hosts: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        hosts.setdefault(str(f.get("asset", "—")), []).append(f)
    if not hosts:
        return ('<div class="empty-msg">No findings to group by host.</div>', 0)

    def host_rank(item: tuple[str, list[dict[str, Any]]]) -> tuple:
        sevs = [_norm(f.get("severity", "info")).replace("ational", "") for f in item[1]]
        best = min((_SEV_ORDER.index(s) for s in sevs if s in _SEV_ORDER), default=99)
        return (best, -len(item[1]))

    blocks: list[str] = []
    for host, host_findings in sorted(hosts.items(), key=host_rank):
        counts: dict[str, int] = {}
        for f in host_findings:
            s = _norm(f.get("severity", "info")).replace("ational", "")
            counts[s] = counts.get(s, 0) + 1
        chips = "".join(
            f'{_sev_badge(s)} {counts[s]}&nbsp;&nbsp;'
            for s in _SEV_ORDER if counts.get(s)
        )
        rows = "".join(
            f'<tr>'
            f'<td>{_sev_badge(_norm(f.get("severity", "info")))}</td>'
            f'<td>{esc(f.get("title", "—"))}'
            + ('<span class="exploit-badge">EXPLOIT</span>' if f.get("exploit_available") else "")
            + ('<span class="kev-badge">KEV</span>' if f.get("kev") else "")
            + f'</td>'
            f'<td class="text-muted">{esc(str(f.get("port", "")))}</td>'
            f'<td class="text-muted">{esc(f.get("module", "—"))}</td>'
            f'</tr>'
            for f in sorted(host_findings, key=lambda x: (
                _SEV_ORDER.index(_norm(x.get("severity", "info")).replace("ational", ""))
                if _norm(x.get("severity", "info")).replace("ational", "") in _SEV_ORDER else 99))
        )
        blocks.append(
            f'<div style="margin-bottom:14px">'
            f'<div style="font-weight:700;margin-bottom:6px">{esc(host)} &nbsp;<span class="text-muted" style="font-weight:400">{chips}</span></div>'
            f'<table class="mini-table"><thead><tr><th>Sev</th><th>Title</th><th>Port</th><th>Module</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>'
            f'</div>'
        )
    return ("".join(blocks), len(hosts))


def _collapsible(title: str, content: str, count: int, open_: bool = False) -> str:
    open_attr = " open" if open_ else ""
    return (
        f'<details class="collapsible"{open_attr}>'
        f'<summary>{esc(title)}<span class="section-count">{count}</span></summary>'
        f'<div class="section-content">{content}</div>'
        f'</details>'
    )


def _mini_table(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return '<div class="empty-msg">No findings in this category.</div>'
    rows = "".join(
        f'<tr>'
        f'<td>{_sev_badge(_norm(f.get("severity", "info")))}</td>'
        f'<td>{esc(f.get("title", "—"))}</td>'
        f'<td class="text-muted">{esc(str(f.get("asset", "—")))}'
        f'{(":" + str(f.get("port", ""))) if f.get("port") else ""}</td>'
        f'<td>{_cat_badge(_norm(f.get("category", "")))}</td>'
        f'<td class="text-muted">{esc(f.get("module", "—"))}</td>'
        f'</tr>'
        for f in findings
    )
    return (
        f'<table class="mini-table"><thead><tr>'
        f'<th>Sev</th><th>Title</th><th>Asset</th><th>Category</th><th>Module</th>'
        f'</tr></thead><tbody>{rows}</tbody></table>'
    )


def _cve_section(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return '<div class="empty-msg">No CVE findings.</div>'
    parts: list[str] = []
    for f in findings:
        cves = f.get("cves") or []
        for c in cves:
            cid = esc(c.get("cve_id", ""))
            cvss = c.get("cvss_score")
            epss = c.get("epss_score")
            kev = c.get("kev", False)
            desc = esc(c.get("description", "")[:300])
            refs = c.get("references", []) or []
            kev_badge = '<span class="kev-badge">KEV</span>' if kev else ""
            ref_links = " ".join(
                f'<a href="{esc(r)}" target="_blank" rel="noopener">&#x2197;</a>'
                for r in (refs[:4] if isinstance(refs, list) else [])
                if isinstance(r, str) and r.startswith("http")
            )
            cvss_str = f'CVSS {cvss:.1f}' if isinstance(cvss, (int, float)) else ""
            epss_str = f'EPSS {float(epss):.3f}' if epss is not None else ""
            parts.append(
                f'<div class="cve-item">'
                f'<span class="cve-id">{cid}</span>{kev_badge}'
                + (f' <span class="text-muted">{esc(cvss_str)} {esc(epss_str)}</span>' if cvss_str or epss_str else "")
                + (f' {ref_links}' if ref_links else "")
                + f'<br><span class="text-muted" style="font-size:10px">{esc(f.get("asset",""))}:{f.get("port","")}</span>'
                + (f'<br>{desc}' if desc else "")
                + '</div>'
            )
    return f'<div class="cve-list">{"".join(parts)}</div>'


def _asset_inventory(services: dict[str, Any]) -> str:
    if not services:
        return '<div class="empty-msg">No asset data.</div>'
    rows = "".join(
        f'<tr>'
        f'<td><strong>{esc(host)}</strong></td>'
        f'<td>{"".join(_svc_pill(s) for s in (svcs if isinstance(svcs, list) else []))}</td>'
        f'</tr>'
        for host, svcs in services.items()
    )
    return (
        f'<table class="asset-table"><thead><tr>'
        f'<th>Host</th><th>Services</th>'
        f'</tr></thead><tbody>{rows}</tbody></table>'
    )


def _svc_pill(svc: Any) -> str:
    if not isinstance(svc, dict):
        return f'<span class="svc-pill">{esc(str(svc))}</span>'
    proto = esc(svc.get("protocol", "tcp"))
    port = esc(str(svc.get("port", "?")))
    name = esc(svc.get("service_name", ""))
    prod = esc(svc.get("product", ""))
    ver = esc(svc.get("version", ""))
    label = f'{proto}/{port} {name}' + (f' {prod}' if prod else "") + (f' {ver}' if ver else "")
    return f'<span class="svc-pill">{label.strip()}</span>'


def _skipped_html(skipped: list[Any], failed: list[Any]) -> str:
    if not skipped and not failed:
        return '<div class="empty-msg">No skipped or failed checks.</div>'
    parts: list[str] = []
    if skipped:
        parts.append(f'<div class="text-muted" style="font-size:11px;margin-bottom:8px">Skipped ({len(skipped)})</div>')
        for item in skipped:
            parts.append(f'<div class="cmd-skip">{esc(str(item))}</div>')
    if failed:
        parts.append(f'<div class="text-muted" style="font-size:11px;margin:8px 0">Failed ({len(failed)})</div>')
        for item in failed:
            parts.append(f'<div class="cmd-err">{esc(str(item))}</div>')
    return "".join(parts)


def _commands_html(commands: list[Any]) -> str:
    if not commands:
        return '<div class="empty-msg">No commands recorded.</div>'
    parts: list[str] = []
    for cmd in commands:
        if not isinstance(cmd, dict):
            parts.append(f'<div class="cmd-block">{esc(str(cmd))}</div>')
            continue
        name = esc(cmd.get("name", ""))
        command_parts = cmd.get("command") or []
        cmd_str = esc(" ".join(command_parts) if isinstance(command_parts, list) else str(command_parts))
        skipped_msg = cmd.get("skipped")
        error_msg = cmd.get("error")
        parts.append(
            '<div>'
            + (f'<div class="cmd-name">{name}</div>' if name else "")
            + f'<div class="cmd-block">{cmd_str or "(no command)"}</div>'
            + (f'<div class="cmd-skip">Skipped: {esc(str(skipped_msg))}</div>' if skipped_msg else "")
            + (f'<div class="cmd-err">Error: {esc(str(error_msg))}</div>' if error_msg else "")
            + '</div>'
        )
    return "".join(parts)


def _render_footer(ts: str) -> str:
    return (
        f'<footer class="site-footer">'
        f'<div><span class="footer-tagline">PortWise {_VERSION}</span>'
        f' &nbsp;—&nbsp; Evidence-first VAPT intelligence</div>'
        f'<div class="text-muted">Generated {esc(ts)} &nbsp;—&nbsp; '
        f'Confidence scoring: Confirmed = version-range match on non-backport package; '
        f'Likely = version-range match (backport-sensitive); '
        f'Possible = keyword match only; '
        f'Needs Validation = version unknown.</div>'
        f'</footer>'
    )


# ---------------------------------------------------------------------------
# Badge helpers
# ---------------------------------------------------------------------------

def _sev_badge(sev: str) -> str:
    cls = sev.lower().replace(" ", "").replace("ational", "")
    label = sev.upper()[:4] if sev else "INFO"
    return f'<span class="badge badge-{esc(cls)}">{esc(label)}</span>'


def _cat_badge(cat: str) -> str:
    if not cat:
        return ""
    display = cat.replace("_", " ").title()
    cls = cat.lower().replace(" ", "_")
    return f'<span class="badge badge-{esc(cls)}">{esc(display)}</span>'


def _conf_badge(conf: str) -> str:
    if not conf:
        return ""
    display = conf.replace("_", " ").title()
    cls = conf.lower().replace(" ", "_")
    return f'<span class="badge badge-{esc(cls)}">{esc(display)}</span>'


# ---------------------------------------------------------------------------
# Utilities (kept for backward compat)
# ---------------------------------------------------------------------------

def esc(value: Any) -> str:
    return html.escape(ensure_text(value))


def _norm(value: Any) -> str:
    return str(value or "").lower().strip().replace(" ", "_")


# Keep old public helpers so existing callers don't break
def summary_cards(data: dict[str, Any]) -> str:
    return _render_stat_cards(data)


def findings_table(findings: list[dict[str, Any]]) -> str:
    return _render_filter_and_table(findings)

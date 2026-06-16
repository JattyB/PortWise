from __future__ import annotations

import html
import math
from typing import Any

from portwise.utils.files import ensure_text

SEV_ORDER = ["critical", "high", "medium", "low", "info", "informational"]
SEV_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#2563eb",
    "info": "#64748b",
    "informational": "#64748b",
}
CONF_COLORS = {
    "confirmed": "#059669",
    "likely": "#2563eb",
    "possible": "#d97706",
    "needs_manual_validation": "#64748b",
    "needs manual validation": "#64748b",
}
CAT_COLORS = {
    "vulnerability": "#ea580c",
    "best_practice": "#2563eb",
    "best practice": "#2563eb",
    "information": "#64748b",
    "hygiene": "#94a3b8",
}


def esc(value: Any) -> str:
    return html.escape(ensure_text(value))


def norm(value: Any) -> str:
    return str(value or "").lower().strip().replace(" ", "_")


def sev_badge(sev: str) -> str:
    cls = sev.lower().replace(" ", "").replace("ational", "")
    label = sev.upper()[:4] if sev else "INFO"
    return f'<span class="badge badge-{esc(cls)}">{esc(label)}</span>'


def conf_badge(conf: str) -> str:
    if not conf:
        return ""
    display = conf.replace("_", " ").title()
    cls = conf.lower().replace(" ", "_")
    return f'<span class="badge badge-{esc(cls)}">{esc(display)}</span>'


def cat_badge(cat: str) -> str:
    if not cat:
        return ""
    display = cat.replace("_", " ").title()
    cls = cat.lower().replace(" ", "_")
    return f'<span class="badge badge-{esc(cls)}">{esc(display)}</span>'


def css() -> str:
    return """
:root{
--bg:#eef1f6;--panel:#ffffff;--panel2:#f8fafc;--border:#e2e8f0;
--accent:#4f46e5;--critical:#dc2626;--high:#ea580c;--medium:#d97706;
--low:#2563eb;--info:#64748b;--text:#0f172a;--muted:#64748b;
--font:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
--mono:'SFMono-Regular',ui-monospace,'JetBrains Mono',Menlo,Consolas,monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
html{background:var(--bg);color:var(--text);font-family:var(--font);font-size:14px;line-height:1.55;-webkit-font-smoothing:antialiased}
body{min-height:100vh;position:relative}

a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.site-header{background:var(--panel);border-bottom:1px solid var(--border);
padding:14px 28px;display:flex;align-items:center;gap:20px;flex-wrap:wrap}
.logo{font-size:22px;font-weight:700;letter-spacing:3px;text-transform:uppercase;
color:var(--accent);flex-shrink:0}
.header-meta{flex:1;color:var(--muted);font-size:11px;line-height:1.9}
.header-meta strong{color:var(--text)}
.badge-confidential{background:rgba(255,45,45,.12);border:1px solid var(--critical);
color:var(--critical);padding:4px 12px;border-radius:4px;font-size:10px;font-weight:700;
letter-spacing:1.5px;white-space:nowrap}
.badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:10px;
font-weight:700;text-transform:uppercase;letter-spacing:.5px;white-space:nowrap}
.badge-critical{background:rgba(255,45,45,.18);color:#ff2d2d;border:1px solid #ff2d2d}
.badge-high{background:rgba(255,107,53,.18);color:#ff6b35;border:1px solid #ff6b35}
.badge-medium{background:rgba(255,210,63,.18);color:#ffd23f;border:1px solid #ffd23f}
.badge-low{background:rgba(76,201,240,.18);color:#4cc9f0;border:1px solid #4cc9f0}
.badge-info,.badge-informational{background:rgba(107,114,128,.18);color:#6b7280;border:1px solid #6b7280}
.badge-vulnerability{background:rgba(255,107,53,.12);color:#ff6b35;border:1px solid rgba(255,107,53,.4)}
.badge-best_practice,.badge-best-practice{background:rgba(76,201,240,.12);color:#4cc9f0;border:1px solid rgba(76,201,240,.4)}
.badge-information{background:rgba(107,114,128,.12);color:#6b7280;border:1px solid rgba(107,114,128,.4)}
.badge-hygiene{background:rgba(136,146,164,.12);color:#8892a4;border:1px solid rgba(136,146,164,.4)}
.badge-confirmed{background:#ecfdf5;color:#047857;border:1px solid #a7f3d0}
.badge-likely{background:rgba(76,201,240,.12);color:#4cc9f0;border:1px solid rgba(76,201,240,.4)}
.badge-possible{background:rgba(255,210,63,.12);color:#ffd23f;border:1px solid rgba(255,210,63,.4)}
.badge-needs_manual_validation,.badge-needs-manual-validation{background:rgba(107,114,128,.12);color:#8892a4;border:1px solid rgba(107,114,128,.4)}
.chart-wrap{background:var(--panel);border:1px solid var(--border);border-radius:7px;
padding:18px 20px;flex:1;min-width:220px}
.chart-title{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:14px}
.chart-inner{display:flex;align-items:center;gap:20px;flex-wrap:wrap}
.chart-legend{display:flex;flex-direction:column;gap:6px}
.legend-item{display:flex;align-items:center;gap:7px;font-size:11px}
.legend-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}
.legend-label{color:var(--muted);min-width:90px}
.legend-count{color:var(--text)}
.empty-msg{color:var(--muted);font-size:12px;padding:10px 0;font-style:italic}
.mini-table{width:100%;border-collapse:collapse}
.mini-table th{font-size:10px;color:var(--muted);text-transform:uppercase;
letter-spacing:.8px;padding:7px 10px;border-bottom:1px solid var(--border);text-align:left}
.mini-table td{padding:7px 10px;border-bottom:1px solid #13181f;vertical-align:top;font-size:11px}
.mini-table tr:last-child td{border-bottom:none}
.cmd-block{background:#0f172a;border:1px solid #1e293b;border-radius:8px;
padding:10px 14px;font-size:12px;color:#a5f3c0;overflow-x:auto;margin-bottom:6px;
white-space:pre-wrap;word-break:break-word;font-family:var(--mono)}
.site-footer{border-top:1px solid var(--border);padding:18px 28px;
margin-top:16px;color:var(--muted);font-size:11px;display:flex;
justify-content:space-between;flex-wrap:wrap;gap:8px}
.footer-tagline{color:var(--accent);font-weight:600;opacity:.8}
.text-accent{color:var(--accent)}
.text-muted{color:var(--muted)}
.str-bar{display:inline-block;height:6px;background:var(--accent);border-radius:3px;
opacity:.7;vertical-align:middle;margin-right:5px}
"""


def donut_chart(counts: dict[str, int], colors: dict[str, str], title: str) -> str:
    total = sum(counts.values())
    r, cx, cy, sw = 68, 100, 100, 20
    circ = 2 * math.pi * r

    if total == 0:
        circle = (
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#1f2933" stroke-width="{sw}"/>'
            f'<text x="{cx}" y="{cy}" text-anchor="middle" dominant-baseline="middle" '
            f'fill="#8892a4" font-size="14" font-family="monospace">0</text>'
        )
        return (
            f'<div class="chart-wrap"><div class="chart-title">{esc(title)}</div>'
            f'<div class="chart-inner"><svg width="200" height="200" viewBox="0 0 200 200">'
            f'{circle}</svg></div></div>'
        )

    segments: list[str] = []
    legend_items: list[str] = []
    cumulative = 0.0
    for label, count in counts.items():
        color = colors.get(label.lower(), "#6b7280")
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
        f'fill="#8892a4" font-size="9" font-family="monospace">TOTAL</text>'
    )

    return (
        f'<div class="chart-wrap"><div class="chart-title">{esc(title)}</div>'
        f'<div class="chart-inner">'
        f'<svg width="200" height="200" viewBox="0 0 200 200">'
        + "".join(segments) + center
        + f'</svg><div class="chart-legend">{"".join(legend_items)}</div>'
        + '</div></div>'
    )


def bar_chart(counts: dict[str, int], colors: dict[str, str], title: str) -> str:
    if not counts:
        return (
            f'<div class="chart-wrap"><div class="chart-title">{esc(title)}</div>'
            f'<div class="empty-msg">No data</div></div>'
        )

    max_val = max(counts.values(), default=1)
    bar_h, gap, label_w, bar_max = 18, 8, 148, 160
    total_w = label_w + bar_max + 36

    rows: list[str] = []
    y = 4
    for label, count in counts.items():
        color = colors.get(label.lower(), "#6b7280")
        w = int(count / max_val * bar_max) if max_val else 0
        rows.append(
            f'<text x="{label_w - 6}" y="{y + bar_h - 4}" text-anchor="end" '
            f'fill="#8892a4" font-size="11" font-family="monospace">{esc(label[:22])}</text>'
            f'<rect x="{label_w}" y="{y}" width="{w}" height="{bar_h}" fill="{color}" rx="2"/>'
            f'<text x="{label_w + w + 5}" y="{y + bar_h - 4}" fill="#e2e8f0" '
            f'font-size="11" font-family="monospace">{count}</text>'
        )
        y += bar_h + gap

    svg_h = y + 4
    return (
        f'<div class="chart-wrap"><div class="chart-title">{esc(title)}</div>'
        f'<svg width="{total_w}" height="{svg_h}" viewBox="0 0 {total_w} {svg_h}">'
        + "".join(rows)
        + '</svg></div>'
    )

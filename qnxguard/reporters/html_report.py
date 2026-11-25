"""Self-contained interactive HTML dashboard reporter for QNXGuard."""
import html
import json
from ..models import AuditReport


def to_html(report: AuditReport) -> str:
    data = report.to_dict()
    score = data["score"]
    score_color = "#10b981" if score >= 85 else ("#f59e0b" if score >= 50 else "#ef4444")
    sev_badges = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#eab308",
        "LOW": "#38bdf8",
        "INFO": "#94a3b8",
    }
    rows_html = []
    for f in data["findings"]:
        c = sev_badges.get(f["severity"], "#94a3b8")
        doc_link = (
            f'<a href="{html.escape(f["qnx_doc_ref"])}" target="_blank" rel="noopener">QNX 8.0 Docs</a>'
            if f.get("qnx_doc_ref") else ""
        )
        rows_html.append(f"""
        <div class="card" data-sev="{html.escape(f['severity'])}">
          <div class="card-head">
            <span class="badge" style="background:{c}">{html.escape(f['severity'])}</span>
            <span class="rule">{html.escape(f['rule_id'])}</span>
            <span class="cat">{html.escape(f['category'])}</span>
            <span class="loc">{html.escape(f['file'])}:{f['line']}</span>
          </div>
          <h3>{html.escape(f['title'])}</h3>
          <pre class="snippet">{html.escape(f['snippet'])}</pre>
          <p class="msg">{html.escape(f['message'])}</p>
          <p class="fix"><strong>Remediation:</strong> {html.escape(f['remediation'])} {doc_link}</p>
        </div>
        """)
    if not rows_html:
        rows_html.append('<div class="card pass"><h3>All QNX 8.0 safety, buildfile, and real-time checks passed!</h3></div>')

    s = data["summary"]
    by = s["by_severity"]
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>QNXGuard Audit Report — {html.escape(data['target_dir'])}</title>
<style>
  body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; background:#0b1120; color:#e2e8f0; margin:0; padding:28px; }}
  .wrap {{ max-width:1080px; margin:0 auto; }}
  header {{ display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid #1e293b; padding-bottom:18px; margin-bottom:24px; }}
  h1 {{ margin:0; font-size:24px; color:#f8fafc; }}
  .sub {{ color:#94a3b8; font-size:13px; margin-top:4px; }}
  .score {{ font-size:36px; font-weight:800; color:{score_color}; border:2px solid {score_color}; border-radius:12px; padding:10px 20px; }}
  .stats {{ display:grid; grid-template-columns:repeat(6,1fr); gap:12px; margin-bottom:20px; }}
  .stat {{ background:#111827; border:1px solid #1f2937; border-radius:10px; padding:14px; text-align:center; }}
  .stat .num {{ font-size:24px; font-weight:700; }}
  .stat .lbl {{ font-size:11px; color:#94a3b8; text-transform:uppercase; letter-spacing:0.06em; }}
  .filters {{ margin-bottom:18px; display:flex; gap:8px; flex-wrap:wrap; }}
  .fbtn {{ background:#1e293b; color:#e2e8f0; border:1px solid #334155; border-radius:8px; padding:6px 14px; cursor:pointer; font-size:13px; }}
  .fbtn.active {{ background:#2563eb; border-color:#3b82f6; color:#fff; }}
  .card {{ background:#111827; border:1px solid #1f2937; border-radius:12px; padding:16px 20px; margin-bottom:14px; }}
  .card.pass {{ border-color:#10b981; color:#a7f3d0; }}
  .card-head {{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin-bottom:8px; font-size:12px; }}
  .badge {{ color:#0b1120; font-weight:800; padding:2px 8px; border-radius:6px; }}
  .rule {{ font-family:monospace; color:#93c5fd; font-weight:700; }}
  .cat {{ color:#94a3b8; }}
  .loc {{ margin-left:auto; font-family:monospace; color:#cbd5e1; }}
  h3 {{ margin:6px 0 8px; font-size:16px; color:#f8fafc; }}
  .snippet {{ background:#020617; border:1px solid #1e293b; border-radius:8px; padding:10px; overflow-x:auto; font-size:12px; color:#7dd3fc; }}
  .msg {{ color:#cbd5e1; font-size:14px; margin:8px 0; }}
  .fix {{ color:#a7f3d0; font-size:13px; margin:6px 0 0; }}
  a {{ color:#60a5fa; margin-left:8px; }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div>
      <h1>QNXGuard — QNX SDP 8.0 Static Safety &amp; Real-Time Audit</h1>
      <div class="sub">Target: {html.escape(data['target_dir'])} | Scanned {s['files_scanned']} files ({s['buildfiles_scanned']} IFS buildfiles, {s['c_files_scanned']} C/C++ files, {s['toolchain_files_scanned']} build configs)</div>
    </div>
    <div class="score">{score}/100</div>
  </header>
  <div class="stats">
    <div class="stat"><div class="num">{s['total_findings']}</div><div class="lbl">Total</div></div>
    <div class="stat"><div class="num" style="color:#ef4444">{by['CRITICAL']}</div><div class="lbl">Critical</div></div>
    <div class="stat"><div class="num" style="color:#f97316">{by['HIGH']}</div><div class="lbl">High</div></div>
    <div class="stat"><div class="num" style="color:#eab308">{by['MEDIUM']}</div><div class="lbl">Medium</div></div>
    <div class="stat"><div class="num" style="color:#38bdf8">{by['LOW']}</div><div class="lbl">Low</div></div>
    <div class="stat"><div class="num" style="color:#10b981">{s['files_scanned']}</div><div class="lbl">Files</div></div>
  </div>
  <div class="filters">
    <button class="fbtn active" onclick="filterSev('ALL', this)">All ({s['total_findings']})</button>
    <button class="fbtn" onclick="filterSev('CRITICAL', this)">Critical ({by['CRITICAL']})</button>
    <button class="fbtn" onclick="filterSev('HIGH', this)">High ({by['HIGH']})</button>
    <button class="fbtn" onclick="filterSev('MEDIUM', this)">Medium ({by['MEDIUM']})</button>
    <button class="fbtn" onclick="filterSev('LOW', this)">Low ({by['LOW']})</button>
  </div>
  <div id="cards">{''.join(rows_html)}</div>
</div>
<script>
function filterSev(sev, btn) {{
  document.querySelectorAll('.fbtn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.card[data-sev]').forEach(c => {{
    c.style.display = (sev === 'ALL' || c.dataset.sev === sev) ? 'block' : 'none';
  }});
}}
</script>
</body>
</html>
"""

"""Executive HTML compliance report (self-contained, light/dark, print-friendly)."""
from __future__ import annotations

from html import escape as _esc

_RESULT_CLASS = {"PASS": "ok", "FAIL": "bad", "MANUAL": "warn"}
_RISK_CLASS = {
    "Very High": "r-vh", "High": "r-h", "Moderate": "r-m",
    "Low": "r-l", "Very Low": "r-vl", "N/A": "r-na",
}

_CSS = """
:root{
  --bg:#f6f8fb; --card:#ffffff; --ink:#0f1b2d; --muted:#5b6b82; --line:#e3e9f2;
  --navy:#0b2447; --teal:#1f8a8a;
  --ok:#188038; --warn:#c77700; --bad:#c5221f;
  --r-vh:#7a0010; --r-h:#c5221f; --r-m:#c77700; --r-l:#1a73e8; --r-vl:#188038; --r-na:#8a97a8;
}
@media (prefers-color-scheme:dark){
  :root:not([data-theme="light"]){
    --bg:#0c1118; --card:#131b26; --ink:#e8eef6; --muted:#9bb0c7; --line:#223042;
    --navy:#9fc0ff; --teal:#5fd0d0;
  }
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:980px;margin:0 auto;padding:28px 16px 72px}
header.top{background:linear-gradient(135deg,var(--navy),#123a63);color:#fff;border-radius:14px;
  padding:24px 26px;margin-bottom:22px}
:root:not([data-theme="light"]) header.top{color:#fff}
header.top h1{margin:0 0 4px;font-size:22px;letter-spacing:.2px}
header.top .sub{opacity:.85;font-size:13px}
.meta{display:flex;flex-wrap:wrap;gap:10px 22px;margin-top:14px;font-size:12.5px;opacity:.95}
.meta code{background:rgba(255,255,255,.14);padding:1px 6px;border-radius:5px;color:#fff;word-break:break-all}
.verdict{display:inline-block;margin-top:14px;padding:8px 14px;border-radius:9px;font-weight:600;font-size:14px}
.v-bad{background:#fdecea;color:#7a0010}.v-warn{background:#fff4e0;color:#8a5200}.v-ok{background:#e6f4ea;color:#0f5126}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin:0 0 16px}
h2{font-size:16px;margin:2px 0 14px;color:var(--navy)}
h2 .n{color:var(--muted);font-weight:500}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.stat{background:var(--bg);border:1px solid var(--line);border-radius:10px;padding:12px}
.stat b{display:block;font-size:22px}.stat span{font-size:12px;color:var(--muted)}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:11.5px;font-weight:600;color:#fff}
.ok{background:var(--ok)}.warn{background:var(--warn)}.bad{background:var(--bad)}
.r-vh{background:var(--r-vh)}.r-h{background:var(--r-h)}.r-m{background:var(--r-m)}
.r-l{background:var(--r-l)}.r-vl{background:var(--r-vl)}.r-na{background:var(--r-na)}
.finding{border:1px solid var(--line);border-radius:11px;padding:14px 16px;margin-bottom:12px}
.finding .hd{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:6px}
.finding .hd h3{font-size:14.5px;margin:0;flex:1 1 60%}
.detail{color:var(--ink);margin:2px 0 8px}
.ev{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:8px 10px;margin:8px 0;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;overflow-x:auto}
.ev div{white-space:pre-wrap;word-break:break-all}.ev .off{color:var(--muted)}
.rem{font-size:13px;color:var(--muted);margin-top:6px}
table{width:100%;border-collapse:collapse;font-size:12.5px;margin-top:6px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}
.ctrls{font-size:12px;margin-top:8px}
.ctrls div{padding:2px 0}.ctrls b{color:var(--teal);display:inline-block;min-width:150px}
.foot{color:var(--muted);font-size:12px;margin-top:18px}
.foot a{color:var(--teal)}
.pill{font-size:11px;color:var(--muted);border:1px solid var(--line);border-radius:999px;padding:1px 8px}
"""


def _ev_block(ev: list[dict]) -> str:
    if not ev:
        return ""
    rows = []
    for e in ev:
        off = f'<span class="off"> @0x{e["offset"]:x}</span>' if e.get("offset", -1) >= 0 else ""
        note = f' <span class="off">[{_esc(e["note"])}]</span>' if e.get("note") else ""
        rows.append(f'<div>{_esc(e.get("excerpt",""))}{off}{note}</div>')
    return '<div class="ev">' + "".join(rows) + "</div>"


def _controls_block(controls: dict, frameworks: dict) -> str:
    if not controls:
        return ""
    out = ['<div class="ctrls">']
    for fw_key, ids in controls.items():
        meta = frameworks.get(fw_key, {})
        name = meta.get("name", fw_key)
        ids_txt = ", ".join(ids) if isinstance(ids, list) else str(ids)
        out.append(f"<div><b>{_esc(name)}</b> {_esc(ids_txt)}</div>")
    out.append("</div>")
    return "".join(out)


def _finding_card(f: dict, frameworks: dict) -> str:
    rc = _RESULT_CLASS.get(f["result"], "warn")
    risk = f.get("risk", "N/A")
    risk_badge = (f'<span class="badge {_RISK_CLASS.get(risk,"r-na")}">Risk: {_esc(risk)}</span>'
                  if f["result"] != "PASS" else "")
    rem = (f'<div class="rem"><b>Remediation:</b> {_esc(f["remediation"])}</div>'
           if f.get("remediation") and f["result"] != "PASS" else "")
    return f"""
    <div class="finding">
      <div class="hd">
        <h3>{_esc(f['title'])}</h3>
        <span class="badge {rc}">{_esc(f['result'])}</span>
        {risk_badge}
        <span class="pill">{_esc(f.get('severity',''))}</span>
      </div>
      <div class="detail">{_esc(f.get('detail',''))}</div>
      {_ev_block(f.get('evidence', []))}
      {_controls_block(f.get('controls', {}), frameworks)}
      {rem}
    </div>"""


def build(result: dict) -> str:
    art = result["artifact"]
    summ = result["summary"]
    frameworks = result.get("frameworks", {})
    findings = result["findings"]

    vclass = {"Reject": "v-bad", "Conditional": "v-warn", "Approve": "v-ok"}.get(
        summ["recommendation_key"], "v-warn")

    stats = "".join(
        f'<div class="stat"><b>{summ["counts"].get(k,0)}</b><span>{lbl}</span></div>'
        for k, lbl in [("FAIL", "Fail"), ("MANUAL", "Manual review"), ("PASS", "Pass")]
    )

    # Attestation reconciliation
    attest_html = ""
    if result.get("attestation"):
        claims = result["attestation"].get("claims", {})
        gaps = [f for f in findings if f["type"] == "attestation-gap" and f["result"] == "FAIL"]
        rows = "".join(
            f"<tr><td><code>{_esc(str(k))}</code></td><td>{_esc(str(v))}</td></tr>"
            for k, v in claims.items()
        )
        gap_rows = "".join(f"<li>{_esc(g['detail'])}</li>" for g in gaps) or "<li>No contradictions found.</li>"
        attest_html = f"""
        <div class="card">
          <h2>Vendor attestation reconciliation <span class="n">— {_esc(result['attestation'].get('vendor',''))}</span></h2>
          <table><tr><th>Claim</th><th>Self-attested</th></tr>{rows}</table>
          <p style="margin:12px 0 4px"><b>Contradictions found ({len(gaps)}):</b></p>
          <ul style="margin-top:4px">{gap_rows}</ul>
        </div>"""

    # Findings (non-pass first, by risk)
    order = {"Very High": 0, "High": 1, "Moderate": 2, "Low": 3, "Very Low": 4, "N/A": 9}
    nonpass = sorted([f for f in findings if f["result"] != "PASS"],
                     key=lambda f: order.get(f.get("risk", "N/A"), 9))
    passed = [f for f in findings if f["result"] == "PASS"]
    findings_html = "".join(_finding_card(f, frameworks) for f in nonpass + passed)

    # SBOM
    comps = art.get("metadata", {}).get("sbom_components", []) or []
    if comps:
        sbom_rows = "".join(
            f"<tr><td>{_esc(c['name'])}</td><td>{_esc(c['version'])}</td>"
            f"<td>{'<span class=\"badge bad\">EOL</span> ' + _esc(c['reason']) if c.get('eol') else 'OK'}</td></tr>"
            for c in comps)
    else:
        sbom_rows = '<tr><td colspan="3">No component versions identified.</td></tr>'

    # Framework coverage matrix
    fw_rows = []
    for fw_key, meta in frameworks.items():
        ids: set[str] = set()
        for f in nonpass:
            v = f.get("controls", {}).get(fw_key)
            if isinstance(v, list):
                ids.update(v)
        fw_rows.append(
            f"<tr><td>{_esc(meta.get('name', fw_key))}</td>"
            f"<td>{_esc(meta.get('version',''))}</td>"
            f"<td>{_esc(meta.get('jurisdiction',''))}</td>"
            f"<td>{_esc(', '.join(sorted(ids)) if ids else '—')}</td></tr>")
    fw_html = "".join(fw_rows)

    src_rows = "".join(
        f'<div><b>{_esc(m.get("name",k))}</b> ({_esc(m.get("version",""))}) — '
        f'<a href="{_esc(m.get("source",""))}">source</a></div>'
        for k, m in frameworks.items())

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VSAS compliance report — {_esc(art.get('name',''))}</title>
<style>{_CSS}</style></head>
<body><div class="wrap">
  <header class="top">
    <h1>Vendor Software Assurance — Compliance Report</h1>
    <div class="sub">Static third-party software assessment · read-only · evidence-based</div>
    <div class="meta">
      <span>Artifact: <code>{_esc(art.get('name',''))}</code></span>
      <span>Format: <code>{_esc(art.get('fmt',''))}</code></span>
      <span>SHA-256: <code>{_esc(art.get('sha256',''))}</code></span>
      <span>Generated: <code>{_esc(result.get('generated',''))}</code></span>
    </div>
    <div class="verdict {vclass}">Recommendation: {_esc(summ['recommendation'])}</div>
  </header>

  <div class="card">
    <h2>Executive summary</h2>
    <div class="grid">{stats}
      <div class="stat"><b>{_esc(summ['max_risk'])}</b><span>Highest open risk</span></div>
    </div>
    <p style="margin:14px 0 0;color:var(--muted)">{_esc(summ['narrative'])}</p>
  </div>

  {attest_html}

  <div class="card">
    <h2>Control-test findings <span class="n">— {len(nonpass)} open, {len(passed)} passed</span></h2>
    {findings_html}
  </div>

  <div class="card">
    <h2>Software Bill of Materials (SBOM)</h2>
    <table><tr><th>Component</th><th>Version</th><th>Status</th></tr>{sbom_rows}</table>
  </div>

  <div class="card">
    <h2>Framework coverage</h2>
    <table><tr><th>Framework</th><th>Version</th><th>Jurisdiction</th><th>Controls exercised</th></tr>{fw_html}</table>
  </div>

  <div class="card foot">
    <p><b>Method:</b> automated static analysis; risk scored with NIST SP 800-30. Results are
    indicators — every FAIL and MANUAL item must be confirmed by a qualified assessor before a
    risk decision. The scanner reads the artifact only; it does not execute or modify it.</p>
    <p><b>Framework sources:</b></p>
    {src_rows}
  </div>
</div></body></html>"""


def write(result: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(build(result))

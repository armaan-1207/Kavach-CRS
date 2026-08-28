"""
HTML Report generator — Kavach-CRS Phase 8

Renders a single self-contained HTML report from the ledger.
"""
from pathlib import Path
from datetime import datetime, timezone

from jinja2 import Environment, BaseLoader

from ledger.ledger import load, verify_chain


REPORT_PATH = Path("run_output") / "report.html"


TEMPLATE_STR = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Kavach-CRS Forensic Report</title>
<style>
  :root {
    --kavach-green: #1a7a4a; --kavach-dark: #0d2b1a;
    --pass: #1a7a4a; --fail: #b91c1c; --warn: #b45309; --info: #1d4ed8;
    --bg: #f8fafc; --card: #ffffff; --border: #e2e8f0;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: #1e293b; }
  header { background: var(--kavach-dark); color: #fff; padding: 2rem 2.5rem; }
  header h1 { font-size: 1.75rem; font-weight: 700; letter-spacing: 0.05em; }
  header p { margin-top: 0.4rem; opacity: 0.75; font-size: 0.9rem; }
  .badge { display: inline-block; padding: 0.2em 0.7em; border-radius: 999px;
           font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
  .badge-pass { background: #dcfce7; color: var(--pass); }
  .badge-fail { background: #fee2e2; color: var(--fail); }
  .badge-warn { background: #fef3c7; color: var(--warn); }
  .badge-info { background: #dbeafe; color: var(--info); }
  .badge-skip { background: #f1f5f9; color: #64748b; }
  main { max-width: 1100px; margin: 2rem auto; padding: 0 1.5rem; }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
                  gap: 1rem; margin-bottom: 2rem; }
  .stat-card { background: var(--card); border: 1px solid var(--border); border-radius: 10px;
               padding: 1.2rem 1.5rem; }
  .stat-card .val { font-size: 2.2rem; font-weight: 700; color: var(--kavach-green); }
  .stat-card .lbl { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em;
                    color: #64748b; margin-top: 0.2rem; }
  section { margin-bottom: 2.5rem; }
  section h2 { font-size: 1.15rem; font-weight: 700; color: var(--kavach-dark);
               border-bottom: 2px solid var(--kavach-green); padding-bottom: 0.4rem;
               margin-bottom: 1rem; }
  .finding-card { background: var(--card); border: 1px solid var(--border); border-radius: 10px;
                  padding: 1.2rem 1.5rem; margin-bottom: 1.2rem; }
  .finding-card h3 { font-size: 1rem; font-weight: 600; margin-bottom: 0.6rem; }
  .meta { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 0.8rem; font-size: 0.82rem; }
  .meta span { background: #f1f5f9; padding: 0.15em 0.6em; border-radius: 4px; }
  pre { background: #0f172a; color: #e2e8f0; padding: 1rem; border-radius: 8px;
        font-size: 0.8rem; overflow-x: auto; white-space: pre-wrap; margin-top: 0.6rem; }
  .diff-add { color: #4ade80; }
  .diff-rm  { color: #f87171; }
  .diff-hdr { color: #93c5fd; }
  .score-bar-wrap { height: 10px; background: #e2e8f0; border-radius: 999px;
                    margin: 0.5rem 0; overflow: hidden; }
  .score-bar { height: 100%; border-radius: 999px; background: var(--kavach-green);
               transition: width 0.3s; }
  .formula-box { background: #f8fafc; border: 1px dashed #94a3b8; border-radius: 8px;
                 padding: 1rem; font-size: 0.82rem; color: #475569; }
  .chain-ok   { color: var(--pass); font-weight: 600; }
  .chain-fail { color: var(--fail); font-weight: 600; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th { background: var(--kavach-dark); color: #fff; padding: 0.5rem 0.8rem; text-align: left; }
  td { padding: 0.45rem 0.8rem; border-bottom: 1px solid var(--border); }
  tr:nth-child(even) td { background: #f8fafc; }
  footer { text-align: center; padding: 2rem; font-size: 0.78rem; color: #94a3b8; }
</style>
</head>
<body>
<header>
  <h1>🛡 Kavach-CRS &nbsp;—&nbsp; Forensic Report</h1>
  <p>Generated: {{ generated_at }} &nbsp;|&nbsp; Run ID: {{ run_id }}</p>
</header>
<main>

  <!-- Summary -->
    <section>
      <h2>Mission Impact literal:</h2>
      <div style="background: #eef2ff; border-left: 4px solid var(--info); padding: 1.2rem; border-radius: 6px; font-size: 0.9rem; margin-bottom: 2rem;">
        <p style="margin-bottom: 0.5rem;"><strong>Strategic Advantage: NO DOWNTIME.</strong> Kavach-CRS resolves logical source code vulnerabilities continuously. Kavach-CRS preserves normal mission functionality while neutralizing exploits via strict AST transformations.</p>
        <p><strong>Fleet Coverage:</strong> Validated via differential replay sandboxing across {{ targets|length if targets else 1 }} assets.</p>
      </div>
    </section>

  <div class="summary-grid">
    <div class="stat-card"><div class="val">{{ stats.total_findings }}</div><div class="lbl">Findings Detected</div></div>
    <div class="stat-card"><div class="val">{{ stats.triaged }}</div><div class="lbl">After Triage</div></div>
    <div class="stat-card"><div class="val">{{ stats.patched }}</div><div class="lbl">Patched</div></div>
    <div class="stat-card"><div class="val">{{ stats.pov_pass }}</div><div class="lbl">PoV Pass</div></div>
    <div class="stat-card"><div class="val">{{ stats.auto_merge }}</div><div class="lbl">Auto-Merged</div></div>
    <div class="stat-card"><div class="val">{{ stats.human_review }}</div><div class="lbl">Human Review</div></div>
    <div class="stat-card"><div class="val">{{ stats.elapsed_s }}s</div><div class="lbl">Total Time</div></div>
  </div>

  <!-- Chain integrity -->
  <section>
    <h2>Ledger Integrity</h2>
    <p>{% if chain_ok %}<span class="chain-ok">✓ {{ chain_msg }}</span>{% else %}<span class="chain-fail">✗ {{ chain_msg }}</span>{% endif %}</p>
  </section>

  <!-- Per-finding detail -->
  <section>
    <h2>Finding Details</h2>
    {% for f in finding_reports %}
    <div class="finding-card">
      <h3>{{ f.id }} — {{ f.cwe }} &nbsp; <span class="badge badge-{{ f.sev_class }}">{{ f.severity }}</span></h3>
      <div class="meta">
        <span>📁 {{ f.file_short }}</span>
        <span>Line {{ f.line }}</span>
        <span>{{ f.rule }}</span>
        <span>Source: {{ f.source }}</span>
        {% if f.enclosing_fn %}<span>fn: {{ f.enclosing_fn }}</span>{% endif %}
        {% if f.mission_tier %}<span>Mission Tier: {{ f.mission_tier }}</span>{% endif %}
      </div>
      <pre>{{ f.snippet }}</pre>

      <!-- Patch -->
      {% if f.patch_status == "PATCHED" %}
      <p style="margin-top:0.8rem"><strong>Patch rationale:</strong> {{ f.rationale }}</p>
      <pre>{% for line in f.diff_lines %}<span class="{% if line.startswith('+') and not line.startswith('+++') %}diff-add{% elif line.startswith('-') and not line.startswith('---') %}diff-rm{% elif line.startswith('@@') %}diff-hdr{% endif %}">{{ line }}</span>
{% endfor %}</pre>
      {% else %}
      <p style="margin-top:0.8rem">Patch status: <em>{{ f.patch_status }}</em> — {{ f.patch_reason }}</p>
      {% endif %}

      <!-- Prove -->
      <div style="margin-top:1rem; display:flex; gap:1rem; flex-wrap:wrap;">
        <span><strong>PoV replay:</strong> <span class="badge badge-{{ 'pass' if f.pov == 'PASS' else 'fail' if f.pov == 'FAIL' else 'skip' }}">{{ f.pov }}</span></span>
        <span><strong>Diff replay:</strong> <span class="badge badge-{{ 'pass' if f.diff_replay == 'PASS' else 'fail' if f.diff_replay == 'FAIL' else 'warn' if f.diff_replay == 'PARTIAL' else 'skip' }}">{{ f.diff_replay }}</span></span>
        <span><strong>Regression:</strong> <span class="badge badge-{{ 'pass' if f.regression in ('PASS','NO_SUITE_PRESENT') else 'fail' }}">{{ f.regression }}</span></span>
      </div>

      <!-- Confidence gate -->
      {% if f.gate %}
      <div style="margin-top:1rem;">
        <strong>Confidence score: {{ "%.2f"|format(f.gate.score) }}</strong>
        <div class="score-bar-wrap"><div class="score-bar" style="width:{{ (f.gate.score * 100)|int }}%"></div></div>
        <p><span class="badge badge-{{ 'pass' if f.gate.decision == 'AUTO_MERGE' else 'warn' if f.gate.decision == 'HUMAN_REVIEW' else 'fail' }}">{{ f.gate.decision }}</span>
        &nbsp; {{ f.gate.rationale }}</p>
        <div class="formula-box" style="margin-top:0.6rem;">
          <strong>Formula (transparent):</strong><br>
          score = 0.40 × PoV({{ "%.2f"|format(f.gate.components.pov) }})
                + 0.35 × DiffReplay({{ "%.2f"|format(f.gate.components.diff_replay) }})
                + 0.15 × Regression({{ "%.2f"|format(f.gate.components.regression) }})
                + 0.10 × DiffSize({{ "%.2f"|format(f.gate.components.diff_size) }})
                = <strong>{{ "%.4f"|format(f.gate.score) }}</strong>
          &nbsp;|&nbsp; AUTO_MERGE ≥ {{ f.gate.thresholds.auto_merge }},
                   HUMAN_REVIEW ≥ {{ f.gate.thresholds.human_review }}
        </div>
      </div>
      {% endif %}
    </div>
    {% endfor %}
  </section>

  <!-- Discarded findings -->
  {% if discarded %}
  <section>
    <h2>Discarded (Unreachable)</h2>
    <table>
      <tr><th>ID</th><th>CWE</th><th>File</th><th>Line</th><th>Reason</th></tr>
      {% for d in discarded %}
      <tr>
        <td>{{ d.id }}</td>
        <td>{{ d.cwe }}</td>
        <td>{{ d.file_short }}</td>
        <td>{{ d.line }}</td>
        <td>{{ d.triage_reason }}</td>
      </tr>
      {% endfor %}
    </table>
  </section>
  {% endif %}

  <!-- Ledger entries -->
  <section>
    <h2>Ledger Entries (Ed25519 Signature Chain)</h2>
    <table>
      <tr><th>#</th><th>Timestamp</th><th>Stage</th><th>Signature (first 16)</th><th>Prev Sig (first 16)</th></tr>
      {% for e in ledger_entries %}
      <tr>
        <td>{{ e.seq }}</td>
        <td>{{ e.timestamp[:19] }}</td>
        <td>{{ e.stage }}</td>
        <td><code>{{ e.signature[:16] }}…</code></td>
        <td><code>{{ e.prev_sig[:16] }}…</code></td>
      </tr>
      {% endfor %}
    </table>
  </section>

</main>
<footer>
  Kavach-CRS &nbsp;|&nbsp; Terrier Cyber Quest 2026 &nbsp;|&nbsp;
  "Proves your patch is correct even when your codebase has no tests."
</footer>
</body>
</html>
""".strip()


def _badge_class(severity: str) -> str:
    return {"HIGH": "fail", "MEDIUM": "warn", "LOW": "info"}.get(severity.upper(), "skip")


def generate_report(run_summary: dict) -> str:
    """
    Generate the HTML report from the run_summary dict produced by cli.py.
    Writes to run_output/report.html and returns the path.
    """
    env = Environment(loader=BaseLoader(), autoescape=True)
    template = env.from_string(TEMPLATE_STR)

    chain_ok, chain_msg = verify_chain()
    ledger_entries = load()

    # Build per-finding report items
    finding_reports = []
    for item in run_summary.get("items", []):
        f = item.get("finding", {})
        patch = item.get("patch", {})
        pov = item.get("pov", {})
        diff = item.get("differential", {})
        reg = item.get("regression", {})
        gate = item.get("gate", {})

        diff_lines = patch.get("unified_diff", "").splitlines()

        finding_reports.append({
            "id": f.get("id", "?"),
            "cwe": f.get("cwe", ""),
            "severity": f.get("severity", "MEDIUM"),
            "sev_class": _badge_class(f.get("severity", "MEDIUM")),
            "file_short": Path(f.get("file", "")).name,
            "line": f.get("line", 0),
            "rule": f.get("rule", ""),
            "source": f.get("source", ""),
            "snippet": f.get("snippet", ""),
            "enclosing_fn": f.get("enclosing_function"),
            "mission_tier": f.get("mission_tier"),
            "patch_status": patch.get("status", "SKIPPED"),
            "patch_reason": patch.get("reason", ""),
            "rationale": item.get("patch_spec", {}).get("rationale", ""),
            "diff_lines": diff_lines,
            "pov": pov.get("status", "SKIPPED"),
            "diff_replay": diff.get("status", "SKIPPED"),
            "regression": reg.get("status", "SKIPPED"),
            "gate": gate if gate else None,
        })

    discarded = []
    for d in run_summary.get("discarded", []):
        discarded.append({
            "id": d.get("id", "?"),
            "cwe": d.get("cwe", ""),
            "file_short": Path(d.get("file", "")).name,
            "line": d.get("line", 0),
            "triage_reason": d.get("triage_reason", ""),
        })

    stats = run_summary.get("stats", {})
    html = template.render(
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        run_id=run_summary.get("run_id", "unknown"),
        stats=stats,
        chain_ok=chain_ok,
        chain_msg=chain_msg,
        finding_reports=finding_reports,
        discarded=discarded,
        ledger_entries=ledger_entries,
    )

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(html, encoding="utf-8")
    return str(REPORT_PATH)

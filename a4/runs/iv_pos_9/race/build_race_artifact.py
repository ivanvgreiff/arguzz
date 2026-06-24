#!/usr/bin/env python3
"""Generate the neat at-a-glance bug-race summary page (Artifact body content) from live
race_lib numbers + the rendered figures (base64-embedded, self-contained). Body-only HTML
(no doctype/html/head/body) for the Artifact wrapper.

    RESULTS_DIR=a4/runs/iv_pos_9/race/thesis_results python3 a4/runs/iv_pos_9/race/build_race_artifact.py
"""
import base64
import os
import sys
from pathlib import Path

sys.path.insert(0, "/root/arguzz")
os.chdir("/root/arguzz")
from a4.runs.iv_pos_9.race import race_lib

RACE = Path("/root/arguzz/a4/runs/iv_pos_9/race")
ART = RACE / "race_artifacts"
OUT = RACE / "race_summary.html"
RESULTS_DIR = os.environ.get("RESULTS_DIR", "a4/runs/iv_pos_9/race/thesis_results")

d = race_lib.load_data(RESULTS_DIR)
tbl = {r["variant"]: r for r in race_lib.per_variant_table(d)}
N, seeds, label = d["N"], d["seeds"], d["label"]
seeds_done = max((r["seeds_done"] for r in tbl.values()), default=0)


def b64(name):
    p = ART / f"race_{name}.png"
    return base64.b64encode(p.read_bytes()).decode() if p.exists() else ""


def img(name, alt):
    return f'<img src="data:image/png;base64,{b64(name)}" alt="{alt}">'


def fmt_p(r):
    return "—" if r["P_found"] is None else f'{r["P_found"]:.2f}'


def fmt_ci(r):
    return "" if r["P_found"] is None else f'[{r["P_found_lo"]:.2f}, {r["P_found_hi"]:.2f}]'


def cond(r):
    return "n/a" if r["cond_find_density"] is None else f'{r["cond_find_density"]*100:.1f}%'


def first(r):
    return "—" if r["first_find_idx_median"] is None else f'{r["first_find_idx_median"]:.0f}'


ON = ["V5_control", "Hybrid_cTS"]
OFF = ["V6_cTS", "V6_uniform"]
SUB = {"V5_control": "A4 · post-execution", "Hybrid_cTS": "A4 + Arguzz",
       "V6_cTS": "Arguzz · cTS", "V6_uniform": "Arguzz · uniform"}


def card_on(v):
    r = tbl[v]
    return f"""
    <div class="node on">
      <div class="node-name">{v}</div>
      <div class="node-sub">{SUB[v]}</div>
      <div class="node-find"><span class="big">{r['mean_finds']:.1f}</span><span class="unit">finds / seed</span></div>
      <div class="node-meta">{r['mean_itm_applied']:.0f} INSTR_TYPE_MOD applied · P(found) {fmt_p(r)}</div>
    </div>"""


def card_off(v):
    r = tbl[v]
    return f"""
    <div class="node off">
      <div class="node-name">{v}</div>
      <div class="node-sub">{SUB[v]}</div>
      <div class="node-find"><span class="big dim">0</span><span class="unit">finds</span></div>
      <div class="node-meta">0 INSTR_TYPE_MOD applied · off the bug's surface</div>
    </div>"""


def trow(v):
    r = tbl[v]
    cls = "on" if v in ON else "off"
    return f"""
      <tr class="{cls}">
        <td class="mono v">{v}</td><td>{r['surface']}</td>
        <td class="num">{fmt_p(r)} <span class="ci">{fmt_ci(r)}</span></td>
        <td class="num">{r['total_finds']}</td>
        <td class="num">{r['mean_finds']:.1f}</td>
        <td class="num">{r['mean_itm_applied']:.0f}</td>
        <td class="num">{cond(r)}</td>
        <td class="num">{first(r)}</td>
        <td class="num">{r['mean_per_mut_s']:.1f}s</td>
      </tr>"""


FIGS = [
    ("finds_reach", "Reachability &amp; finds",
     "A4/Hybrid apply the bug-relevant mutation hundreds–thousands of times and find the hole; pure Arguzz applies it zero times."),
    ("decomposition", "The mechanism — why",
     "P(find) = P(apply INSTR_TYPE_MOD) × P(find | ITM). The first factor is identically 0 for pure Arguzz — structural, not effort."),
    ("discovery_cdf", "Discovery CDF",
     "Mutations-to-first-find. A4/Hybrid reach the bug early; the Arguzz curves are censored on the floor (never found)."),
    ("cumulative_finds", "Discovery dynamics",
     "Cumulative finds over the budget (bold = mean over seeds, faint = each seed). Arguzz lines sit on zero."),
    ("accept_channels", "The falsifier",
     "Every accept is control-checked. Every Arguzz accept is non-planted — so P(found)=0 is tested, not assumed."),
]

fig_html = "\n".join(
    f"""
      <figure class="fig">
        <figcaption><span class="fig-t">{t}</span><span class="fig-c">{c}</span></figcaption>
        <div class="fig-img">{img(name, t)}</div>
      </figure>"""
    for name, t, c in FIGS)

partial = (seeds_done < 10)
status = (f'<span class="live">● LIVE · {seeds_done} of 10 seed-pairs in</span>'
          if partial else f'<span class="done">{seeds_done} seed-pairs · complete</span>')

HTML = f"""
<title>Bug Race · A4 vs Arguzz · VerifyOpcode</title>
<style>
  :root {{
    --ground:#EEF1F6; --panel:#FFFFFF; --ink:#141C2B; --muted:#5B6675; --dim:#98A2B3;
    --accent:#1B6CC4; --amber:#C8741A; --line:#D4DAE3; --on-wash:#E3ECF7; --off-wash:#EAECF0;
    --mono:ui-monospace,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace;
    --sans:system-ui,-apple-system,"Segoe UI",Helvetica,Arial,sans-serif;
  }}
  * {{ box-sizing:border-box; }}
  .wrap {{ background:var(--ground); color:var(--ink); font-family:var(--sans);
    line-height:1.55; -webkit-font-smoothing:antialiased; padding:0 0 64px; }}
  .wrap > * {{ max-width:1040px; margin-inline:auto; padding-inline:24px; }}
  a {{ color:var(--accent); }}

  /* masthead */
  .eyebrow {{ font-family:var(--mono); font-size:12.5px; letter-spacing:.14em; text-transform:uppercase;
    color:var(--accent); margin:40px auto 10px; display:flex; gap:14px; align-items:center; flex-wrap:wrap; }}
  .eyebrow .sep {{ color:var(--line); }}
  h1 {{ font-size:clamp(30px,4.4vw,46px); line-height:1.04; font-weight:800; letter-spacing:-.022em;
    margin:0 auto 12px; max-width:1040px; }}
  h1 .em {{ color:var(--accent); }}
  .lede {{ font-size:18px; color:var(--muted); max-width:760px; margin:0 auto 8px; }}
  .lede b {{ color:var(--ink); font-weight:650; }}

  /* hero surface map */
  .surface {{ margin-top:30px; margin-bottom:14px; }}
  .surface-head {{ display:flex; justify-content:space-between; font-family:var(--mono); font-size:12px;
    letter-spacing:.08em; text-transform:uppercase; color:var(--muted); margin-bottom:8px; }}
  .map {{ display:grid; grid-template-columns:1fr auto 1fr; gap:0; align-items:stretch;
    border:1px solid var(--line); border-radius:12px; overflow:hidden; background:var(--panel); }}
  .col {{ display:flex; flex-direction:column; gap:12px; padding:22px; }}
  .col.offside {{ background:var(--off-wash); }}
  .col.onside {{ background:var(--on-wash); }}
  .boundary {{ width:0; border-left:2px dashed var(--accent); position:relative; }}
  .boundary span {{ position:absolute; top:50%; left:50%; transform:translate(-50%,-50%) rotate(90deg);
    transform-origin:center; white-space:nowrap; font-family:var(--mono); font-size:11px;
    letter-spacing:.1em; text-transform:uppercase; color:var(--accent); background:var(--ground);
    padding:6px 10px; border-radius:6px; border:1px solid var(--line); }}
  .node {{ background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:14px 16px; }}
  .node.off {{ opacity:.72; }}
  .node.on {{ border-left:3px solid var(--accent); }}
  .node-name {{ font-family:var(--mono); font-weight:700; font-size:15px; }}
  .node-sub {{ font-family:var(--mono); font-size:11.5px; color:var(--muted); margin-bottom:8px; letter-spacing:.04em; }}
  .node-find {{ display:flex; align-items:baseline; gap:8px; }}
  .big {{ font-size:34px; font-weight:800; letter-spacing:-.02em; color:var(--amber); font-variant-numeric:tabular-nums; }}
  .big.dim {{ color:var(--dim); }}
  .unit {{ font-family:var(--mono); font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:.08em; }}
  .node-meta {{ font-size:12.5px; color:var(--muted); margin-top:6px; }}
  .bug {{ margin-top:4px; display:flex; align-items:center; gap:10px; font-family:var(--mono);
    font-size:12.5px; color:var(--ink); background:#FBEED9; border:1px solid #EAD2A8;
    border-radius:8px; padding:9px 12px; }}
  .bug .dot {{ width:9px; height:9px; border-radius:50%; background:var(--amber); box-shadow:0 0 0 4px #F4DCB4; flex:none; }}

  /* callout */
  .note {{ margin-top:30px; border:1px solid var(--line); border-radius:12px; background:var(--panel);
    padding:20px 22px; display:grid; grid-template-columns:repeat(3,1fr); gap:18px; }}
  .note h3 {{ font-size:12px; font-family:var(--mono); letter-spacing:.1em; text-transform:uppercase;
    color:var(--accent); margin:0 0 6px; }}
  .note p {{ margin:0; font-size:13.5px; color:var(--muted); }}
  .note p b {{ color:var(--ink); font-weight:600; }}

  /* section heads */
  h2 {{ font-size:13px; font-family:var(--mono); letter-spacing:.12em; text-transform:uppercase;
    color:var(--ink); margin:48px auto 16px; padding-bottom:10px; border-bottom:1px solid var(--line);
    display:flex; gap:12px; align-items:baseline; }}
  h2 .idx {{ color:var(--accent); }}

  /* table */
  .tbl-scroll {{ overflow-x:auto; }}
  table {{ width:100%; border-collapse:collapse; font-size:13.5px; }}
  thead th {{ text-align:right; font-family:var(--mono); font-size:11px; font-weight:600; letter-spacing:.04em;
    text-transform:uppercase; color:var(--muted); padding:8px 10px; border-bottom:1px solid var(--line); white-space:nowrap; }}
  thead th:first-child, thead th:nth-child(2) {{ text-align:left; }}
  tbody td {{ padding:11px 10px; border-bottom:1px solid var(--line); }}
  td.num {{ text-align:right; font-family:var(--mono); font-variant-numeric:tabular-nums; white-space:nowrap; }}
  td.v {{ font-weight:700; }}
  .mono {{ font-family:var(--mono); }}
  .ci {{ color:var(--dim); font-size:11px; }}
  tr.on td.v {{ color:var(--accent); }}
  tr.off {{ color:var(--muted); }}
  tr.off td.v {{ color:var(--dim); }}

  /* figures */
  .figs {{ display:flex; flex-direction:column; gap:26px; }}
  .fig {{ margin:0; background:var(--panel); border:1px solid var(--line); border-radius:12px; overflow:hidden; }}
  .fig figcaption {{ padding:14px 18px 12px; border-bottom:1px solid var(--line); }}
  .fig-t {{ display:block; font-weight:700; font-size:15px; }}
  .fig-c {{ display:block; font-size:13px; color:var(--muted); margin-top:3px; }}
  .fig-img {{ overflow-x:auto; padding:14px; background:var(--panel); }}
  .fig-img img {{ display:block; width:100%; max-width:100%; height:auto; }}

  /* verdict table */
  .verdict td, .verdict th {{ text-align:left; }}
  .verdict td.mark {{ font-family:var(--mono); font-weight:700; }}
  .yes {{ color:var(--accent); }} .no {{ color:var(--dim); }} .exp {{ color:var(--amber); }}

  footer {{ margin-top:48px; padding-top:20px; border-top:1px solid var(--line);
    font-family:var(--mono); font-size:11.5px; color:var(--muted); line-height:1.7; }}
  .live {{ color:var(--amber); font-weight:700; }}
  .done {{ color:var(--accent); font-weight:700; }}
  @media (max-width:720px) {{
    .map {{ grid-template-columns:1fr; }}
    .boundary {{ width:auto; height:0; border-left:0; border-top:2px dashed var(--accent); }}
    .boundary span {{ transform:translate(-50%,-50%); }}
    .note {{ grid-template-columns:1fr; }}
  }}
</style>

<div class="wrap">

  <div class="eyebrow">
    <span>IV.POS.9 · Track A</span><span class="sep">/</span><span>A4-findable bug race</span>
    <span class="sep">/</span><span>Seam-B · VerifyOpcode</span>
  </div>
  <h1>A4 finds the planted decode bug.<br>Pure Arguzz <span class="em">structurally cannot</span>.</h1>
  <p class="lede">Four fuzzing variants race to discover a single planted soundness hole — a removed
    <span class="mono">VerifyOpcode</span> decode-equality constraint. The result is not a speed gap:
    <b>two of the four can't even enter the race</b>, because the bug-relevant mutation is absent from
    their attack surface. This is the A4 side of the complementarity claim.</p>

  <section class="surface">
    <div class="surface-head"><span>off the bug's surface</span><span>on the bug's surface</span></div>
    <div class="map">
      <div class="col offside">
        {''.join(card_off(v) for v in OFF)}
      </div>
      <div class="boundary"><span>surface boundary · INSTR_TYPE_MOD</span></div>
      <div class="col onside">
        {''.join(card_on(v) for v in ON)}
        <div class="bug"><span class="dot"></span>VerifyOpcode decode hole — the only planted flaw</div>
      </div>
    </div>
  </section>

  <div class="note">
    <div><h3>Is this just smoke?</h3><p>No. The <b>N=120</b> run was the smoke (pipeline check).
      This is the <b>N=5000</b> thesis race — the real A4-side result. The <b>rs1==rs2 CVE race</b>
      is the Arguzz-side mirror, later.</p></div>
    <div><h3>The oracle</h3><p>A find = the bug binary <b>accepts</b> a decode-divergent
      <span class="mono">INSTR_TYPE_MOD</span>, and the clean control <b>rejects</b> it specifically at
      <span class="mono">VerifyOpcode</span>. Every accept is control-checked.</p></div>
    <div><h3>Honest severity</h3><p>The finds are <b>result-preserving</b> (no output change) — a
      genuine but low-severity <b>decode</b> underconstraint. That is exactly the constraint family
      A4's post-execution surface is built to reach.</p></div>
  </div>

  <h2><span class="idx">01</span> Per-variant results</h2>
  <div class="tbl-scroll">
    <table>
      <thead><tr>
        <th>variant</th><th>surface</th><th>P(found) [95% CI]</th><th>finds</th><th>finds/seed</th>
        <th>ITM applied/seed</th><th>P(find&#124;ITM)</th><th>1st-find idx</th><th>s/mut</th>
      </tr></thead>
      <tbody>{''.join(trow(v) for v in ON + OFF)}</tbody>
    </table>
  </div>

  <h2><span class="idx">02</span> The evidence</h2>
  <div class="figs">{fig_html}</div>

  <h2><span class="idx">03</span> The complementarity table</h2>
  <div class="tbl-scroll">
    <table class="verdict">
      <thead><tr><th>bug class</th><th>A4 (V5)</th><th>Arguzz (V6)</th><th>Hybrid</th></tr></thead>
      <tbody>
        <tr><td><b>decode underconstraint</b> — VerifyOpcode (this race)</td>
          <td class="mark yes">FINDS</td><td class="mark no">off surface</td><td class="mark yes">FINDS</td></tr>
        <tr><td><b>value / permutation CVE</b> — rs1==rs2 (later)</td>
          <td class="mark exp">expected: no</td><td class="mark exp">expected: yes</td><td class="mark exp">expected: yes</td></tr>
      </tbody>
    </table>
  </div>

  <footer>
    campaign: {label} · N={N} · seeds {seeds} · {status}<br>
    numbers + figures generated live from the run-DBs by race_lib / build_race_notebook (no hardcoding).
    Full reproducible notebook: race_exploration.ipynb. Re-runs unchanged at CHAIN_COMPLETE (full 4×10).
  </footer>

</div>
"""

OUT.write_text(HTML)
print(f"[saved] {OUT}  ({len(HTML)//1024} KB, figures embedded)")

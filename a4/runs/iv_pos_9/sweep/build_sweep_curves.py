#!/usr/bin/env python3
"""IV.POS.9 Track-B — per-guest coverage curves vs the sha2 baseline (g0).

Reuses the D2.H curve concept (cumulative distinct coverage vs mutation index) but is
self-contained (no edits to the shared a4/runs/iv_pos_8/d2g module — §1.4 isolation).
Compares, WITHIN each variant, the new guest's curve against the reused g0 baseline
(D2.F N=10000 truncated to the first 5000 mutations). Emits a self-contained HTML.

Usage: python3 build_sweep_curves.py <guest_slug> <out.html>
   e.g. python3 build_sweep_curves.py g1_ecall_control /tmp/.../g1_curves.html
"""
import sqlite3, sys, io, base64, os
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

N = 5000
VARIANTS = ["V5_control", "V6_uniform", "V6_cTS", "Hybrid_cTS"]
COLORS = {"V5_control": "#1f77b4", "V6_uniform": "#2ca02c", "V6_cTS": "#ff7f0e", "Hybrid_cTS": "#d62728"}
AN = os.environ.get("AN", "/tmp/claude-0/-root-arguzz/5dab1f71-93ac-4daf-b85a-f22d0f93c4ba/scratchpad/analysis")

def g0_db(v): return f"a4/runs/iv_pos_8/d2f/prod/d2f_prod_b1/pos_iv_pos_8_d2f_{v}_seed1234_n10000/run.db"
def sweep_db(guest, v): return f"{AN}/sweep_b1/{guest}_{v}.db"

def cum(db, table, col):
    """cumulative count of distinct items by first_hit_mutation_id, over 0..N."""
    if not os.path.exists(db): return None
    c = sqlite3.connect(db)
    ids = [int(m) for (m,) in c.execute(f"SELECT first_hit_mutation_id FROM {table}") if m is not None]
    c.close()
    a = np.zeros(N + 1)
    for m in ids:
        if 1 <= m <= N: a[m] += 1
    return np.cumsum(a)

def b64fig(fig):
    buf = io.BytesIO(); fig.savefig(buf, format="png", dpi=110, bbox_inches="tight"); plt.close(fig)
    return base64.b64encode(buf.getvalue()).decode()

def build(guest):
    x = np.arange(N + 1)
    fig, axes = plt.subplots(len(VARIANTS), 2, figsize=(13, 4.2 * len(VARIANTS)))
    rows = []
    for i, v in enumerate(VARIANTS):
        for j, (table, lbl) in enumerate([("coverage", "local constraint-locs"),
                                          ("compressed_global_coverage", "CGC contexts")]):
            ax = axes[i][j]
            g0 = cum(g0_db(v), table, None); g1 = cum(sweep_db(guest, v), table, None)
            if g0 is not None: ax.plot(x, g0, color=COLORS[v], lw=1.6, ls="--", alpha=0.6,
                                       label=f"g0 baseline (final {int(g0[-1])})")
            if g1 is not None: ax.plot(x, g1, color=COLORS[v], lw=2.4,
                                       label=f"{guest} (final {int(g1[-1])})")
            ax.set_title(f"{v} — {lbl}", fontsize=11)
            ax.set_xlabel("mutation index"); ax.set_ylabel(f"distinct {lbl}")
            ax.legend(fontsize=8, loc="lower right"); ax.grid(alpha=0.3); ax.margins(x=0)
            if g0 is not None and g1 is not None:
                rows.append((v, lbl, int(g0[-1]), int(g1[-1])))
    fig.suptitle(f"{guest} vs g0 sha2 baseline — coverage trajectories (N=5000, seed 1234; dashed=g0, solid={guest})",
                 fontsize=13)
    fig.tight_layout(rect=[0, 0, 1, 0.99])
    return b64fig(fig), rows

if __name__ == "__main__":
    guest = sys.argv[1] if len(sys.argv) > 1 else "g1_ecall_control"
    out = sys.argv[2] if len(sys.argv) > 2 else f"/tmp/{guest}_curves.html"
    img, rows = build(guest)
    trows = "\n".join(f"<tr><td>{v}</td><td>{lbl}</td><td>{a}</td><td>{b}</td>"
                      f"<td style='color:{'#c0392b' if b<a else '#27ae60' if b>a else '#555'}'>{b-a:+d}</td></tr>"
                      for v, lbl, a, b in rows)
    html = f"""<title>{guest} coverage vs sha2 baseline</title>
<h1>{guest} — coverage vs g0 (sha2) baseline · N=5000 · seed 1234</h1>
<p>Within-variant comparison (the valid generalization read): each panel overlays the reused g0 baseline
(dashed, D2.F N=10000 truncated to 5000) against {guest} (solid). Cross-variant comparison is confounded
by different selectors/extractors, so read down a single variant.</p>
<img src="data:image/png;base64,{img}" style="max-width:100%"/>
<h2>Final coverage (within-variant)</h2>
<table border=1 cellpadding=6 style="border-collapse:collapse">
<tr><th>variant</th><th>metric</th><th>g0</th><th>{guest}</th><th>Δ</th></tr>
{trows}
</table>"""
    open(out, "w").write(html)
    print(f"wrote {out} ({len(rows)} panels)")

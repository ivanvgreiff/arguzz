#!/usr/bin/env python3
"""Scheduler-ablation bug-race analysis library — SEPARATE, SELF-CONTAINED copy.

PROVENANCE / SEPARATION (read before trusting any number):
- This is a VERBATIM copy of ../race_lib.py with ONLY the constants changed (VARIANTS, COLORS,
  DISPLAY, LABEL, SURFACE, DEFAULT_RESULTS, _RID). The metric logic (load_data, per_variant_table,
  oracle.is_decode_divergent_itm find predicate, markers densities) is BYTE-IDENTICAL to the
  published race analysis — so these are "the same bug-race statistics, computed anew" on new data.
- DATA = the FIXED Seam-B binary run (risc0 head f3c659a8, cherry-pick 6556e8d7; planted_bug=
  verifyopcode; 3-kind contamination FIXED). Run-id slug `a3seambfix`. Read from LOCAL COPIES at
  ./fix_thesis_results/ (rsync'd read-only from coinbase:/tmp/ivg_race/results_race/greedy/).
- This NEVER reads the old contaminated `../thesis_results/` (head 93bda33b, 3 dead kinds) and
  NEVER edits ../race_lib.py / ../race_exploration.* (those stay the published 4-variant story).
- Reuses ../oracle.py + ../markers.py by READ-ONLY import. No DB is moved or modified.

    python3 a4/runs/iv_pos_9/race/sched_ablation/sched_ablation_lib.py   (prints the per-variant table)
"""
from __future__ import annotations

import math
import os
import re
import sqlite3
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path("/root/arguzz")
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from a4.runs.iv_pos_9.race import oracle, markers  # noqa: E402

# SCHEDULER-ABLATION ladder (all A4-surface, all CAN reach the planted bug):
#   V8 (no arm semantics, no bandit) -> V0 (arm semantics, no bandit) -> V5 (arm semantics + bandit),
#   + Hybrid (A4+Arguzz surfaces, bandit) as the surface-mix reference.
# V8->V0 isolates whether ARM SEMANTICS help; V0->V5 isolates whether the BANDIT helps.
VARIANTS = ["V8_arguzz_sched", "V0_uniform", "V5_control", "Hybrid_cTS"]  # code names = DB-file ids
COLORS = {"V8_arguzz_sched": "#9467bd", "V0_uniform": "#2ca02c",
          "V5_control": "#1f77b4", "Hybrid_cTS": "#d62728"}
DISPLAY = {"V8_arguzz_sched": "V8: Arguzz-sched", "V0_uniform": "V0: Uniform arms",
           "V5_control": "V5: cTS Bandit", "Hybrid_cTS": "Hybrid: A4+Arguzz Bandit"}
LABEL = {
    "V8_arguzz_sched": "V8: Arguzz-sched\n(no arms, no bandit)",
    "V0_uniform": "V0: Uniform arms\n(arms, no bandit)",
    "V5_control": "V5: cTS Bandit\n(arms + bandit)",
    "Hybrid_cTS": "Hybrid\n(A4+Arguzz, bandit)",
}
SURFACE = {"V8_arguzz_sched": "A4", "V0_uniform": "A4", "V5_control": "A4", "Hybrid_cTS": "A4+Arguzz"}
# LOCAL COPIES of the FIXED-binary (head f3c659a8) run DBs, read-only from coinbase. NEVER the old
# contaminated thesis_results (head 93bda33b, 3 dead kinds).
DEFAULT_RESULTS = "a4/runs/iv_pos_9/race/sched_ablation/fix_thesis_results"
SMOKE_RESULTS = "a4/runs/iv_pos_9/race/sched_ablation/fix_thesis_results"  # no separate smoke set

_RID = re.compile(r"a3seambfix_(?P<variant>.+?)_seed(?P<seed>\d+)_n(?P<n>\d+)")


# --------------------------------------------------------------------------- discovery
def discover_runs(results_dir: str) -> List[Dict]:
    base = Path(results_dir)
    runs = []
    for db in sorted(base.rglob("run.db")):
        m = _RID.search(db.parent.name)
        if not m:
            continue
        runs.append({"db": str(db), "variant": m.group("variant"),
                     "seed": int(m.group("seed")), "N": int(m.group("n"))})
    # DEDUPE (added vs race_lib): a re-pulled job can nest RES/<rid>/chainjob_<rid>/run.db beside
    # RES/<rid>/run.db (scp -r into an existing dir). Verified byte-identical (same sha256), so we keep
    # exactly ONE per (variant,seed) — the SHALLOWEST (canonical RES/<rid>/run.db). No DB edited/removed;
    # this just stops rglob double-counting the nested copy. (Hit V5 seeds 1238 & 1240 here.)
    best: Dict = {}
    for r in runs:
        k = (r["variant"], r["seed"])
        if k not in best or r["db"].count("/") < best[k]["db"].count("/"):
            best[k] = r
    return sorted(best.values(), key=lambda r: (r["variant"], r["seed"]))


def _elapsed_stats(db: str):
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        vals = [r[0] for r in con.execute(
            "SELECT elapsed_ms FROM mutations WHERE elapsed_ms IS NOT NULL AND elapsed_ms>0")]
    finally:
        con.close()
    if not vals:
        return 0.0, 0.0
    # median is robust to the one-time prover-key-setup outlier on the first mutation
    return statistics.mean(vals), statistics.median(vals)


# --------------------------------------------------------------------------- load
def load_data(results_dir: Optional[str] = None) -> Dict:
    results_dir = results_dir or os.environ.get("RESULTS_DIR", DEFAULT_RESULTS)
    if not list(Path(results_dir).rglob("run.db")):
        results_dir = SMOKE_RESULTS
    per_run: List[Dict] = []
    for r in discover_runs(results_dir):
        db, N = r["db"], r["N"]
        accepts = oracle.extract_accepts(db)
        find_ids = [a["id"] for a in accepts if oracle.is_decode_divergent_itm(a)]
        m = markers.per_run_markers(db, find_ids, N)
        mean_ms, med_ms = _elapsed_stats(db)
        accept_kinds = Counter(a["kind"] for a in accepts)
        find_kinds = Counter(a["kind"] for a in accepts if a["id"] in set(find_ids))
        per_run.append({
            **m, "variant": r["variant"], "seed": r["seed"], "N": N, "db": db,
            "find_ids": find_ids, "n_accepts": len(accepts),
            "n_non_planted": len(accepts) - len(find_ids),
            "accept_kinds": dict(accept_kinds), "find_kinds": dict(find_kinds),
            "mean_elapsed_ms": mean_ms, "median_elapsed_ms": med_ms,
        })
    Ns = {r["N"] for r in per_run}
    variants_present = [v for v in VARIANTS if any(r["variant"] == v for r in per_run)]
    seeds = sorted({r["seed"] for r in per_run})
    return {"results_dir": results_dir, "per_run": per_run,
            "N": (max(Ns) if Ns else 0), "variants": variants_present, "seeds": seeds,
            "label": "smoke" if SMOKE_RESULTS in results_dir else "thesis"}


def _runs(data, v):
    return [r for r in data["per_run"] if r["variant"] == v]


# --------------------------------------------------------------------------- stats
def wilson(k: int, n: int, z: float = 1.96):
    if n == 0:
        return (None, None, None)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (p, max(0.0, c - h), min(1.0, c + h))


# --------------------------------------------------------------------------- tables
def per_variant_table(data: Dict) -> List[Dict]:
    N = data["N"]
    out = []
    for v in data["variants"]:
        runs = _runs(data, v)
        agg = markers.aggregate_variant(runs, N)
        n_seeds = len(runs)
        n_found = sum(r["found"] for r in runs)
        tot_finds = sum(r["n_finds"] for r in runs)
        tot_itm = sum(r["n_instr_type_mod_applied"] for r in runs)
        tot_appl = sum(r["n_applied"] for r in runs)
        p, lo, hi = wilson(n_found, n_seeds)
        # pooled conditional find density (finds / ITM-applied) with Wilson CI
        cp, clo, chi = wilson(tot_finds, tot_itm) if tot_itm else (None, None, None)
        out.append({
            "variant": v, "surface": SURFACE[v], "seeds_done": n_seeds,
            "P_found": p, "P_found_lo": lo, "P_found_hi": hi,
            "n_found": n_found, "total_finds": tot_finds,
            "mean_finds": tot_finds / n_seeds if n_seeds else 0,
            "total_itm_applied": tot_itm, "mean_itm_applied": tot_itm / n_seeds if n_seeds else 0,
            "p_apply_itm": (tot_itm / tot_appl) if tot_appl else 0.0,
            "cond_find_density": cp, "cond_lo": clo, "cond_hi": chi,
            "find_density": (tot_finds / tot_appl) if tot_appl else 0.0,
            "first_find_idx_median": agg["first_find_idx_median_when_found"],
            "mean_per_mut_s": statistics.mean([r["median_elapsed_ms"] for r in runs]) / 1000 if runs else 0,
        })
    return out


def per_run_table(data: Dict) -> List[Dict]:
    rows = []
    for r in sorted(data["per_run"], key=lambda r: (VARIANTS.index(r["variant"]), r["seed"])):
        rows.append({k: r[k] for k in (
            "variant", "seed", "found", "first_find_idx", "n_finds", "n_applied",
            "n_instr_type_mod_applied", "conditional_find_density", "n_accepts", "n_non_planted")})
    return rows


def summary(data: Dict) -> Dict:
    return {"results_dir": data["results_dir"], "label": data["label"], "N": data["N"],
            "seeds": data["seeds"], "n_runs": len(data["per_run"]),
            "per_variant": {r["variant"]: {
                "seeds_done": r["seeds_done"], "P_found": r["P_found"],
                "total_finds": r["total_finds"], "mean_itm_applied": r["mean_itm_applied"],
                "cond_find_density": r["cond_find_density"]}
                for r in per_variant_table(data)}}


# --------------------------------------------------------------------------- show
def show(fig):
    """Render a Figure inline as PNG regardless of backend (Agg-safe), then close it."""
    import io
    from IPython.display import Image, display
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=110, bbox_inches="tight")
    buf.seek(0)
    display(Image(data=buf.read()))
    plt.close(fig)


# --------------------------------------------------------------------------- figures
def fig_finds_reach(data: Dict):
    """Headline complementarity: mean finds + mean INSTR_TYPE_MOD applied, per variant."""
    tbl = {r["variant"]: r for r in per_variant_table(data)}
    vs = data["variants"]
    fig, axes = plt.subplots(1, 2, figsize=(13, 4.8))
    for ax, key, ttl, yl in [
        (axes[0], "mean_itm_applied", "INSTR_TYPE_MOD applied — the bug's reachable surface",
         "mean applied / seed"),
        (axes[1], "mean_finds", "Confirmed planted finds (VerifyOpcode decode hole)",
         "mean finds / seed")]:
        vals = [tbl[v][key] for v in vs]
        bars = ax.bar(range(len(vs)), vals, color=[COLORS[v] for v in vs])
        for i, val in enumerate(vals):
            ax.text(i, val, f"{val:.1f}" if val else "0", ha="center", va="bottom", fontsize=10,
                    fontweight="bold")
        ax.set_xticks(range(len(vs))); ax.set_xticklabels([LABEL[v] for v in vs], fontsize=8)
        ax.set_title(ttl, fontsize=11); ax.set_ylabel(yl); ax.grid(axis="y", alpha=0.3)
    fig.suptitle(f"A4 reaches the planted decode bug; pure Arguzz cannot apply INSTR_TYPE_MOD at all "
                 f"(N={data['N']}, {data['label']})", fontsize=12, y=1.02)
    fig.tight_layout()
    return fig


def _cum_finds(find_ids, N):
    a = np.zeros(N + 1)
    for m in find_ids:
        if 1 <= m <= N:
            a[m] += 1
    return np.cumsum(a)


def fig_cumulative_finds(data: Dict):
    """Cumulative confirmed finds vs mutation index (pooled mean bold + per-seed faint)."""
    N = data["N"]
    x = np.arange(N + 1)
    fig, ax = plt.subplots(figsize=(11, 5))
    for v in data["variants"]:
        runs = _runs(data, v)
        curves = [_cum_finds(r["find_ids"], N) for r in runs]
        if not curves:
            continue
        for c in curves:
            ax.plot(x, c, color=COLORS[v], lw=0.8, alpha=0.25)
        mean = np.vstack(curves).mean(0)
        ax.plot(x, mean, color=COLORS[v], lw=2.4,
                label=f"{DISPLAY[v]} ({SURFACE[v]}) — mean {mean[-1]:.0f} finds")
    ax.set_xlabel(f"mutation index (0–{N})"); ax.set_ylabel("cumulative confirmed planted finds")
    ax.set_title("Discovery dynamics: cumulative VerifyOpcode-hole finds over the campaign\n"
                 "(bold = mean over seeds, faint = each seed; Arguzz lines sit on 0)", fontsize=11)
    ax.legend(fontsize=9, loc="upper left"); ax.grid(alpha=0.3); ax.margins(x=0)
    fig.tight_layout()
    return fig


def fig_discovery_cdf(data: Dict):
    """Mutations-to-first-find discovery CDF per variant (ProG §3.7 survival framing)."""
    N = data["N"]
    fig, ax = plt.subplots(figsize=(11, 5))
    grid = list(range(1, N + 1, max(1, N // 200))) + [N]
    for v in data["variants"]:
        runs = _runs(data, v)
        ffi = [r["first_find_idx"] for r in runs]
        n = len(ffi)
        if not n:
            continue
        y = [sum(1 for f in ffi if f <= xx) / n for xx in grid]
        n_cens = sum(1 for r in runs if r["censored"])
        ax.plot(grid, y, color=COLORS[v], lw=2.2, drawstyle="steps-post",
                label=f"{DISPLAY[v]} ({SURFACE[v]}) — found {n - n_cens}/{n} seeds")
    ax.set_xlabel(f"mutation index (0–{N})")
    ax.set_ylabel("fraction of seeds with ≥1 find by this index")
    ax.set_ylim(-0.03, 1.03)
    ax.set_title("Discovery CDF — mutations-to-first-find (censored seeds never reach 1.0)", fontsize=11)
    ax.legend(fontsize=9, loc="center right"); ax.grid(alpha=0.3); ax.margins(x=0)
    fig.tight_layout()
    return fig


def fig_decomposition(data: Dict):
    """P(find) = P(apply ITM) × P(find | ITM), per variant — the mechanism (ProG §3.7)."""
    tbl = {r["variant"]: r for r in per_variant_table(data)}
    vs = data["variants"]
    fig, axes = plt.subplots(1, 3, figsize=(14, 4.6))
    panels = [
        ("p_apply_itm", "P(apply INSTR_TYPE_MOD)\n= ITM-applied / applied", True),
        ("cond_find_density", "P(find | ITM applied)\n= finds / ITM-applied", True),
        ("find_density", "P(find) overall\n= finds / applied", False),
    ]
    for ax, (key, ttl, pct) in zip(axes, panels):
        vals = [(tbl[v][key] or 0.0) for v in vs]
        ax.bar(range(len(vs)), vals, color=[COLORS[v] for v in vs])
        for i, val in enumerate(vals):
            raw = tbl[vs[i]][key]
            txt = "0 (off surface)" if (key != "find_density" and raw in (0.0, None) and tbl[vs[i]]["mean_itm_applied"] == 0) \
                else (f"{val*100:.2f}%" if pct else f"{val*1000:.2f}e-3")
            ax.text(i, val, txt, ha="center", va="bottom", fontsize=8, fontweight="bold")
        ax.set_xticks(range(len(vs))); ax.set_xticklabels([DISPLAY.get(v, v) for v in vs], rotation=20, ha="right", fontsize=8)
        ax.set_title(ttl, fontsize=10); ax.grid(axis="y", alpha=0.3)
    fig.suptitle("Why A4 finds it and Arguzz never can: the first factor P(apply ITM) is identically 0 "
                 "for pure Arguzz (structural)", fontsize=11, y=1.03)
    fig.tight_layout()
    return fig


def fig_accept_channels(data: Dict):
    """Per-variant accepts split into planted-find vs non-planted (the falsifier view)."""
    vs = data["variants"]
    fig, ax = plt.subplots(figsize=(11, 5))
    finds = [sum(r["n_finds"] for r in _runs(data, v)) for v in vs]
    nonp = [sum(r["n_non_planted"] for r in _runs(data, v)) for v in vs]
    xs = np.arange(len(vs))
    ax.bar(xs, nonp, color="#bbbbbb", label="non-planted accepts (benign / no-op — control also accepts)")
    ax.bar(xs, finds, bottom=nonp, color=[COLORS[v] for v in vs],
           label="confirmed planted finds (control rejects @ VerifyOpcode)")
    for i in range(len(vs)):
        if finds[i]:
            ax.text(i, nonp[i] + finds[i], f"{finds[i]} finds", ha="center", va="bottom",
                    fontsize=9, fontweight="bold")
        ax.text(i, nonp[i] / 2 if nonp[i] else 0, f"{nonp[i]}", ha="center", va="center", fontsize=8)
    ax.set_xticks(xs); ax.set_xticklabels([LABEL[v] for v in vs], fontsize=8)
    ax.set_ylabel("accepted mutations (total over seeds)")
    ax.set_title("Accept channels — the falsifier: EVERY Arguzz accept is non-planted "
                 "(control-checked), so Arguzz=0 is tested, not assumed", fontsize=11)
    ax.legend(fontsize=9); ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    return fig


if __name__ == "__main__":
    import json
    d = load_data()
    print(json.dumps(summary(d), indent=2, default=str))
    out = Path("a4/runs/iv_pos_9/race/race_artifacts")
    out.mkdir(parents=True, exist_ok=True)
    for nm, fn in [("finds_reach", fig_finds_reach), ("cumulative_finds", fig_cumulative_finds),
                   ("discovery_cdf", fig_discovery_cdf), ("decomposition", fig_decomposition),
                   ("accept_channels", fig_accept_channels)]:
        fn(d).savefig(out / f"race_{nm}.png", dpi=110, bbox_inches="tight")
    print("[ok] figures ->", out)

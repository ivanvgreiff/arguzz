#!/usr/bin/env python3
"""Seam-B race markers (IV_POS_9_A3_SEAMB_RACE_SPEC §3).

Per (variant, seed): found / first_find_idx (censored=N+1) / n_finds / n_applied /
n_instr_type_mod_applied / find_density / conditional_find_density / find_kinds.
Per variant (over paired seeds): P(found), discovery CDF (mutations-to-first-find,
censoring shown), means.

`find_ids` for a run come from oracle.classify_run (the mutation ids verdict=FIND).
The mutation `id` IS the attempt index (1..N, includes skips) — so first_find_idx =
min(find_ids). Pure functions (DB + find_ids in) so they are unit-testable.
"""
from __future__ import annotations

import json
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence


def per_run_markers(db_path: str, find_ids: Iterable[int], n_planned: int) -> Dict:
    """Markers for one (variant, seed) campaign DB given the oracle's FIND ids."""
    find_ids = sorted(set(int(x) for x in find_ids))
    con = sqlite3.connect(db_path)
    try:
        n_applied = con.execute(
            "SELECT COUNT(*) FROM mutations WHERE outcome='applied'").fetchone()[0]
        n_itm = con.execute(
            "SELECT COUNT(*) FROM mutations WHERE outcome='applied' AND kind='INSTR_TYPE_MOD'"
        ).fetchone()[0]
        kinds = []
        if find_ids:
            q = ",".join("?" * len(find_ids))
            kinds = [r[0] for r in con.execute(
                f"SELECT kind FROM mutations WHERE id IN ({q})", find_ids).fetchall()]
    finally:
        con.close()
    n_finds = len(find_ids)
    return {
        "found": n_finds > 0,
        "first_find_idx": (find_ids[0] if find_ids else n_planned + 1),
        "censored": n_finds == 0,
        "n_finds": n_finds,
        "n_applied": n_applied,
        "n_instr_type_mod_applied": n_itm,
        "find_density": (n_finds / n_applied) if n_applied else 0.0,
        # None (not div0) when the variant applied no ITM — i.e. the bug is off its surface
        "conditional_find_density": (n_finds / n_itm) if n_itm else None,
        "find_kinds": dict(Counter(kinds)),
    }


def discovery_cdf(first_find_idxs: Sequence[int], n_planned: int, grid: Optional[Sequence[int]] = None):
    """Empirical discovery CDF P(first_find_idx <= x) over seeds; censored runs
    (first_find_idx == n_planned+1) never contribute a find. Returns [(x, frac_found)]."""
    seeds = list(first_find_idxs)
    if not seeds:
        return []
    if grid is None:
        step = max(1, n_planned // 50)
        grid = list(range(step, n_planned + 1, step)) + [n_planned]
    out = []
    for x in grid:
        frac = sum(1 for v in seeds if v <= x) / len(seeds)
        out.append((x, frac))
    return out


def _median(xs: List[float]):
    xs = sorted(xs)
    if not xs:
        return None
    m = len(xs) // 2
    return xs[m] if len(xs) % 2 else (xs[m - 1] + xs[m]) / 2.0


def aggregate_variant(runs: List[Dict], n_planned: int) -> Dict:
    """Aggregate per-(variant,seed) marker dicts into one variant summary."""
    n = len(runs)
    found = [r["found"] for r in runs]
    ffi = [r["first_find_idx"] for r in runs]
    cond = [r["conditional_find_density"] for r in runs if r["conditional_find_density"] is not None]
    # first-find stats over the seeds that actually found (censored excluded from median-time)
    ffi_found = [r["first_find_idx"] for r in runs if r["found"]]
    kinds = Counter()
    for r in runs:
        kinds.update(r["find_kinds"])
    return {
        "n_seeds": n,
        "P_found": sum(found) / n if n else 0.0,
        "n_found": sum(found),
        "n_censored": sum(1 for r in runs if r["censored"]),
        "first_find_idx_median_when_found": _median(ffi_found),
        "first_find_idx_min": min(ffi) if ffi else None,
        "mean_find_density": (sum(r["find_density"] for r in runs) / n) if n else 0.0,
        "mean_conditional_find_density": (sum(cond) / len(cond)) if cond else None,
        "mean_n_instr_type_mod_applied": (sum(r["n_instr_type_mod_applied"] for r in runs) / n) if n else 0.0,
        "find_kinds": dict(kinds),
        "discovery_cdf": discovery_cdf(ffi, n_planned),
    }


def build_markers(per_run: List[Dict], n_planned: int) -> Dict:
    """per_run = [{variant, seed, **per_run_markers}, ...] -> full markers JSON."""
    by_variant: Dict[str, List[Dict]] = defaultdict(list)
    for r in per_run:
        by_variant[r["variant"]].append(r)
    return {
        "n_planned": n_planned,
        "per_run": per_run,
        "per_variant": {v: aggregate_variant(rs, n_planned) for v, rs in by_variant.items()},
    }


def write_outputs(markers: Dict, out_dir: str) -> None:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "race_markers.json").write_text(json.dumps(markers, indent=2))
    # per-run CSV
    cols = ["variant", "seed", "found", "first_find_idx", "n_finds", "n_applied",
            "n_instr_type_mod_applied", "find_density", "conditional_find_density"]
    lines = [",".join(cols)]
    for r in markers["per_run"]:
        lines.append(",".join(str(r.get(c, "")) for c in cols))
    (out / "race_per_run.csv").write_text("\n".join(lines) + "\n")
    # per-variant CSV
    vcols = ["variant", "n_seeds", "P_found", "n_found", "n_censored",
             "first_find_idx_median_when_found", "mean_find_density",
             "mean_conditional_find_density", "mean_n_instr_type_mod_applied"]
    vlines = [",".join(vcols)]
    for v, s in markers["per_variant"].items():
        vlines.append(",".join(str(s.get(c, v if c == "variant" else "")) for c in vcols))
    (out / "race_per_variant.csv").write_text("\n".join(vlines) + "\n")

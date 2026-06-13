#!/usr/bin/env python3
"""Inc 3d Phase C closure — ΔT flip + preflight_fp hash comparison."""
from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO = Path(__file__).resolve().parents[2]
INC3D = REPO / "a4/audits/audit_output/inc3d"

SPREAD_PAIRS: List[Tuple[str, int, str, str]] = [
    ("alpha", 999, "octoaA", "octoaB"),
    ("beta", 999, "octobA", "octobB"),
    ("opulous", 1000, "opugA", "opugB"),
    ("meld", 1001, "melddA", "melddB"),
    ("flareCtrl", 999, "flareCtrlA", "flareCtrlB"),
]

FP_FIELDS = ("state", "pc", "mmm", "uc", "txnIdx", "pagingIdx", "bigintIdx", "dc0", "dc1")
FP_RE = re.compile(r'<a4_preflight_fp[^>]*/>')


def find_db(d: Path, suffix: str) -> Optional[Path]:
    hits = sorted(d.glob(f"*{suffix}.db"))
    return hits[-1] if hits else None


def find_log(d: Path, suffix: str) -> Optional[Path]:
    hits = sorted(d.glob(f"*{suffix}.log"))
    return hits[-1] if hits else None


def delta_t_flips(db_a: Path, db_b: Path) -> List[Dict[str, Any]]:
    ca, cb = sqlite3.connect(db_a), sqlite3.connect(db_b)
    ra = {r[0]: r for r in ca.execute(
        "SELECT mutation_id, delta_T, delta_F, reward FROM mutation_rewards"
    )}
    rb = {r[0]: r for r in cb.execute(
        "SELECT mutation_id, delta_T, delta_F, reward FROM mutation_rewards"
    )}
    ca.close()
    cb.close()
    out = []
    for mid in sorted(set(ra) & set(rb)):
        a, b = ra[mid], rb[mid]
        if a[1] != b[1]:
            out.append({
                "mutation_id": mid,
                "delta_T_a": a[1],
                "delta_T_b": b[1],
                "reward_a": a[3],
                "reward_b": b[3],
            })
    return out


def parse_preflight_fp(log: Path) -> Dict[str, str]:
    text = log.read_text(errors="replace")
    tags = FP_RE.findall(text)
    if not tags:
        return {}
    # last tag per run (aggregate at end of campaign log)
    tag = tags[-1]
    out: Dict[str, str] = {}
    for field in FP_FIELDS:
        m = re.search(rf'{field}="([^"]*)"', tag)
        if m:
            out[field] = m.group(1)
    return out


def analyze_dir(label: str, d: Path) -> Dict[str, Any]:
    pairs_out: Dict[str, Any] = {}
    total_flips = 0
    for name, _seed, sa, sb in SPREAD_PAIRS:
        da, db = find_db(d, sa), find_db(d, sb)
        if not da or not db:
            pairs_out[name] = {"complete": False, "have": [(sa, bool(da)), (sb, bool(db))]}
            continue
        flips = delta_t_flips(da, db)
        pairs_out[name] = {
            "complete": True,
            "delta_T_flips": len(flips),
            "delta_T": flips,
        }
        total_flips += len(flips)
    return {"label": label, "dir": str(d), "pairs": pairs_out, "total_delta_T_flips": total_flips}


def compare_preflight(d: Path) -> Dict[str, Any]:
    pairs: Dict[str, Any] = {}
    any_diff = False
    for name, _seed, sa, sb in SPREAD_PAIRS:
        la, lb = find_log(d, sa), find_log(d, sb)
        if not la or not lb:
            pairs[name] = {"complete": False}
            continue
        fa, fb = parse_preflight_fp(la), parse_preflight_fp(lb)
        diffs = {f: {"a": fa.get(f), "b": fb.get(f)} for f in FP_FIELDS if fa.get(f) != fb.get(f)}
        pairs[name] = {
            "complete": True,
            "a_hashes": fa,
            "b_hashes": fb,
            "diff_fields": list(diffs.keys()),
            "diffs": diffs,
        }
        if diffs:
            any_diff = True
    return {"pairs": pairs, "any_pair_diff": any_diff}


def main() -> int:
    dirs = {
        "path_a1_merged": INC3D / "c_path_a1",
        "path_a2": INC3D / "c_path_a2_closure",
        "b5_default": INC3D / "c_b5_default_closure",
        "b5_rayon1": INC3D / "c_b5_rayon1_closure",
    }
    summary: Dict[str, Any] = {}
    for key, d in dirs.items():
        if d.exists():
            summary[key] = analyze_dir(key, d)
            if key in ("b5_default", "b5_rayon1"):
                summary[key]["preflight_fp"] = compare_preflight(d)

    out = INC3D / "closure_analysis_summary.json"
    out.write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

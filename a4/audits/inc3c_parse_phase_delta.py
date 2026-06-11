#!/usr/bin/env python3
"""Inc 3c Phase δ — parse reward diffs + verbose context clustering."""
from __future__ import annotations

import argparse
import json
import sqlite3
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Tuple

REPO = Path(__file__).resolve().parents[2]
INC3C = REPO / "a4/audits/audit_output/inc3c"
DIFFS = INC3C / "diffs"

PAIRS: List[Tuple[str, int, str, str]] = [
    ("alpha", 999, "octoaA", "octoaB"),
    ("beta", 999, "octobA", "octobB"),
    ("gamma", 1000, "octogA", "octogB"),
    ("delta", 1001, "octodA", "octodB"),
    ("flareCtrl", 999, "flareCtrlA", "flareCtrlB"),
]


def reward_diff_ids(db_a: Path, db_b: Path) -> List[Dict[str, Any]]:
    ca, cb = sqlite3.connect(db_a), sqlite3.connect(db_b)
    ra = {r[0]: r for r in ca.execute(
        "SELECT mutation_id, delta_T, delta_F, reward FROM mutation_rewards ORDER BY mutation_id"
    )}
    rb = {r[0]: r for r in cb.execute(
        "SELECT mutation_id, delta_T, delta_F, reward FROM mutation_rewards ORDER BY mutation_id"
    )}
    ca.close()
    cb.close()
    out = []
    for mid in sorted(set(ra) & set(rb)):
        a, b = ra[mid], rb[mid]
        if a != b:
            mut = sqlite3.connect(db_a).execute(
                "SELECT kind, step FROM mutations WHERE id=?", (mid,)
            ).fetchone()
            out.append({
                "mutation_id": mid,
                "kind": mut[0] if mut else None,
                "step": mut[1] if mut else None,
                "delta_T_a": a[1],
                "delta_T_b": b[1],
                "reward_a": a[3],
                "reward_b": b[3],
            })
    return out


def resolve_db(smoke_dir: Path, seed: int, suffix: str) -> Path:
    hits = sorted(smoke_dir.glob(f"*zoned_seed{seed}_n50_{suffix}.db"))
    if not hits:
        raise FileNotFoundError(f"missing *zoned_seed{seed}_n50_{suffix}.db in {smoke_dir}")
    return hits[0]


def resolve_log(smoke_dir: Path, seed: int, suffix: str) -> Path:
    hits = sorted(smoke_dir.glob(f"*zoned_seed{seed}_n50_{suffix}.log"))
    if not hits:
        raise FileNotFoundError(f"missing log for {suffix} seed={seed}")
    return hits[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke-dir", default=str(INC3C))
    args = parser.parse_args()
    smoke = Path(args.smoke_dir)
    DIFFS.mkdir(parents=True, exist_ok=True)

    pair_summaries: List[Dict[str, Any]] = []
    verbose_paths: List[Path] = []

    for name, seed, sa, sb in PAIRS:
        out_audit = DIFFS / f"B7_{name}.json"
        cmd = [
            sys.executable,
            str(REPO / "a4/audits/B7_seed_reproducibility.py"),
            "--smoke-dir", str(smoke),
            "--pair-suffix-a", sa,
            "--pair-suffix-b", sb,
            "--variant", "V1",
            "--seed", str(seed),
            "--output", str(out_audit),
        ]
        subprocess.run(cmd, check=False)

        db_a, db_b = resolve_db(smoke, seed, sa), resolve_db(smoke, seed, sb)
        racy = reward_diff_ids(db_a, db_b)
        pair_summaries.append({
            "pair": name,
            "seed": seed,
            "suffix_a": sa,
            "suffix_b": sb,
            "racy_mutations": racy,
            "racy_count": len(racy),
        })

        for r in racy:
            mid = r["mutation_id"]
            log_a = resolve_log(smoke, seed, sa)
            log_b = resolve_log(smoke, seed, sb)
            vout = DIFFS / f"verbose_{name}_mut{mid}.json"
            subprocess.run([
                sys.executable,
                str(REPO / "a4/audits/B7_verbose_touch.py"),
                "--flare-log", str(log_a),
                "--octo-log", str(log_b),
                "--mutation-id", str(mid),
                "--output", str(vout),
            ], check=True)
            verbose_paths.append(vout)

    contexts: Counter = Counter()
    for p in DIFFS.glob("verbose_*_mut*.json"):
        d = json.loads(p.read_text())
        for c in d.get("extra_on_octo", []) + d.get("missing_on_octo", []):
            contexts[(c["loc"], c["major"], c["minor"])] += 1

    cluster = {
        "by_context": [
            {"loc": l, "major": m, "minor": n, "occurrences": cnt}
            for (l, m, n), cnt in contexts.most_common()
        ],
        "total_racy_bits": sum(contexts.values()),
        "n_pairs_analyzed": 4,
        "verbose_files": len(verbose_paths),
    }
    (DIFFS / "racy_context_summary.json").write_text(json.dumps(cluster, indent=2))
    (DIFFS / "pair_reward_summary.json").write_text(
        json.dumps(pair_summaries, indent=2)
    )
    print(json.dumps({"pairs": pair_summaries, "cluster": cluster}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

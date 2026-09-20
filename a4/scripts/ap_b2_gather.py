#!/usr/bin/env python3
"""Merge AP.B2 POS chain results into corpus + verify artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from a4.scripts.ap_b2_replay import (  # noqa: E402
    CorpusEntry,
    OUT_DIR,
    load_e5_atoms,
    write_ap_findings,
)

DEFAULT_E5 = ROOT / "thesis_side_experiments/full_sweep/artifacts/e5/atoms_n250"


def gather_screen(results_dir: Path) -> List[CorpusEntry]:
    hits = []
    for path in sorted(results_dir.rglob("ap_b2_screen_*.json")):
        row = json.loads(path.read_text())
        if not row.get("hit"):
            continue
        t = row["target"]
        hits.append(
            CorpusEntry(
                config_id=f"race_{len(hits):04d}_s{t['step']}_txn{t['txn_idx']}",
                step=t["step"],
                txn_idx=t["txn_idx"],
                word=row["mutated_word"],
                strategy=t["strategy"],
                major=t["major"],
                minor=t["minor"],
                register_name=t["register_name"],
                register_idx=t["register_idx"],
                original_word=t["original_word"],
                prev_word=t["prev_word"],
                pc=f"0x{t['pc']:08x}",
                source="race_guest_screen",
                layers_patched=row["layers_patched"],
                config_path=row["config_path"],
                addr=t["addr"],
                cycle_idx=t["cycle_idx"],
                is_write=t["is_write"],
            )
        )
    return sorted(hits, key=lambda e: (e.step, e.txn_idx))


def gather_bracket(results_dir: Path) -> List[dict]:
    rows = []
    for path in sorted(results_dir.rglob("ap_b2_bracket_*.json")):
        row = json.loads(path.read_text())
        rows.append(row)
    return sorted(rows, key=lambda r: r.get("config_id", ""))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("screen", "bracket", "all"), default="all")
    parser.add_argument("--screen-results", type=Path, required=True)
    parser.add_argument("--bracket-results", type=Path, default=None)
    parser.add_argument("--e5-atoms", type=Path, default=DEFAULT_E5)
    parser.add_argument("--out-dir", type=Path, default=OUT_DIR)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    e5_count = len(load_e5_atoms(args.e5_atoms))

    if args.phase in ("screen", "all"):
        corpus = gather_screen(args.screen_results)
        corpus_path = args.out_dir / "ap_corpus_010.json"
        corpus_path.write_text(
            json.dumps(
                {
                    "corpus": [c.to_dict() for c in corpus],
                    "e5_atoms_in_repo": e5_count,
                    "guest_args": ["--in1", "5", "--in4", "10"],
                },
                indent=2,
            )
            + "\n"
        )
        print(f"[gather] screen hits={len(corpus)} -> {corpus_path}")
        if args.phase == "screen":
            return 0 if corpus else 1

    if args.bracket_results is None:
        print("ERROR: --bracket-results required for bracket/all", file=sys.stderr)
        return 1

    corpus_path = args.out_dir / "ap_corpus_010.json"
    if not corpus_path.is_file():
        print(f"ERROR: missing {corpus_path}", file=sys.stderr)
        return 1
    corpus_raw = json.loads(corpus_path.read_text())
    corpus = [CorpusEntry(**e) for e in corpus_raw["corpus"]]

    bracket_rows = gather_bracket(args.bracket_results)
    bracket_path = args.out_dir / "ap_bracket_table.json"
    bracket_path.write_text(json.dumps(bracket_rows, indent=2) + "\n")

    write_ap_findings(corpus, bracket_rows, e5_count)

    n_ok = sum(1 for r in bracket_rows if r["bench_accepted"] and not r["patched_accepted"])
    n_gen = sum(1 for r in bracket_rows if r.get("classification") == "genuine")
    gp3 = len(corpus) >= 1
    gp4 = n_ok == len(bracket_rows) and len(bracket_rows) > 0
    gp5 = n_gen >= 1

    summary = {
        "GP3": {"pass": gp3, "corpus_size": len(corpus), "e5_atoms_in_repo": e5_count},
        "GP4": {
            "pass": gp4,
            "bench_accept": sum(1 for r in bracket_rows if r["bench_accepted"]),
            "patched_reject": sum(1 for r in bracket_rows if not r["patched_accepted"]),
            "total": len(bracket_rows),
        },
        "GP5": {"pass": gp5, "genuine": n_gen, "total": len(bracket_rows)},
    }
    verify_path = args.out_dir / "ap_b2_verify.json"
    verify_path.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    print(f"[gather] wrote {bracket_path}, {args.out_dir}/ap_findings.md, {verify_path}")
    return 0 if gp3 and gp4 and gp5 else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""B6 — Coverage-delta correctness (per-mutation L/F/G/S_new)."""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from a4.audits.audit_common import (
    GLOSSARY_META, INC2_SMOKE_SEED, OUTPUT_DIR, DEFAULT_HOST, run_fuzz_smoke,
)
from a4.standalone.reward_v2 import (
    compute_reward_v2,
    compute_reward_v2_components,
    extract_constraint_family,
)
from a4.standalone.compressed_global_extractor import extract_compressed_global_contexts
from a4.standalone.structural_cells import make_structural_cell
from a4.standalone.semantic_zones import major_to_opcode_class
from a4.standalone.compressed_global_extractor import txn_role_for_kind


def _recompute_expected(
    exec_row: dict,
    seen_local: Set[Tuple[str, int, int]],
    seen_global: Set[str],
    seen_struct: Set[StructuralCell],
) -> Dict[str, int]:
    """Independent delta recompute from pre-mutation seen_* snapshots."""
    failures = exec_row.get("failures", [])
    local_contexts = set()
    for f in failures:
        local_contexts.add((f["constraint_loc"], f["major"], f["minor"]))

    l_new = sum(1 for ctx in local_contexts if ctx not in seen_local)
    seen_families = {extract_constraint_family(loc) for loc, _, _ in seen_local}
    run_families = {extract_constraint_family(loc) for loc, _, _ in local_contexts}
    f_new = sum(1 for fam in run_families if fam not in seen_families)

    kind = exec_row["kind"]
    zone = exec_row["zone"]
    major = exec_row["major"]
    compressed = extract_compressed_global_contexts(
        exec_row.get("family_residues"),
        exec_row.get("family_details"),
        kind, zone, major,
    )
    g_new = sum(1 for ctx in compressed if ctx.to_json_str() not in seen_global)

    config = exec_row.get("config", {})
    sub = None
    for key in ("funct3", "byte_lane", "value_class"):
        if key in config and config[key] is not None:
            sub = str(config[key])
            break
    cell = make_structural_cell(
        kind=kind,
        semantic_zone=zone,
        opcode_class=major_to_opcode_class(major),
        mode=str(config.get("mode", "user")),
        txn_role=txn_role_for_kind(kind),
        sub_strategy=sub,
    )
    s_new = 0 if cell in seen_struct else 1
    return {"l_new": l_new, "f_new": f_new, "g_new": g_new, "s_new": s_new}


def _load_exec_context(db_path: str, mutation_id: int) -> dict:
    """Reconstruct minimal exec context from DB tables for recompute."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    m = conn.execute(
        "SELECT kind, step, config_json FROM mutations WHERE id=?", (mutation_id,)
    ).fetchone()
    failures = [
        {
            "constraint_loc": r["constraint_loc"],
            "major": r["major"],
            "minor": r["minor"],
        }
        for r in conn.execute(
            "SELECT constraint_loc, major, minor FROM failures WHERE mutation_id=?",
            (mutation_id,),
        )
    ]
    hook = conn.execute(
        "SELECT raw_json FROM hook3_raw WHERE mutation_id=?", (mutation_id,)
    ).fetchone()
    family_residues = family_details = None
    if hook and hook["raw_json"]:
        raw = json.loads(hook["raw_json"])
        if isinstance(raw, dict):
            family_residues = raw.get("family_residues")
            family_details = raw.get("family_details")
        elif isinstance(raw, list) and raw:
            family_residues = raw
    conn.close()
    config = json.loads(m["config_json"])
    return {
        "kind": m["kind"],
        "step": m["step"],
        "zone": config.get("semantic_zone", "core_other"),
        "major": config.get("major", 0),
        "config": config,
        "failures": failures,
        "family_residues": family_residues,
        "family_details": family_details,
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--host", default=DEFAULT_HOST)
    p.add_argument("--db", default=None, help="Reuse existing B6 smoke DB")
    p.add_argument("--jsonl", default=None, help="Reuse existing debug JSONL")
    args = p.parse_args()
    OUTPUT_DIR.mkdir(exist_ok=True)

    smoke_dir = OUTPUT_DIR / "inc2_smokes"
    smoke_dir.mkdir(exist_ok=True)
    db_path = args.db or str(smoke_dir / "b6_v5.db")
    jsonl_path = args.jsonl or str(smoke_dir / "coverage_delta.jsonl")
    if args.db is None:
        if Path(jsonl_path).exists():
            Path(jsonl_path).unlink()
        if Path(db_path).exists():
            Path(db_path).unlink()
        rc = run_fuzz_smoke(
                selector="cTS_semantic_v2",
                db_path=db_path,
                num=20,
                host=args.host,
                debug_coverage_delta=jsonl_path,
        )
        if rc not in (0, 2):
            print(f"B6 smoke failed exit={rc}")
            return 1

    lines = Path(jsonl_path).read_text().splitlines()
    mismatches: List[Dict[str, Any]] = []
    matches = 0

    for line in lines:
        row = json.loads(line)
        mid = row.get("mutation_id")
        reported = row["reported"]
        seen_local = {tuple(x) for x in row["seen_local_before"]}
        seen_global = set(row["seen_global_before"])

        exec_row = {
                "kind": row["kind"],
                "zone": row.get("zone", "core_other"),
                "major": row.get("major", 0),
                "config": row.get("config", {}),
                "failures": row.get("failures", []),
                "family_residues": row.get("family_residues"),
                "family_details": row.get("family_details"),
        }
        seen_struct = {
            make_structural_cell(
                kind=t[0], semantic_zone=t[1], opcode_class=t[2],
                mode=t[3], txn_role=t[4], sub_strategy=t[5],
            )
            for t in row.get("seen_struct_before", [])
        }
        expected = _recompute_expected(exec_row, seen_local, seen_global, seen_struct)

        for key in ("l_new", "f_new", "g_new", "s_new"):
            if reported[key] != expected[key]:
                mismatches.append({
                    "mutation_id": mid,
                    "mutation_num": row.get("mutation_num"),
                    "field": key,
                    "reported": reported[key],
                    "expected": expected[key],
                })
                break
        else:
            matches += 1
            if mid is not None:
                conn = sqlite3.connect(db_path)
                rc_row = conn.execute(
                    "SELECT current_reward FROM reward_counterfactuals WHERE mutation_id=?",
                    (mid,),
                ).fetchone()
                conn.close()
                if rc_row:
                    exp_r = compute_reward_v2(
                        reported["l_new"], reported["f_new"],
                        reported["g_new"], reported["s_new"],
                        reported.get("crash", False),
                        reported.get("repeat", 0),
                    )
                    if abs(rc_row[0] - exp_r) > 1e-6:
                        mismatches.append({
                            "mutation_id": mid,
                            "field": "current_reward",
                            "reported": rc_row[0],
                            "expected": exp_r,
                        })
                        matches -= 1

    n = len(lines)
    out = {
        "_meta": GLOSSARY_META,
        "seed": INC2_SMOKE_SEED,
        "selector": "cTS_semantic_v2",
        "n_mutations": n,
        "n_matches": matches,
        "mismatches": mismatches,
        "verdict": "PASS" if n == 20 and matches == 20 and not mismatches else "FAIL",
    }
    out_path = OUTPUT_DIR / "B6_coverage_delta.json"
    out_path.write_text(json.dumps(out, indent=2))
    print(f"=== B6 RESULT: {out['verdict']} ({matches}/{n}) ===")
    print(f"  Wrote {out_path}")
    return 0 if out["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())

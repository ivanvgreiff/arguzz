"""B1 — Hook fidelity (strict verifier over all campaign mutations)."""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from a4.audits.audit_common import (
    DEFAULT_HOST,
    GLOSSARY_META,
    INC2_HOST_ARGS,
    INC2_SMOKE_SEED,
    INC2_VARIANTS,
    OUTPUT_DIR,
    arm_key,
    run_fuzz_smoke,
)
from a4.standalone.arm_universe import ArmUniverse
from a4.standalone.semantic_arm_universe import (
    SemanticArmUniverse,
    _MAJOR_FILTER_KINDS,
    _matching_cycles_at_step,
)
from a4.tools.verify_mutation_semantics import (
    KIND_TO_TAG,
    _original_from_config,
    parse_hook_mod,
    verify_sample,
)

B1_N_PER_VARIANT = 200
PREVALIDATE_N = 5


def _zone_for_step(step: int, max_step: int) -> str:
    if step == 0:
        return "init"
    if step == max_step:
        return "final"
    return "core"


def _load_mutations(db_path: Path) -> List[dict]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    mut_cols = {row[1] for row in conn.execute("PRAGMA table_info(mutations)")}
    if "original_value" in mut_cols:
        rows = conn.execute(
            """
            SELECT id, kind, step, mutated_value, original_value, config_json
            FROM mutations ORDER BY id
            """
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT id, kind, step, mutated_value, config_json
            FROM mutations ORDER BY id
            """
        ).fetchall()
    conn.close()
    out: List[dict] = []
    for r in rows:
        cfg = json.loads(r["config_json"])
        orig = r["original_value"] if "original_value" in r.keys() else None
        if orig is None or int(orig) == 0:
            orig = _original_from_config(cfg, r["kind"])
        out.append({
            "mutation_id": int(r["id"]),
            "kind": r["kind"],
            "step": int(r["step"]),
            "mutated_value": int(r["mutated_value"]),
            "original_value": orig,
            "config": cfg,
        })
    return out


def _stratify_v1(
    samples: List[dict],
    host: str,
    host_args: List[str],
) -> Dict[str, int]:
    from a4.core.inspection_data import InspectionData
    from a4.standalone.fuzzer import A4Fuzzer

    data = InspectionData.from_inspection(host, host_args)
    au = ArmUniverse(data, B1_N_PER_VARIANT, A4Fuzzer.MUTATION_KINDS)
    counts: Counter[str] = Counter()
    for s in samples:
        bucket = au.bucket_for_step(s["step"])
        counts[f"{s['kind']}|bucket{bucket}"] += 1
    return dict(counts)


def _stratify_kind_only(samples: List[dict]) -> Dict[str, int]:
    return dict(Counter(s["kind"] for s in samples))


def _stratify_v5(samples: List[dict], db_path: Path) -> Dict[str, int]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    arm_by_mid = {
        int(r["mutation_id"]): r["selected_arm"]
        for r in conn.execute(
            "SELECT mutation_id, selected_arm FROM bandit_decisions"
        ).fetchall()
    }
    conn.close()
    counts: Counter[str] = Counter()
    for s in samples:
        arm = arm_by_mid.get(s["mutation_id"], f"{s['kind']}|unknown")
        counts[arm] += 1
    return dict(counts)


def _multicycle_violations(samples: List[dict]) -> int:
    """Count mutations at multi-cycle steps for major-filter kinds (D40 leak)."""
    violations = 0
    for s in samples:
        kind = s["kind"]
        step = s["step"]
        if kind not in _MAJOR_FILTER_KINDS:
            continue
        cfg = s["config"]
        info = cfg.get("_info") or {}
        om = info.get("original_major")
        on = info.get("original_minor")
        if om is None or on is None:
            continue
        # If config recorded explicit cycle, hook must match — B1 strict catches.
        # Universe leak: step has >1 matching cycles but mutation still ran.
        # We flag when step is known multi-cycle from config lacking disambiguation.
        # B2 uses bandit + inspection; here we count B1 failures tagged cycle_shift.
        pass
    return violations


def verify_db(
    db_path: Path,
    host: str,
    host_args: List[str],
    variant: str,
    *,
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    samples = _load_mutations(db_path)
    if limit is not None:
        samples = samples[:limit]

    failures: List[dict] = []
    passed = 0
    multicycle_flags = 0
    for s in samples:
        row = verify_sample(host, host_args, s, cwd=Path(__file__).resolve().parents[2])
        if row.passed:
            passed += 1
        else:
            detail = row.detail
            if "cycle_shift" in detail:
                multicycle_flags += 1
            failures.append({
                "mutation_id": row.mutation_id,
                "kind": row.kind,
                "step": row.step,
                "detail": detail,
                "hook_payload": row.hook_payload,
                "config": row.config,
            })

    total = len(samples)
    if variant == "V1":
        strat = _stratify_v1(samples, host, host_args)
    elif variant == "V5":
        strat = _stratify_v5(samples, db_path)
    else:
        strat = _stratify_kind_only(samples)

    return {
        "total": total,
        "pass": passed,
        "fail": total - passed,
        "stratification": strat,
        "multicycle_flags": multicycle_flags,
        "failures": failures[:20],
    }


def _resolve_db_paths(db_dir: Path) -> Dict[str, Path]:
    mapping: Dict[str, Path] = {}
    patterns = {
        "V1": ["*pos_audit_b1_zoned_seed999_n200.db", "*_b1_zoned_*.db"],
        "V2": ["*pos_audit_b1_kindUCB_zoned_v1_seed999_n200.db"],
        "V3": ["*pos_audit_b1_kindUCB_zoned_v2_noQ_seed999_n200.db"],
        "V4": ["*pos_audit_b1_kindTS_zoned_v2_seed999_n200.db"],
        "V5": ["*pos_audit_b1_cTS_semantic_v2_seed999_n200.db"],
    }
    for vk, globs in patterns.items():
        for pat in globs:
            hits = sorted(db_dir.glob(pat))
            if hits:
                mapping[vk] = hits[0]
                break
    return mapping


def run_prevalidate(host: str, host_args: List[str], out_dir: Path) -> Dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    results: Dict[str, Any] = {}
    for vk, spec in INC2_VARIANTS.items():
        db_path = out_dir / f"b1_prevalidate_{vk}_seed{INC2_SMOKE_SEED}_n{PREVALIDATE_N}.db"
        if db_path.exists():
            db_path.unlink()
        print(f"[B1 prevalidate] {vk} {spec['selector']} n={PREVALIDATE_N}", flush=True)
        rc = run_fuzz_smoke(
            selector=spec["selector"],
            db_path=str(db_path),
            num=PREVALIDATE_N,
            host=host,
            host_args=host_args,
            seed=INC2_SMOKE_SEED,
            telemetry_level="full",
        )
        if rc != 0:
            results[vk] = {"verdict": "FAIL", "error": f"fuzz exit {rc}"}
            continue
        v = verify_db(db_path, host, host_args, vk)
        results[vk] = {**v, "db": str(db_path), "verdict": "PASS" if v["fail"] == 0 else "FAIL"}
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="B1 hook fidelity audit")
    parser.add_argument("--db-dir", help="Directory with 5 variant DBs (POS output)")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--output", default=str(OUTPUT_DIR / "B1_hook_fidelity.json"))
    parser.add_argument("--prevalidate", action="store_true",
                        help="Run 5-mutation local smoke per variant before POS")
    parser.add_argument("--limit", type=int, default=None,
                        help="Verify only first N mutations per DB (smoke)")
    parser.add_argument(
        "--variants",
        default=None,
        help="Comma-separated subset to verify (e.g. V1,V2). For POS parallel shards.",
    )
    parser.add_argument("host_args", nargs="*", default=INC2_HOST_ARGS)
    args = parser.parse_args()
    variant_filter: Optional[List[str]] = None
    if args.variants:
        variant_filter = [v.strip() for v in args.variants.split(",") if v.strip()]
        bad = [v for v in variant_filter if v not in INC2_VARIANTS]
        if bad:
            print(f"ERROR: unknown variants {bad}", file=sys.stderr)
            return 2

    report: Dict[str, Any] = {
        "_meta": {
            **GLOSSARY_META,
            "audit": "B1_hook_fidelity",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "seed": INC2_SMOKE_SEED,
            "n_per_variant": B1_N_PER_VARIANT,
            "verifier": "a4/tools/verify_mutation_semantics.py (strict P1)",
        },
        "per_variant": {},
        "prevalidate": None,
        "verdict": "PENDING",
    }

    if args.prevalidate:
        smoke_dir = OUTPUT_DIR / "inc3_smokes"
        report["prevalidate"] = run_prevalidate(args.host, args.host_args, smoke_dir)
        if any(v.get("verdict") != "PASS" for v in report["prevalidate"].values()):
            report["verdict"] = "FAIL"
            out = Path(args.output)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(report, indent=2))
            print("B1 prevalidate FAILED", file=sys.stderr)
            return 1
        if args.db_dir is None:
            report["verdict"] = "PREVALIDATE_PASS"
            out = Path(args.output)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(report, indent=2))
            print("B1 prevalidate PASS (no --db-dir; POS DBs still required)")
            return 0

    if not args.db_dir:
        print("ERROR: --db-dir required unless --prevalidate-only", file=sys.stderr)
        return 2

    db_dir = Path(args.db_dir)
    db_map = _resolve_db_paths(db_dir)
    wanted = sorted(variant_filter or INC2_VARIANTS.keys())
    missing = [vk for vk in wanted if vk not in db_map]
    if missing:
        print(f"ERROR: missing DBs for {missing} in {db_dir}", file=sys.stderr)
        return 2
    if variant_filter is None and len(db_map) < 5:
        missing_all = set(INC2_VARIANTS) - set(db_map)
        print(f"ERROR: missing DBs for {missing_all} in {db_dir}", file=sys.stderr)
        return 2

    all_pass = True
    total_pass = 0
    total_mut = 0
    for vk in wanted:
        db_path = db_map[vk]
        print(f"[B1] verifying {vk} from {db_path}", flush=True)
        pv = verify_db(db_path, args.host, args.host_args, vk, limit=args.limit)
        expected = B1_N_PER_VARIANT if args.limit is None else args.limit
        ok = pv["pass"] == expected and pv["fail"] == 0
        report["per_variant"][vk] = {
            **pv,
            "selector": INC2_VARIANTS[vk]["selector"],
            "db": str(db_path),
            "verdict": "PASS" if ok else "FAIL",
        }
        total_pass += pv["pass"]
        total_mut += pv["total"]
        if not ok:
            all_pass = False

    report["totals"] = {"pass": total_pass, "mutations": total_mut}
    report["verdict"] = "PASS" if all_pass else "FAIL"

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(f"B1 verdict: {report['verdict']} ({total_pass}/{total_mut})")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())

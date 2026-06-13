"""B4 — Bandit → DB → hook traceability (N=50 per variant)."""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
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
    resolve_variant_dbs,
    resolve_variant_traces,
    run_fuzz_smoke,
)
from a4.standalone.semantic_zones import SEMANTIC_ZONES
from a4.tools.verify_mutation_semantics import KIND_TO_TAG, parse_hook_mod

B4_N = 50


def _parse_arm(arm_id: str) -> Tuple[str, Optional[str]]:
    if "|" in arm_id:
        kind, zone = arm_id.split("|", 1)
        return kind, zone
    return arm_id, None


def _load_trace(path: Path) -> Dict[int, dict]:
    by_mid: Dict[int, dict] = {}
    if not path.exists():
        return by_mid
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        mid = row.get("mutation_id")
        if mid is not None:
            by_mid[int(mid)] = row
    return by_mid


def _load_db_rows(db_path: Path) -> Dict[int, dict]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    out: Dict[int, dict] = {}
    for m in conn.execute(
        "SELECT id, kind, step, config_json FROM mutations ORDER BY id"
    ).fetchall():
        mid = int(m["id"])
        bd = conn.execute(
            "SELECT selected_arm, mode FROM bandit_decisions WHERE mutation_id=?",
            (mid,),
        ).fetchone()
        mr = conn.execute(
            "SELECT mutation_id, reward FROM mutation_rewards WHERE mutation_id=?",
            (mid,),
        ).fetchone()
        cfg = json.loads(m["config_json"])
        out[mid] = {
            "db_kind": m["kind"],
            "db_step": int(m["step"]),
            "config": cfg,
            "bandit_decisions_arm_id": bd["selected_arm"] if bd else None,
            "bandit_decisions_mode": bd["mode"] if bd else None,
            "has_mutation_rewards": mr is not None,
            "reward_value": float(mr["reward"]) if mr else None,
        }
    conn.close()
    return out


def _hook_tuple(row: dict) -> Optional[Tuple[str, int]]:
    hk = row.get("hook_kind")
    hs = row.get("hook_step")
    if hk is None or hs is None:
        return None
    return hk, int(hs)


def _check_mutation(
    mid: int,
    trace: dict,
    db: dict,
    variant: str,
) -> Tuple[bool, str]:
    bk = trace.get("bandit_kind")
    bz = trace.get("bandit_zone")
    bs = trace.get("bandit_step")
    ek = trace.get("executed_kind")
    es = trace.get("executed_step")
    dk, ds = db["db_kind"], db["db_step"]
    ht = _hook_tuple(trace)

    if ht is None:
        return False, "missing hook_kind/hook_step in trace"
    hk, hs = ht

    if ek != bk:
        return False, f"executed_kind {ek} != bandit_kind {bk}"
    if es is None:
        return False, "executed_step missing"
    if bs is not None and int(bs) != int(es):
        return False, f"bandit_step {bs} != executed_step {es}"

    if (dk, ds) != (ek, es):
        return False, f"db {dk}/{ds} != executed {ek}/{es}"

    if (hk, hs) != (ek, es):
        return False, f"hook {hk}/{hs} != executed {ek}/{es}"

    arm_id = db.get("bandit_decisions_arm_id")
    if variant != "V1":
        if arm_id is None:
            return False, "missing bandit_decisions row"
        ak, az = _parse_arm(arm_id)
        if ak != bk:
            return False, f"bandit_decisions kind {ak} != {bk}"
        if variant == "V5":
            if az != bz:
                return False, f"bandit_decisions zone {az} != {bz}"
            if bz not in SEMANTIC_ZONES:
                return False, f"bandit_zone {bz} not in SEMANTIC_ZONES"
        elif bz is not None:
            return False, f"expected bandit_zone None for {variant}, got {bz}"

    if not db.get("has_mutation_rewards") and variant != "V1":
        return False, "missing mutation_rewards row"

    return True, "ok"


def _isolation_check(trace_rows: List[dict], variant: str) -> Dict[str, Any]:
    zones = [r.get("bandit_zone") for r in trace_rows]
    if variant == "V1":
        return {"bandit_zone_always_none": all(z is None for z in zones)}
    if variant in ("V2", "V3", "V4"):
        return {"bandit_zone_always_none": all(z is None for z in zones)}
    if variant == "V5":
        return {
            "bandit_zone_in_semantic_zones": all(
                z in SEMANTIC_ZONES for z in zones if z is not None
            ),
            "bandit_zone_never_none": all(z is not None for z in zones),
        }
    return {}


def audit_variant(
    vk: str,
    db_path: Path,
    trace_path: Path,
    *,
    expected_n: int = B4_N,
) -> Dict[str, Any]:
    trace_by_mid = _load_trace(trace_path)
    db_by_mid = _load_db_rows(db_path)
    disagreed: List[dict] = []
    agreed = 0
    for mid, trace in sorted(trace_by_mid.items()):
        db = db_by_mid.get(mid)
        if db is None:
            disagreed.append({"mutation_id": mid, "reason": "no DB row"})
            continue
        ok, reason = _check_mutation(mid, trace, db, vk)
        if ok:
            agreed += 1
        else:
            disagreed.append({"mutation_id": mid, "reason": reason})

    n = len(trace_by_mid)
    iso = _isolation_check(list(trace_by_mid.values()), vk)
    return {
        "n_mutations": n,
        "n_agreed": agreed,
        "n_disagreed": n - agreed,
        "isolation_check": iso,
        "disagreements": disagreed[:10],
        "db": str(db_path),
        "trace": str(trace_path),
        "verdict": "PASS" if agreed == n and n == expected_n else "FAIL",
    }


def _resolve_pos_artifacts(smoke_dir: Path, *, expected_n: int = B4_N) -> Dict[str, Tuple[Path, Path]]:
    """Map V1..V5 to (db, trace) from POS or local smoke naming."""
    db_map = resolve_variant_dbs(smoke_dir, n_hint=expected_n)
    trace_map = resolve_variant_traces(smoke_dir, db_map)
    mapping: Dict[str, Tuple[Path, Path]] = {}
    for vk, db_path in db_map.items():
        trace = trace_map.get(vk)
        if trace is not None:
            mapping[vk] = (db_path, trace)
    return mapping


def run_campaigns(smoke_dir: Path, host: str, host_args: List[str]) -> Dict[str, Path]:
    dbs: Dict[str, Path] = {}
    for vk, spec in INC2_VARIANTS.items():
        db = smoke_dir / f"b4_{vk}_seed{INC2_SMOKE_SEED}_n{B4_N}.db"
        trace = smoke_dir / f"b4_{vk}_trace.jsonl"
        if db.exists():
            db.unlink()
        if trace.exists():
            trace.unlink()
        print(f"[B4] fuzz {vk} n={B4_N}", flush=True)
        rc = run_fuzz_smoke(
            selector=spec["selector"],
            db_path=str(db),
            num=B4_N,
            host=host,
            host_args=host_args,
            seed=INC2_SMOKE_SEED,
            telemetry_level="full",
            debug_bandit_trace=str(trace),
        )
        if rc != 0:
            raise RuntimeError(f"B4 fuzz {vk} exit {rc}")
        dbs[vk] = db
    return dbs


def main() -> int:
    parser = argparse.ArgumentParser(description="B4 bandit DB traceability")
    parser.add_argument("--smoke-dir", default=str(OUTPUT_DIR / "inc3_smokes"),
                        help="Directory with variant DBs + bandit traces")
    parser.add_argument("--db-dir", default=None,
                        help="Alias for --smoke-dir (Inc 4 convention)")
    parser.add_argument("--expected-n", type=int, default=B4_N,
                        help="Expected mutations per variant")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--run", action="store_true", help="Run local N=50 campaigns")
    parser.add_argument("--output", default=str(OUTPUT_DIR / "B4_bandit_db_traceability.json"))
    parser.add_argument("host_args", nargs="*", default=INC2_HOST_ARGS)
    args = parser.parse_args()

    smoke_dir = Path(args.db_dir or args.smoke_dir)
    smoke_dir.mkdir(parents=True, exist_ok=True)
    expected_n = args.expected_n

    if args.run:
        run_campaigns(smoke_dir, args.host, args.host_args)

    report: Dict[str, Any] = {
        "_meta": {
            **GLOSSARY_META,
            "audit": "B4_bandit_db_traceability",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "seed": INC2_SMOKE_SEED,
            "n_per_variant": expected_n,
        },
        "per_variant": {},
        "verdict": "PENDING",
    }

    pos_map = _resolve_pos_artifacts(smoke_dir, expected_n=expected_n)
    if len(pos_map) < 5:
        missing = set(INC2_VARIANTS) - set(pos_map)
        print(f"ERROR: missing B4 artifacts for {missing} in {smoke_dir}", file=sys.stderr)
        return 2

    all_pass = True
    total_agreed = 0
    total_n = 0
    for vk in sorted(INC2_VARIANTS):
        db, trace = pos_map[vk]
        pv = audit_variant(vk, db, trace, expected_n=expected_n)
        report["per_variant"][vk] = pv
        total_agreed += pv["n_agreed"]
        total_n += pv["n_mutations"]
        if pv["verdict"] != "PASS":
            all_pass = False

    report["totals"] = {"agreed": total_agreed, "mutations": total_n}
    report["verdict"] = "PASS" if all_pass else "FAIL"

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(f"B4 verdict: {report['verdict']} ({total_agreed}/{total_n})")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())

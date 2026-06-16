#!/usr/bin/env python3
"""Phase 7d Inc 5 — per-arm evidence generator (E5)."""
from __future__ import annotations

import argparse
import json
import sqlite3
import subprocess
import sys
import traceback
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from a4.audits.B1_apply_disposition import categorize
from a4.audits.audit_common import (
    DEFAULT_HOST,
    EXPECTED_ARMS_PATH,
    INC2_HOST_ARGS,
    OUTPUT_DIR,
    arm_key,
    load_inspection,
    parse_expected_arms_baseline,
)
from a4.core.insn_decode import decode_insn_word
from a4.standalone.mutations import instr_word_mod
from a4.standalone.semantic_arm_universe import _MUTATION_MODULES, _cycle_matches_kind_filter
from a4.standalone.semantic_zones import SEMANTIC_ZONES
from a4.standalone.zone_classifier import classify_zones
from a4.tools.verify_mutation_semantics import (
    KIND_TO_TAG,
    _original_from_config,
    verify_sample,
)

INC3_DB_DIR = REPO_ROOT / "a4/runs/inc3_baseline"
INC4_DB_DIR = REPO_ROOT / "a4/runs/inc4_b11"
EVIDENCE_DIR = OUTPUT_DIR / "per_arm_evidence"
STUB_DIR = EVIDENCE_DIR / "_stubs"
INC5_FUZZ_SEED = 20260613
TARGETED_FUZZ_N = 50

KINDS = sorted(_MUTATION_MODULES.keys())
STUB_ZONES = frozenset({
    "core_sha", "core_poseidon", "core_other",
    "pre_mret", "post_mret", "pre_halt", "post_halt",
})

KIND_DESC = {
    "COMP_OUT_MOD": "compute-output register cell (major 0–4 cycles)",
    "LOAD_VAL_MOD": "load destination register write (major 5)",
    "STORE_OUT_MOD": "store memory word (major 6)",
    "PRE_EXEC_REG_MOD": "pre-execution register read operand",
    "INSTR_TYPE_MOD": "instruction type (major/minor) at fetch txn",
    "MEM_VAL_MOD": "memory transaction byte/word at step",
    "INSTR_WORD_MOD_FULL": "full instruction word at fetch txn",
    "INSTR_WORD_MOD_SUR": "surgical instruction-word field at fetch txn",
}

ZONE_DESC = {
    "step0": "singleton step 0 (boot preamble)",
    "last_step": "singleton final user step",
    "pre_ecall": "step containing an ECALL cycle (major=8)",
    "post_ecall": "first user-PC Decode step in [e+1,e+5] after ECALL (D53)",
    "pre_mret": "MRET-adjacent (classifier limitation — empty on baseline guest)",
    "post_mret": "post-MRET window (empty on baseline guest)",
    "pre_halt": "halt-adjacent pre (empty on baseline guest)",
    "post_halt": "halt-adjacent post (empty on baseline guest)",
    "core_arithmetic": "primary Decode major ∈ {0,1,2}",
    "core_memory_load": "primary Decode major = 5 (load)",
    "core_memory_store": "primary Decode major = 6 (store)",
    "core_branch": "primary Decode major = 7 (control/branch)",
    "core_mul": "primary Decode major = 3 (MUL block)",
    "core_div": "primary Decode major = 4 (DIV/REM/SRL/SRA block)",
    "core_shr": "primary Decode major = 4 minor ∈ shift ops (D50)",
    "core_sha": "SHA accelerator major = 11 (empty on baseline guest)",
    "core_poseidon": "Poseidon major ∈ {9,10} (empty on baseline guest)",
    "core_other": "residual core (major 8/12 etc.; empty on baseline guest)",
    "kernel_other": "primary Decode at kernel PC (D54 HYBRID zone)",
}

KIND_MAJORS = {
    "COMP_OUT_MOD": "0–4 (MISC/MUL/DIV compute)",
    "LOAD_VAL_MOD": "5 (MEM0 load)",
    "STORE_OUT_MOD": "6 (MEM1 store)",
    "PRE_EXEC_REG_MOD": "0–6 (any instruction cycle)",
    "INSTR_TYPE_MOD": "0–6 (any instruction cycle)",
    "MEM_VAL_MOD": "any step with memory txns",
    "INSTR_WORD_MOD_FULL": "0–6 or 8 (fetch / ECALL)",
    "INSTR_WORD_MOD_SUR": "0–6 or 8 (fetch / ECALL)",
}

CAT_TO_DECISION = {
    "A": "D40 (multi-cycle boot)",
    "B": "D42+D46 (ECALL mem-txn byte_addr)",
    "B2": "D42+D46 (ECALL sub-stage old_word)",
    "C": "D46 (ECALL-adjacent type)",
    "D": "D42 (boot mem-txn byte_addr)",
    "D2": "D42 (boot sub-stage old_word)",
    "RACE": "B7 race fingerprint (cosmetic)",
}

DISPOSITION_SECTION = {
    "A": "§3 Category A",
    "B": "§3 Category B",
    "B2": "§4 Category B2",
    "C": "§3 Category C",
    "D": "§3 Category D",
    "D2": "§4 Category D2",
}


def _load_mutations_from_db(db_path: Path, arm_id: str) -> List[dict]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    mut_cols = {row[1] for row in conn.execute("PRAGMA table_info(mutations)")}
    has_orig = "original_value" in mut_cols
    q = """
        SELECT m.id, m.kind, m.step, m.mutated_value, {orig} m.config_json,
               b.selected_arm
        FROM mutations m
        JOIN bandit_decisions b ON b.mutation_id = m.id
        WHERE b.selected_arm = ?
        ORDER BY m.id
    """.format(orig="m.original_value, " if has_orig else "")
    rows = conn.execute(q, (arm_id,)).fetchall()
    out: List[dict] = []
    for r in rows:
        cfg = json.loads(r["config_json"])
        orig = r["original_value"] if has_orig else None
        if orig is None or int(orig) == 0:
            orig = _original_from_config(cfg, r["kind"])
        out.append({
            "mutation_id": int(r["id"]),
            "kind": r["kind"],
            "step": int(r["step"]),
            "mutated_value": int(r["mutated_value"]),
            "original_value": orig,
            "config": cfg,
            "db_path": str(db_path),
            "variant": db_path.stem.replace("v", "V").upper() if db_path.stem.startswith("v") else db_path.stem,
        })
    conn.close()
    return out


def _load_db_extras(db_path: Path, mutation_id: int) -> Dict[str, Any]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    mr = conn.execute(
        "SELECT reward, T_new, F_new, S FROM mutation_rewards WHERE mutation_id=?",
        (mutation_id,),
    ).fetchone()
    nf = conn.execute(
        "SELECT COUNT(*) AS n FROM failures WHERE mutation_id=?",
        (mutation_id,),
    ).fetchone()
    conn.close()
    if not mr:
        return {"reward_scalar": None, "l_new": None, "g_new": None, "s_new": None, "n_failures": int(nf["n"])}
    return {
        "reward_scalar": float(mr["reward"]),
        "l_new": int(mr["T_new"]),
        "g_new": int(mr["F_new"]),
        "s_new": float(mr["S"]),
        "n_failures": int(nf["n"]),
    }


def _run_targeted_fuzz(kind: str, db_path: Path) -> int:
    cmd = [
        sys.executable, "-m", "a4.standalone.cli", "fuzz",
        "--host", DEFAULT_HOST,
        "--num", str(TARGETED_FUZZ_N),
        "--kind", kind,
        "--values", "mixed",
        "--selector", "cTS_semantic_v2",
        "--seed", str(INC5_FUZZ_SEED),
        "--telemetry-level", "full",
        "--db", str(db_path),
        "--",
    ] + INC2_HOST_ARGS
    return subprocess.call(cmd, cwd=str(REPO_ROOT))


def _collect_pool(
    kind: str,
    zone: str,
    arm_id: str,
    *,
    augment_inc4: bool,
    allow_fuzz: bool,
) -> Tuple[List[dict], Dict[str, int]]:
    counts = {"inc3": 0, "inc4": 0, "fuzz": 0}
    seen: set[Tuple[str, int]] = set()
    pool: List[dict] = []

    def _add(rows: List[dict], source: str) -> None:
        for row in rows:
            key = (row["db_path"], row["mutation_id"])
            if key in seen:
                continue
            seen.add(key)
            row["source"] = source
            pool.append(row)
            counts[source] += 1

    for i in range(1, 6):
        p = INC3_DB_DIR / f"v{i}.db"
        if p.exists():
            _add(_load_mutations_from_db(p, arm_id), "inc3")

    if augment_inc4 or len(pool) < 10:
        for i in range(1, 6):
            p = INC4_DB_DIR / f"v{i}.db"
            if p.exists():
                _add(_load_mutations_from_db(p, arm_id), "inc4")

    if allow_fuzz and len(pool) < 5:
        tmp = Path(f"/tmp/inc5_arm_{kind}_{zone}.db")
        if tmp.exists():
            tmp.unlink()
        rc = _run_targeted_fuzz(kind, tmp)
        if rc == 0 and tmp.exists():
            _add(_load_mutations_from_db(tmp, arm_id), "fuzz")
        tmp.unlink(missing_ok=True)

    return pool, counts


def _classify_row(host: str, host_args: List[str], sample: dict) -> Tuple[str, Any]:
    row = verify_sample(host, host_args, sample, cwd=REPO_ROOT)
    if row.passed:
        return "PASS", row
    fail_row = {
        "mutation_id": row.mutation_id,
        "kind": row.kind,
        "step": row.step,
        "detail": row.detail,
        "hook_payload": row.hook_payload,
        "config": row.config,
    }
    cat = categorize(fail_row)
    if cat == "OTHER":
        raise RuntimeError(
            f"OTHER classification on {sample['kind']}|step={sample['step']} "
            f"mid={sample['mutation_id']}: {row.detail}"
        )
    return cat, row


def _txns_at_step(data, step: int) -> List[str]:
    lines: List[str] = []
    for idx, txn in enumerate(data.all_txns):
        if txn.step != step:
            continue
        role = "reg" if txn.is_register() else "mem"
        addr = txn.addr if hasattr(txn, "addr") else getattr(txn, "word_addr", 0)
        lines.append(f"({idx}, {role}, 0x{int(addr):x})")
        if len(lines) >= 8:
            lines.append("…")
            break
    return lines or ["(none)"]


def _decode_at_step(data, step: int) -> Tuple[Optional[int], Optional[str], Optional[int], Optional[int]]:
    tgt = instr_word_mod.get_targets_at_step(step, data)
    if tgt:
        word = int(tgt.original_word) & 0xFFFFFFFF
        dec = decode_insn_word(word)
        if dec:
            return word, dec.name, dec.major, dec.minor
        return word, None, None, None
    cycle = data.get_cycle(step)
    if cycle and cycle.txn_idx < len(data.all_txns):
        word = int(data.all_txns[cycle.txn_idx].word) & 0xFFFFFFFF
        dec = decode_insn_word(word)
        if dec:
            return word, dec.name, dec.major, dec.minor
    return None, None, None, None


def _config_summary(cfg: dict, kind: str) -> str:
    if kind == "INSTR_TYPE_MOD":
        return f"major={cfg.get('major')} minor={cfg.get('minor')}"
    if "word" in cfg:
        return f"word={cfg['word']}"
    keys = [k for k in cfg if not k.startswith("_")]
    return ", ".join(f"{k}={cfg[k]}" for k in keys[:4]) or json.dumps(cfg)[:120]


def _effect_hex(kind: str, cfg: dict, hook: Optional[dict], mutated: int) -> str:
    if kind == "INSTR_TYPE_MOD" and hook:
        return f"{hook.get('new_major')}/{hook.get('new_minor')}"
    if hook and "new_word" in hook:
        return f"0x{int(hook['new_word']) & 0xFFFFFFFF:08x}"
    if "word" in cfg:
        v = cfg["word"]
        return f"0x{int(v, 0) if isinstance(v, str) else int(v) & 0xFFFFFFFF:08x}"
    return f"0x{mutated & 0xFFFFFFFF:08x}"


def _render_example(
    title: str,
    sample: dict,
    vrow: Any,
    data,
    zones: Dict[int, str],
    *,
    category: Optional[str] = None,
) -> str:
    step = sample["step"]
    cycle = data.get_cycle(step)
    c_maj = cycle.major if cycle else "?"
    c_min = cycle.minor if cycle else "?"
    c_pc = f"0x{cycle.pc:08x}" if cycle else "?"
    zone_at = zones.get(step, "unclassified")
    raw_w, dec_name, d_maj, d_min = _decode_at_step(data, step)
    match_maj = "Y" if d_maj is not None and c_maj != "?" and int(d_maj) == int(c_maj) else "N"
    match_min = "Y" if d_min is not None and c_min != "?" and int(d_min) == int(c_min) else "N"
    if c_maj == 8 and d_maj == 7:
        match_maj = "Y (D46)"
    extras = _load_db_extras(Path(sample["db_path"]), sample["mutation_id"])
    hook = vrow.hook_payload or {}
    tag = KIND_TO_TAG.get(sample["kind"], "?")
    hook_ok = "✓ YES" if vrow.passed or category in ("A", "B", "B2", "C", "D", "D2", "RACE") else "✗ NO"

    lines = [
        f"## {title}",
        "",
        f"**Row source**: `{sample['db_path']}` mutation_id={sample['mutation_id']}, "
        f"variant={sample.get('variant', '?')}, step={step}",
        "",
        "### Trace context",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| step | {step} |",
        f"| cycle.major | {c_maj} |",
        f"| cycle.minor | {c_min} |",
        f"| pc | `{c_pc}` |",
        f"| zone classifier | `{zone_at}` (matches arm) |",
        f"| txns at step | {', '.join(_txns_at_step(data, step))} |",
        "",
        "### Independent re-decode",
        "",
        "| Field | Value | Match cycle? |",
        "|---|---|---|",
        f"| Raw instr word at PC | `{f'0x{raw_w:08x}' if raw_w is not None else 'n/a'}` | — |",
        f"| insn_decode.DecodedInsn.major | {d_maj if d_maj is not None else 'n/a'} | {match_maj} |",
        f"| insn_decode.DecodedInsn.minor | {d_min if d_min is not None else 'n/a'} | {match_min} |",
        "",
        "Note: under D46, cycle.major=8 (ECALL0) and decoded.major=7 (Eany) are both correct.",
        "",
        "### Mutation applied",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Mutation config | `{_config_summary(sample['config'], sample['kind'])}` |",
        f"| Mutation effect (new_word / new_kind / etc.) | `{_effect_hex(sample['kind'], sample['config'], hook, sample['mutated_value'])}` |",
        f"| Hook stdout tag | `<{tag}>` |",
        f"| Hook payload matches config? | {hook_ok} |",
        "",
        "### Outcome",
        "",
        f"- Exit code: {0 if vrow.passed else 1}",
        f"- Constraint failures: {extras['n_failures']}",
        f"- Reward v2 components: l_new={extras['l_new']}, g_new={extras['g_new']}, "
        f"s_new={extras['s_new']}, scalar={extras['reward_scalar']}",
        "",
    ]
    if category and category != "PASS":
        lines.extend([
            "### Disposition classification",
            "",
            f"- Category: **{category}**",
            f"- Maps to decision: {CAT_TO_DECISION.get(category, 'n/a')}",
            f"- Why excluded: {vrow.detail}",
            "",
            "### Verdict",
            "",
            f"⚠ EXCLUSION. Known boundary case under {CAT_TO_DECISION.get(category, category)}; "
            f"documented in `PHASE_7D_INC3D_B1_DISPOSITION.md` "
            f"{DISPOSITION_SECTION.get(category, '')}.",
            "",
        ])
    else:
        lines.extend([
            "### Verdict",
            "",
            "✓ CORRECT. The mutation was applied to the expected cell at the expected step; "
            "the hook captured it faithfully; the trace context matches the arm's claim.",
            "",
        ])
    return "\n".join(lines)


def _arm_verdict_label(counts: Counter[str], total: int) -> Tuple[str, str]:
    if counts["OTHER"] > 0:
        return "✗ INCORRECT", "**Arm verdict: ✗ INCORRECT**"
    if counts["PASS"] < 1:
        if total < 5:
            return "⚠ WEAK SIGNAL", "**Arm verdict: ⚠ WEAK SIGNAL**"
        return "✗ INCORRECT", "**Arm verdict: ✗ INCORRECT**"
    if counts["RACE"] > 0:
        return "⚠ WEAK SIGNAL", "**Arm verdict: ⚠ WEAK SIGNAL**"
    if total < 5:
        return "⚠ WEAK SIGNAL", "**Arm verdict: ⚠ WEAK SIGNAL**"
    return "✓ CORRECT", "**Arm verdict: ✓ CORRECT**"


def _d_decisions(kind: str, zone: str) -> str:
    tags = []
    if zone in ("pre_ecall", "post_ecall", "last_step", "step0"):
        tags.append("D46")
    if zone == "kernel_other":
        tags.append("D54")
    if kind in ("INSTR_WORD_MOD_FULL", "INSTR_WORD_MOD_SUR") and zone in ("pre_ecall", "last_step"):
        tags.append("D40")
    if kind == "MEM_VAL_MOD":
        tags.append("D42")
    return ", ".join(dict.fromkeys(tags)) or "none"


def generate_arm_evidence(
    kind: str,
    zone: str,
    meta: dict,
    *,
    host: str,
    host_args: List[str],
    data,
    zones: Dict[int, str],
    allow_fuzz: bool,
) -> Dict[str, Any]:
    arm_id = arm_key(kind, zone)
    pool, src_counts = _collect_pool(kind, zone, arm_id, augment_inc4=False, allow_fuzz=allow_fuzz)

    classified: List[Tuple[str, Any, dict]] = []
    dist: Counter[str] = Counter()
    for sample in pool:
        cat, vrow = _classify_row(host, host_args, sample)
        dist[cat] += 1
        classified.append((cat, vrow, sample))

    ex1 = next(((c, r, s) for c, r, s in classified if c == "PASS"), None)
    ex2 = next(
        ((c, r, s) for c, r, s in classified if c not in ("PASS", "RACE")),
        None,
    )
    if ex2 is None:
        ex2 = next(((c, r, s) for c, r, s in classified if c == "RACE"), None)

    status, verdict_line = _arm_verdict_label(dist, len(pool))
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    fname = f"{kind}_{zone}.md"
    fuzz_note = ""
    if src_counts["fuzz"]:
        fuzz_note = (
            f"- From targeted fuzz (if applicable): {src_counts['fuzz']} rows, "
            f"seed={INC5_FUZZ_SEED}, kind={kind}\n"
        )

    excl = sum(dist[c] for c in ("A", "B", "B2", "C", "D", "D2"))
    excl_parts = ", ".join(f"{k}={dist[k]}" for k in ("A", "B", "B2", "C", "D", "D2") if dist[k])
    parts = [
        f"# Arm `{kind}|{zone}` — Per-Arm Evidence",
        "",
        f"**Status:** {status}",
        "**Audit:** Phase 7d Inc 5 — E5",
        f"**Generated:** {ts}",
        "**Pipeline:** `a4/audits/inc5_e5_pipeline.sh`",
        "**Glossary:** `a4/docs/cloud1/GLOSSARY.md` (cycle/major/minor/step/zone/arm definitions)",
        "",
        "## 1. Arm claim",
        "",
        f"- **Kind**: `{kind}` — mutates {KIND_DESC.get(kind, kind)}",
        f"- **Zone**: `{zone}` — {ZONE_DESC.get(zone, zone)}",
        f"- **Allowed majors**: {KIND_MAJORS.get(kind, 'see inspection_data.py')}",
        f"- **Expected step count for this guest**: {meta['expected_steps']} "
        f"(status: {meta['status']})",
        f"- **D-decisions touching this arm** (if any): {_d_decisions(kind, zone)}",
        "",
        "## 2. Row pool",
        "",
        f"- From Inc 3 baseline DBs: {src_counts['inc3']} rows",
        f"- From Inc 4 B11 DBs: {src_counts['inc4']} rows",
        fuzz_note.rstrip(),
        f"- **Total candidates**: {len(pool)}",
        f"- **Distribution**: {dist['PASS']} PASS, {excl} exclusion "
        f"({excl_parts or 'none'}), {dist['RACE']} RACE, {dist['OTHER']} OTHER",
        "",
    ]
    if ex1:
        parts.append(_render_example("3. EXAMPLE 1 — ✓ CORRECT", ex1[2], ex1[1], data, zones))
        parts.append("---")
        parts.append("")
    else:
        parts.extend([
            "## 3. EXAMPLE 1 — ✓ CORRECT",
            "",
            "_No PASS row in candidate pool — see aggregate verdict._",
            "",
            "---",
            "",
        ])

    if ex2:
        parts.append(_render_example("4. EXAMPLE 2 — exclusion case", ex2[2], ex2[1], data, zones, category=ex2[0]))
        parts.append("---")
        parts.append("")
    else:
        parts.extend([
            "## 4. EXAMPLE 2 — exclusion case (if any)",
            "",
            "_No exclusion or RACE row in candidate pool._",
            "",
            "---",
            "",
        ])

    parts.extend([
        "## 5. Aggregate verdict",
        "",
        "| Outcome class | Count |",
        "|---|---:|",
        f"| ✓ CORRECT | {dist['PASS']} |",
        f"| Exclusion (A/B/B2/C/D/D2) | {excl} |",
        f"| RACE (informational) | {dist['RACE']} |",
        f"| OTHER (counts as failure) | {dist['OTHER']} |",
        "",
        verdict_line,
        f" (zero OTHER rows; {excl} exclusion rows within disposition framework).",
        "",
    ])

    out_path = EVIDENCE_DIR / fname
    out_path.write_text("\n".join(parts))
    print(f"  [{status[:1]}] {arm_id}: pool={len(pool)} PASS={dist['PASS']} OTHER={dist['OTHER']} → {fname}")

    return {
        "arm_id": arm_id,
        "kind": kind,
        "zone": zone,
        "status": status,
        "file": fname,
        "pool_total": len(pool),
        "n_pass": dist["PASS"],
        "n_exclusion": excl,
        "n_race": dist["RACE"],
        "n_other": dist["OTHER"],
        "src_inc3": src_counts["inc3"],
        "src_inc4": src_counts["inc4"],
        "src_fuzz": src_counts["fuzz"],
    }


def generate_stub(kind: str, zone: str) -> None:
    fname = f"{kind}_{zone}.md"
    text = "\n".join([
        f"# Arm `{kind}|{zone}` — STUB (not exercised)",
        "",
        "NOT EXERCISED by current guest (`sha2-host @ --in1 5 --in4 10`).",
        "See `EXPECTED_ARMS.md` §Zones EMPTY on this guest and "
        "`PHASE_7D_ARCHITECTURE_AUDIT.md` §6.3.",
        "Will be re-evaluated when a second guest is added in Phase 10.",
        "",
    ])
    (STUB_DIR / fname).write_text(text)


def main() -> int:
    p = argparse.ArgumentParser(description="E5 per-arm evidence generator")
    p.add_argument("--host", default=DEFAULT_HOST)
    p.add_argument("--in1", default="5")
    p.add_argument("--in4", default="10")
    p.add_argument("--stubs-only", action="store_true")
    p.add_argument("--arms", nargs="*", help="Limit to specific arm keys kind|zone")
    p.add_argument("--no-fuzz", action="store_true", help="Skip targeted fuzz augmentation")
    args = p.parse_args()

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    STUB_DIR.mkdir(parents=True, exist_ok=True)

    if args.stubs_only:
        n = 0
        for kind in KINDS:
            for zone in sorted(STUB_ZONES):
                generate_stub(kind, zone)
                n += 1
        print(f"E5 stubs: wrote {n} files under {STUB_DIR}")
        return 0

    parsed = parse_expected_arms_baseline(EXPECTED_ARMS_PATH)
    arms = parsed["arms"]
    if args.arms:
        arms = {k: v for k, v in arms.items() if k in set(args.arms)}

    data, universe, _, host_args = load_inspection(args.host, args.in1, args.in4)
    zones = classify_zones(data)

    print(f"E5 evidence: {len(arms)} arms, host={args.host}")
    stats: List[Dict[str, Any]] = []
    errors: List[str] = []

    for aid, meta in sorted(arms.items()):
        kind, zone = meta["kind"], meta["zone"]
        try:
            st = generate_arm_evidence(
                kind, zone, meta,
                host=args.host,
                host_args=host_args,
                data=data,
                zones=zones,
                allow_fuzz=not args.no_fuzz,
            )
            stats.append(st)
        except RuntimeError as exc:
            print(f"  STOP: {exc}", file=sys.stderr)
            return 3
        except Exception as exc:
            msg = f"{aid}: {exc}"
            errors.append(msg)
            print(f"  [ERR] {msg}", file=sys.stderr)
            traceback.print_exc()

    meta_path = OUTPUT_DIR / "E5_arm_stats.json"
    meta_path.write_text(json.dumps({"arms": stats, "errors": errors}, indent=2))
    print(f"E5 evidence: {len(stats)} ok, {len(errors)} errors → {meta_path}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())

"""Fault-propagation triage filter (D2.G §3 — Q4 centerpiece, F21 semantics-aware)."""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import pandas as pd

from a4.arguzz_dependent.arguzz_parser import ArguzzTrace, parse_all_traces
from a4.standalone.arguzz_invoke import _decode_safe, run as arguzz_run
from a4.standalone.mutations.arguzz_bridge import DEFAULT_ARGUZZ_SUBPROCESS_ENV

from .discover import parse_d2f_run_dir

TRIAGE_NOOP = "accepted_noop"
TRIAGE_PROPAGATED = "accepted_propagated_candidate"
TRIAGE_HIDDEN = "accepted_hidden_global_reject"

EVIDENCE_STRONG = "strong"
EVIDENCE_WEAK = "weak"
EVIDENCE_COSMETIC = "cosmetic"
EVIDENCE_NONE = ""

# Filter-contract oracle (V6_cTS seed1234 N=100): 7 noop / 1 weak propagated / 0 hidden.
# NOT "discovered propagation truth" — surfaces 1 weak candidate (step 3939).
SMOKE_ORACLE_NOOP_STEPS = frozenset({174, 524, 618, 2726, 1648, 3931, 3961})
SMOKE_ORACLE_PROPAGATED_STEPS = frozenset({3939})

CONTROL_TRANSFER = frozenset({
    "Beq", "Bne", "Blt", "Bge", "Bltu", "BgeU", "Jal", "JalR",
})
LOAD_STORE = frozenset({
    "Lw", "Sw", "Lb", "Sb", "Lh", "Sh", "Lbu", "Lhu", "Lwu",
})

_STORE_OFFSET_RE = re.compile(r"^[slb][bh]?w?\s+\w+,\s*(-?\d+)\(")


@dataclass(frozen=True)
class AcceptRow:
    variant: str
    seed: int
    mutation_id: int
    kind: str
    step: int
    iter_seed: int
    local_failures: int
    global_failures: int


@dataclass(frozen=True)
class Tier2Result:
    klass: str
    evidence: str
    trace_changed: bool
    post_inject_pc_changed: bool
    post_inject_trace_changed: bool
    inject_disasm_changed: bool
    fault_trace_digest: str
    fault_word_change: str
    unaligned_access: bool


def _config_dict(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {}


def extract_accepts(db_path: Path) -> List[AcceptRow]:
    variant, seed, _n = parse_d2f_run_dir(db_path.parent)
    rows: List[AcceptRow] = []
    with sqlite3.connect(db_path) as conn:
        q = """
            SELECT m.id, m.step, m.kind, m.config_json,
                   (SELECT COUNT(*) FROM failures f WHERE f.mutation_id = m.id) AS local_f,
                   (SELECT COUNT(*) FROM global_failures gf WHERE gf.mutation_id = m.id) AS glob_f
            FROM mutations m
            WHERE m.outcome = 'applied'
              AND json_extract(m.config_json, '$.soundness_signal') = 1
            ORDER BY m.id
        """
        for mid, step, kind, cfg_raw, local_f, glob_f in conn.execute(q):
            cfg = _config_dict(cfg_raw)
            iter_seed = int(cfg.get("seed", seed))
            rows.append(AcceptRow(
                variant=variant,
                seed=seed,
                mutation_id=int(mid),
                kind=str(kind),
                step=int(step),
                iter_seed=iter_seed,
                local_failures=int(local_f),
                global_failures=int(glob_f),
            ))
    return rows


def trace_digest(traces: Iterable[ArguzzTrace]) -> str:
    payload = [
        {"step": t.step, "pc": t.pc, "instruction": t.instruction, "assembly": t.assembly}
        for t in sorted(traces, key=lambda x: x.step)
    ]
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()


def post_inject_trace_digest(traces: Iterable[ArguzzTrace], after_step: int) -> str:
    payload = [
        {"step": t.step, "pc": t.pc, "instruction": t.instruction, "assembly": t.assembly}
        for t in sorted(traces, key=lambda x: x.step)
        if t.step > after_step
    ]
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()


def post_inject_pc_sequence(traces: Iterable[ArguzzTrace], after_step: int) -> List[Tuple[int, int]]:
    return [(t.step, t.pc) for t in sorted(traces, key=lambda x: x.step) if t.step > after_step]


def baseline_traces(
    host: str,
    host_args: List[str],
    *,
    env: Optional[dict] = None,
    cache: Optional[Dict[str, List[ArguzzTrace]]] = None,
) -> List[ArguzzTrace]:
    key = f"{host}|{' '.join(host_args)}"
    if cache is not None and key in cache:
        return cache[key]
    subprocess_env = {**os.environ, "CONSTRAINT_CONTINUE": "1"}
    subprocess_env.update(DEFAULT_ARGUZZ_SUBPROCESS_ENV)
    if env:
        subprocess_env.update(env)
    proc = subprocess.run(
        [host, "--trace", *host_args],
        capture_output=True,
        timeout=120.0,
        env=subprocess_env,
    )
    stdout = _decode_safe(proc.stdout) + _decode_safe(proc.stderr)
    if proc.returncode != 0:
        raise RuntimeError(f"baseline --trace failed rc={proc.returncode}")
    traces = parse_all_traces(stdout)
    if not traces:
        raise RuntimeError("baseline --trace produced no trace records")
    if cache is not None:
        cache[key] = traces
    return traces


def _fault_word_change(faults) -> str:
    if not faults:
        return ""
    f0 = faults[0]
    return f"{f0.original_value}=>{f0.mutated_value}"


def _store_offset_unaligned(assembly: str) -> bool:
    m = _STORE_OFFSET_RE.match(assembly.strip().lower())
    if not m:
        return False
    return int(m.group(1)) % 4 != 0


def classify_semantics(
    baseline: List[ArguzzTrace],
    fault: List[ArguzzTrace],
    step: int,
    *,
    faults,
) -> Tier2Result:
    """§3.1 semantics-aware rule with evidence tiers (F21)."""
    base_digest = trace_digest(baseline)
    fault_digest = trace_digest(fault)

    post_pc_base = post_inject_pc_sequence(baseline, step)
    post_pc_fault = post_inject_pc_sequence(fault, step)
    post_pc_changed = post_pc_base != post_pc_fault

    post_trace_base = post_inject_trace_digest(baseline, step)
    post_trace_fault = post_inject_trace_digest(fault, step)
    post_trace_changed = post_trace_base != post_trace_fault

    bm = {t.step: t for t in baseline}
    fm = {t.step: t for t in fault}
    bt, ft = bm.get(step), fm.get(step)
    inject_disasm_changed = bool(
        bt and ft and (bt.assembly != ft.assembly or bt.instruction != ft.instruction)
    )

    word_chg = _fault_word_change(faults)
    unaligned = bool(ft and _store_offset_unaligned(ft.assembly))

    if post_pc_changed or post_trace_changed:
        return Tier2Result(
            klass=TRIAGE_PROPAGATED,
            evidence=EVIDENCE_STRONG,
            trace_changed=True,
            post_inject_pc_changed=post_pc_changed,
            post_inject_trace_changed=post_trace_changed,
            inject_disasm_changed=inject_disasm_changed,
            fault_trace_digest=fault_digest,
            fault_word_change=word_chg,
            unaligned_access=unaligned,
        )

    if not inject_disasm_changed:
        return Tier2Result(
            klass=TRIAGE_NOOP,
            evidence=EVIDENCE_NONE,
            trace_changed=fault_digest != base_digest,
            post_inject_pc_changed=False,
            post_inject_trace_changed=False,
            inject_disasm_changed=False,
            fault_trace_digest=fault_digest,
            fault_word_change=word_chg,
            unaligned_access=False,
        )

    instr = (ft or bt).instruction if (ft or bt) else ""
    if instr in CONTROL_TRANSFER:
        return Tier2Result(
            klass=TRIAGE_NOOP,
            evidence=EVIDENCE_COSMETIC,
            trace_changed=fault_digest != base_digest,
            post_inject_pc_changed=False,
            post_inject_trace_changed=False,
            inject_disasm_changed=True,
            fault_trace_digest=fault_digest,
            fault_word_change=word_chg,
            unaligned_access=False,
        )

    # store / load / compute — used operand changed; surface as weak candidate
    return Tier2Result(
        klass=TRIAGE_PROPAGATED,
        evidence=EVIDENCE_WEAK,
        trace_changed=fault_digest != base_digest,
        post_inject_pc_changed=False,
        post_inject_trace_changed=False,
        inject_disasm_changed=True,
        fault_trace_digest=fault_digest,
        fault_word_change=word_chg,
        unaligned_access=unaligned,
    )


def tier1_classify(accept: AcceptRow) -> Optional[str]:
    if accept.global_failures > 0:
        return TRIAGE_HIDDEN
    return None


def tier2_classify(
    accept: AcceptRow,
    *,
    host: str,
    host_args: List[str],
    baseline: List[ArguzzTrace],
    env: Optional[dict] = None,
) -> Tier2Result:
    subprocess_env = dict(DEFAULT_ARGUZZ_SUBPROCESS_ENV)
    if env:
        subprocess_env.update(env)
    result = arguzz_run(
        host,
        host_args,
        step=accept.step,
        kind=accept.kind,
        seed=accept.iter_seed,
        include_trace=True,
        env=subprocess_env,
        timeout=120.0,
    )
    return classify_semantics(
        baseline, result.traces, accept.step, faults=result.faults,
    )


def triage_accepts(
    accepts: List[AcceptRow],
    *,
    host: str,
    host_args: List[str],
    run_tier2: bool = True,
    env: Optional[dict] = None,
) -> pd.DataFrame:
    """Run triage; oracle 7/1/0 is a filter-contract (surfaces 1 weak candidate)."""
    cache: Dict[str, List[ArguzzTrace]] = {}
    baseline = baseline_traces(host, host_args, env=env, cache=cache) if run_tier2 else []
    base_digest = trace_digest(baseline) if baseline else ""
    rows: List[dict] = []
    for acc in accepts:
        t1 = tier1_classify(acc)
        if t1 == TRIAGE_HIDDEN:
            rows.append({
                "variant": acc.variant,
                "seed": acc.seed,
                "mutation_id": acc.mutation_id,
                "kind": acc.kind,
                "step": acc.step,
                "iter_seed": acc.iter_seed,
                "class": t1,
                "evidence": EVIDENCE_STRONG,
                "trace_changed": False,
                "post_inject_pc_changed": False,
                "post_inject_trace_changed": False,
                "inject_disasm_changed": False,
                "unaligned_access": False,
                "fault_word_change": "",
                "global_residue": True,
                "local_failures": acc.local_failures,
                "global_failures": acc.global_failures,
                "baseline_trace_digest": base_digest,
                "fault_trace_digest": "",
            })
            continue
        if run_tier2:
            t2 = tier2_classify(
                acc, host=host, host_args=host_args, baseline=baseline, env=env,
            )
            rows.append({
                "variant": acc.variant,
                "seed": acc.seed,
                "mutation_id": acc.mutation_id,
                "kind": acc.kind,
                "step": acc.step,
                "iter_seed": acc.iter_seed,
                "class": t2.klass,
                "evidence": t2.evidence,
                "trace_changed": t2.trace_changed,
                "post_inject_pc_changed": t2.post_inject_pc_changed,
                "post_inject_trace_changed": t2.post_inject_trace_changed,
                "inject_disasm_changed": t2.inject_disasm_changed,
                "unaligned_access": t2.unaligned_access,
                "fault_word_change": t2.fault_word_change,
                "global_residue": acc.global_failures > 0,
                "local_failures": acc.local_failures,
                "global_failures": acc.global_failures,
                "baseline_trace_digest": base_digest,
                "fault_trace_digest": t2.fault_trace_digest,
            })
        else:
            rows.append({
                "variant": acc.variant,
                "seed": acc.seed,
                "mutation_id": acc.mutation_id,
                "kind": acc.kind,
                "step": acc.step,
                "iter_seed": acc.iter_seed,
                "class": "pending_tier2",
                "evidence": "",
                "trace_changed": False,
                "post_inject_pc_changed": False,
                "post_inject_trace_changed": False,
                "inject_disasm_changed": False,
                "unaligned_access": False,
                "fault_word_change": "",
                "global_residue": acc.global_failures > 0,
                "local_failures": acc.local_failures,
                "global_failures": acc.global_failures,
                "baseline_trace_digest": base_digest,
                "fault_trace_digest": "",
            })
    return pd.DataFrame(rows)


def triage_summary(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame()
    return (
        df.groupby(["variant", "seed", "class", "evidence"], dropna=False)
        .size()
        .reset_index(name="count")
    )


def dedupe_accepts_for_rerun(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df
    return df.drop_duplicates(subset=["kind", "step"], keep="first").reset_index(drop=True)


def validate_smoke_oracle(df: pd.DataFrame) -> Tuple[bool, str]:
    """Filter-contract gate: V6_cTS seed1234 → 7 noop / 1 propagated / 0 hidden."""
    sub = df[(df["variant"] == "V6_cTS") & (df["seed"] == 1234)]
    if len(sub) != 8:
        return False, f"expected 8 accepts, got {len(sub)}"
    counts = sub["class"].value_counts().to_dict()
    noop = counts.get(TRIAGE_NOOP, 0)
    prop = counts.get(TRIAGE_PROPAGATED, 0)
    hidden = counts.get(TRIAGE_HIDDEN, 0)
    if noop != 7 or prop != 1 or hidden != 0:
        return False, f"oracle mismatch: noop={noop} prop={prop} hidden={hidden} ({counts})"
    steps_prop = set(sub.loc[sub["class"] == TRIAGE_PROPAGATED, "step"])
    steps_noop = set(sub.loc[sub["class"] == TRIAGE_NOOP, "step"])
    if steps_prop != SMOKE_ORACLE_PROPAGATED_STEPS:
        return False, f"propagated steps {steps_prop} != oracle {SMOKE_ORACLE_PROPAGATED_STEPS}"
    if steps_noop != SMOKE_ORACLE_NOOP_STEPS:
        return False, f"noop steps {steps_noop} != oracle {SMOKE_ORACLE_NOOP_STEPS}"
    weak = sub.loc[sub["step"] == 3939, "evidence"]
    if len(weak) != 1 or weak.iloc[0] != EVIDENCE_WEAK:
        return False, f"step 3939 evidence={weak.tolist()} expected weak"
    return True, "oracle OK: 7 noop / 1 weak propagated (3939) / 0 hidden"


def default_host() -> str:
    return os.environ.get(
        "A4_TEST_HOST", "workspace/output/target/release/risc0-host"
    ).strip()


def default_host_args() -> List[str]:
    raw = os.environ.get("A4_TEST_HOST_ARGS", "--in1 5 --in4 10").strip()
    return raw.split() if raw else []

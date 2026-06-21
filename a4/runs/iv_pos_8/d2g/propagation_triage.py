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
EVIDENCE_WORD_TRUNCATED = "word_truncated"   # F22/F23: provable full-word same-word no-op
EVIDENCE_IDENTITY = "identity"               # F24: fault produced no value change (X==Y)
EVIDENCE_CF_INERT = "cf_inert"               # F27: pure-control-flow kind, post-inject PC stream identical
EVIDENCE_NONE = ""

# Filter-contract oracle (V6_cTS seed1234 N=100): 8 noop / 0 propagated / 0 hidden (F22/F24).
# All 8 smoke accepts are INSTR_WORD_MOD (provably inert): 5 byte-identical disasm, 2
# not-taken-branch target (cosmetic), 1 full-word store within-word (3939, word_truncated).
# NOTE: the smoke is ALL INSTR_WORD_MOD, so the value-mutating-kind path (F24) is NOT
# exercised here — see test_propagation_triage_unit.py for that coverage.
SMOKE_ORACLE_NOOP_STEPS = frozenset({174, 524, 618, 2726, 1648, 3931, 3961, 3939})
SMOKE_ORACLE_PROPAGATED_STEPS = frozenset()

CONTROL_TRANSFER = frozenset({
    "Beq", "Bne", "Blt", "Bge", "Bltu", "BgeU", "Jal", "JalR",
})
LOAD_STORE = frozenset({
    "Lw", "Sw", "Lb", "Sb", "Lh", "Sh", "Lbu", "Lhu", "Lwu",
})

# F23 width guard: only FULL-WORD store/load can be a `word_truncated` no-op (low 2 bits
# of the address ignored). SUB-WORD ops place data by lane (`shift = 8*(addr&3)`), so a
# within-word offset change is a REAL divergence — never a no-op.
FULL_WORD_MNEMONICS = frozenset({"sw", "lw", "lwu"})
SUB_WORD_MNEMONICS = frozenset({"sb", "sh", "lb", "lbu", "lh", "lhu"})

# F24: kinds whose <fault> tag exposes a GENUINE (original => mutated) value pair, so an
# X==Y identity test is meaningful. The other kinds do NOT (verified in arguzz_parser.py):
#   BR_NEG_COND -> "cond:true => cond:false" (bool; parser yields info_type='unknown' 0=>0)
#   *_REG_MOD   -> "<reg> = <val>"          (parser hardcodes original_value=0)
#   *_MEM_MOD   -> "MEM[addr] = <val>"      (parser stores ADDR as original_value)
# For those, "X==Y" is spurious/uncomputable -> must NEVER be called identity; fail-safe weak.
_GENUINE_VALUE_PAIR_INFO = frozenset({"word", "out", "data", "pc"})

# F27: kinds whose ONLY committed effect is the PC stream, AND whose inertness is independently
# CIRCUIT-AUDITED. Currently POST_EXEC_PC_MOD only:
#   POST_EXEC_PC_MOD -> ctx.set_pc only (rv32im.rs:688); the executed instruction already ran.
#   The circuit has NO PC-provenance constraint (INV1 §2c, mem.zir:59-90): it constrains the
#   RESULTING pc sequence, not who set it. So if the post-inject pc+trace are byte-identical to
#   baseline (STRONG already ruled out divergence), the mutation produced identical constraints
#   => PROVABLY inert. INV2 confirms 30/30 accepts were pc+4 with empty semantic diff.
# DELIBERATELY EXCLUDED (kept at the `weak` fail-safe until audited / by design):
#   BR_NEG_COND      -> also PC-only at runtime (rv32im.rs:757, rd=0 as any branch), BUT it flips
#     the branch CONDITION, which the circuit DOES verify; its no-divergence inertness (degenerate
#     target==pc+4) is reasoned, NOT audited like POST_EXEC_PC_MOD. 0 accepts in prod -> 0 cost to
#     keep conservative. Revisit (audit + add) only if it starts accepting. (See F27 flag.)
#   PRE_EXEC_PC_MOD  -> changes the CURRENT fetch, not just the post-inject stream; 0 accepts.
_CONTROL_FLOW_ONLY_KINDS = frozenset({"POST_EXEC_PC_MOD"})

# F24 sub-ranking: value-mutating kinds where a circuit constraint SHOULD reject the mutated
# value if it reaches the constrained column (ALU out / memory-read / memory permutation).
# An ACCEPT here is either inert (value unused) or a soundness gap — surface above generic.
CONSTRAINT_SHOULD_FIRE_KINDS = frozenset({
    "COMP_OUT_MOD", "LOAD_VAL_MOD", "PRE_EXEC_MEM_MOD", "POST_EXEC_MEM_MOD",
})

_STORE_OFFSET_RE = re.compile(r"^[slb][bh]?w?\s+\w+,\s*(-?\d+)\(")
_MEM_OPERAND_RE = re.compile(
    r"^(?P<mn>sb|sh|sw|lbu|lhu|lwu|lb|lh|lw)\s+\w+,\s*(?P<off>-?\d+)\((?P<base>\w+)\)"
)


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


def _parse_mem_operand(assembly: str):
    """Return (mnemonic, offset, base_reg) for a store/load assembly, else None."""
    if not assembly:
        return None
    m = _MEM_OPERAND_RE.match(assembly.strip().lower())
    if not m:
        return None
    return m.group("mn"), int(m.group("off")), m.group("base")


def _fault_is_identity(faults) -> bool:
    """True ONLY when the <fault> tag exposes a genuine original==mutated pair (F24).

    Guards against the spurious 0=>0 the parser yields for BR_NEG_COND ('unknown'),
    *_REG_MOD (original hardcoded 0) and *_MEM_MOD (original = addr) — for those the
    identity test is meaningless and must fall through to the weak fail-safe.
    """
    if not faults:
        return False
    f0 = faults[0]
    if getattr(f0, "info_type", "") not in _GENUINE_VALUE_PAIR_INFO:
        return False
    return f0.original_value == f0.mutated_value


def classify_semantics(
    baseline: List[ArguzzTrace],
    fault: List[ArguzzTrace],
    step: int,
    *,
    faults,
    kind: str = "",
) -> Tier2Result:
    """§3.1 fault-value-aware + kind-aware rule with evidence tiers (F21/F22/F23/F24/F25/F27).

    Precedence (each step is provable-inert OR a fail-safe surface):
      1. strong   — observed downstream divergence (post-inject PC seq / trace hash).
      2. identity — genuine value-pair fault with X==Y (no actual change).
      2b. cf_inert (F27) — pure-control-flow kind (POST_EXEC_PC_MOD / BR_NEG_COND) whose ONLY
         committed effect is the PC stream, with the post-inject pc+trace byte-identical AND a
         non-empty post-inject window -> provably inert (no PC-provenance constraint, INV1 §2c).
      3. INSTR_WORD_MOD (the only disasm-bearing kind) — F23 width-aware store/load:
         byte-identical -> noop; not-taken branch target -> cosmetic; full-word within-word
         store/load (aligned base, b_off%4==0, F25) -> word_truncated; sub-word / cross-word /
         unaligned-base / other -> weak.
      4. everything else (value-mutating kinds, X!=Y or non-genuine pair) -> weak.
    The cardinal rule: anything not PROVABLY inert is surfaced as weak — a no-op is cheap
    to discard in D3; dropping one real candidate could bury a soundness bug.
    """
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

    def _result(klass: str, evidence: str) -> Tier2Result:
        return Tier2Result(
            klass=klass,
            evidence=evidence,
            trace_changed=fault_digest != base_digest,
            post_inject_pc_changed=post_pc_changed,
            post_inject_trace_changed=post_trace_changed,
            inject_disasm_changed=inject_disasm_changed,
            fault_trace_digest=fault_digest,
            fault_word_change=word_chg,
            unaligned_access=unaligned,
        )

    # 1. STRONG — observed downstream divergence (control flow OR instruction stream).
    if post_pc_changed or post_trace_changed:
        return _result(TRIAGE_PROPAGATED, EVIDENCE_STRONG)

    # 2. IDENTITY — the fault produced no actual value change (genuine value-pair kinds only).
    if _fault_is_identity(faults):
        return _result(TRIAGE_NOOP, EVIDENCE_IDENTITY)

    # 2b. CONTROL-FLOW-INERT (F27) — POST_EXEC_PC_MOD mutates ONLY the PC stream (no register/
    # memory/witness state). The circuit has no PC-provenance constraint (INV1 §2c), so once STRONG
    # (rule 1) confirmed the post-inject pc+trace are byte-identical, the mutation produced identical
    # constraints => provably inert (the +4-on-sequential case overwrites the PC with the value the
    # executor already committed; INV2: 30/30 accepts = pc+4, empty semantic diff).
    # GUARD: require a NON-EMPTY post-inject window (>=1 confirmed-convergent step) so a last-step
    # mutation — whose only effect would be the final committed pc, invisible to the step trace —
    # is NOT silently no-op'd but falls to the `weak` fail-safe below.
    if kind in _CONTROL_FLOW_ONLY_KINDS and post_pc_base:
        return _result(TRIAGE_NOOP, EVIDENCE_CF_INERT)

    # 3. INSTR_WORD_MOD — the only kind that mutates the instruction word (disasm-bearing).
    if kind == "INSTR_WORD_MOD" or (not kind and inject_disasm_changed):
        if not inject_disasm_changed:
            # word changed but disassembles identically -> provably inert encoding change.
            return _result(TRIAGE_NOOP, EVIDENCE_NONE)
        instr = (ft or bt).instruction if (ft or bt) else ""
        if instr in CONTROL_TRANSFER:
            # branch/jump target on a not-taken branch (PC unchanged) -> provably inert.
            return _result(TRIAGE_NOOP, EVIDENCE_COSMETIC)
        b_op = _parse_mem_operand(bt.assembly) if bt else None
        f_op = _parse_mem_operand(ft.assembly) if ft else None
        if b_op and f_op:
            b_mn, b_off, b_base = b_op
            f_mn, f_off, f_base = f_op
            # word_truncated no-op ONLY for full-word ops, same op + base, same effective
            # word (off>>2). F25: also require b_off % 4 == 0. A baseline full-word store/load
            # did not trap, so rs1+b_off ≡ 0 (mod 4); hence b_off % 4 == 0 ⟺ rs1 word-aligned,
            # computable from the disasm alone (no rs1 needed). Only an aligned base makes
            # (off>>2) equality equivalent to same-effective-word; an unaligned base can carry
            # into the next word, so without this guard a cross-word full-word access is falsely
            # no-op'd (the exact hiding class). 3939 has b_off=4 (4%4==0) — unchanged.
            if (
                b_mn == f_mn
                and b_mn in FULL_WORD_MNEMONICS
                and b_base == f_base
                and b_off % 4 == 0
                and (b_off >> 2) == (f_off >> 2)
            ):
                return _result(TRIAGE_NOOP, EVIDENCE_WORD_TRUNCATED)
            # sub-word lane change / cross-word / op or base change -> surface (F23).
            return _result(TRIAGE_PROPAGATED, EVIDENCE_WEAK)
        # compute / non-parseable mem operand / other disasm change -> surface.
        return _result(TRIAGE_PROPAGATED, EVIDENCE_WEAK)

    # 4. Value-mutating kinds (no disasm change, X!=Y or non-genuine pair) -> fail-safe surface.
    return _result(TRIAGE_PROPAGATED, EVIDENCE_WEAK)


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
        baseline, result.traces, accept.step, faults=result.faults, kind=accept.kind,
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
                "constraint_should_fire": acc.kind in CONSTRAINT_SHOULD_FIRE_KINDS,
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
                "constraint_should_fire": acc.kind in CONSTRAINT_SHOULD_FIRE_KINDS,
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
                "constraint_should_fire": acc.kind in CONSTRAINT_SHOULD_FIRE_KINDS,
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
    """Kind-aware dedup for tier-2 rerun manifests (ISS-4).

    INSTR_WORD_MOD: one rerun per (variant, kind, step) — within each group every
    accept shares the same fault word (prod DB verified; classification is invariant).
    POST_EXEC_PC_MOD: keep every (variant, kind, step, iter_seed) — DB orig/mut are
    degenerate and random_pc is iter_seed-dependent, so same-step siblings must not
    collapse.
    """
    if df.empty:
        return df
    iwm = df[df["kind"] == "INSTR_WORD_MOD"].drop_duplicates(
        subset=["variant", "kind", "step"], keep="first",
    )
    pepc = df[df["kind"] == "POST_EXEC_PC_MOD"].drop_duplicates(
        subset=["variant", "kind", "step", "iter_seed"], keep="first",
    )
    other = df[~df["kind"].isin({"INSTR_WORD_MOD", "POST_EXEC_PC_MOD"})]
    if not other.empty:
        other = other.drop_duplicates(
            subset=["variant", "kind", "step", "iter_seed"], keep="first",
        )
    return pd.concat([iwm, pepc, other], ignore_index=True).reset_index(drop=True)


def validate_smoke_oracle(df: pd.DataFrame) -> Tuple[bool, str]:
    """Filter-contract gate (F22/F24): V6_cTS seed1234 → 8 noop / 0 propagated / 0 hidden."""
    sub = df[(df["variant"] == "V6_cTS") & (df["seed"] == 1234)]
    if len(sub) != 8:
        return False, f"expected 8 accepts, got {len(sub)}"
    counts = sub["class"].value_counts().to_dict()
    noop = counts.get(TRIAGE_NOOP, 0)
    prop = counts.get(TRIAGE_PROPAGATED, 0)
    hidden = counts.get(TRIAGE_HIDDEN, 0)
    if noop != 8 or prop != 0 or hidden != 0:
        return False, f"oracle mismatch: noop={noop} prop={prop} hidden={hidden} ({counts})"
    steps_noop = set(sub.loc[sub["class"] == TRIAGE_NOOP, "step"])
    if steps_noop != SMOKE_ORACLE_NOOP_STEPS:
        return False, f"noop steps {steps_noop} != oracle {SMOKE_ORACLE_NOOP_STEPS}"
    wt = sub.loc[sub["step"] == 3939, "evidence"]
    if len(wt) != 1 or wt.iloc[0] != EVIDENCE_WORD_TRUNCATED:
        return False, f"step 3939 evidence={wt.tolist()} expected word_truncated"
    return True, "oracle OK (F22/F24): 8 noop / 0 propagated (3939=word_truncated) / 0 hidden"


def default_host() -> str:
    return os.environ.get(
        "A4_TEST_HOST", "workspace/output/target/release/risc0-host"
    ).strip()


def default_host_args() -> List[str]:
    raw = os.environ.get("A4_TEST_HOST_ARGS", "--in1 5 --in4 10").strip()
    return raw.split() if raw else []

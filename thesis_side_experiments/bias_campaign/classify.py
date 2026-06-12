"""Fuzzer-agnostic outcome classifier (PLAN.md §2, C1 §0.1)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from a4.core.constraint_parser import parse_all_constraint_failures
from a4.core.touch_coverage import parse_family_residues, parse_global_residue
from a4.common.trace_parser import ArguzzFault, parse_all_faults

VERIFIER_SUCCESS_RE = re.compile(
    r'<record>\{"context":"Verifier", "status":"success"'
)
PANIC_RE = re.compile(r"panicked at ([^\n]+?:\d+)")

PROVER_CRASH_MARKERS = (
    "preflight.rs",
    "/witgen/",
    "risc0/circuit",
    "risc0/zkp",
)


@dataclass
class RunOutcome:
    outcome_class: str
    injected: bool
    fault: Optional[Dict[str, Any]]
    failures: List[Any]
    family_residues: Optional[List[dict]]
    global_residue: Optional[dict]
    global_nonzero: bool
    verifier_success: bool
    panic_loc: Optional[str]
    preflight_crash: bool
    prover_crash: bool
    host_panic: bool
    soundness_escape: bool
    combined_output: str = field(repr=False, default="")


def is_host_harness_panic(panic_loc: Optional[str]) -> bool:
    return panic_loc is not None and "main.rs" in panic_loc


def is_prover_crash(panic_loc: Optional[str]) -> bool:
    if not panic_loc or is_host_harness_panic(panic_loc):
        return False
    return any(m in panic_loc for m in PROVER_CRASH_MARKERS)


def is_preflight_crash(panic_loc: Optional[str]) -> bool:
    return panic_loc is not None and "preflight.rs" in panic_loc


def _fault_at_step(output: str, target_step: Optional[int]) -> Optional[ArguzzFault]:
    if target_step is None:
        return None
    for fault in parse_all_faults(output):
        if fault.step == target_step:
            return fault
    return None


def _fault_dict(fault: ArguzzFault) -> Dict[str, Any]:
    d: Dict[str, Any] = {
        "kind": fault.kind,
        "step": fault.step,
        "pc": fault.pc,
        "value": fault.mutated_value,
    }
    if fault.target_register:
        d["register"] = fault.target_register
    return d


def classify_run(
    combined_output: str,
    target_step: Optional[int] = None,
    *,
    injected_override: Optional[bool] = None,
) -> RunOutcome:
    """Classify a host run from raw stdout+stderr."""
    failures = parse_all_constraint_failures(combined_output)
    family = parse_family_residues(combined_output)
    global_res = parse_global_residue(combined_output)
    global_nonzero = bool(global_res and global_res.get("nonzero"))
    if not global_nonzero and family:
        global_nonzero = any(f.get("nonzero") for f in family)

    verifier_success = VERIFIER_SUCCESS_RE.search(combined_output) is not None
    pm = PANIC_RE.search(combined_output)
    panic_loc = pm.group(1) if pm else None
    preflight_crash = is_preflight_crash(panic_loc)
    prover_crash = is_prover_crash(panic_loc)
    host_panic = is_host_harness_panic(panic_loc)

    fault = _fault_at_step(combined_output, target_step)
    injected = injected_override if injected_override is not None else (fault is not None)

    local_fails = [f for f in failures if f.phase == "local"]
    soundness_escape = bool(injected and verifier_success)

    # C1 §0.1 precedence
    if preflight_crash:
        outcome = "PREFLIGHT_CRASH"
    elif prover_crash and len(failures) == 0:
        outcome = "OTHER_CRASH"
    elif len(failures) >= 1:
        outcome = "CONSTRAINT_REJECT"
    elif injected and verifier_success:
        outcome = "ACCEPTED"
    elif len(local_fails) == 0 and global_nonzero:
        outcome = "GLOBAL_REJECT"
    elif not verifier_success and len(failures) == 0 and not prover_crash:
        outcome = "VERIFY_REJECT"
    elif target_step is not None and not injected:
        outcome = "NO_INJECTION"
    else:
        outcome = "VALID_NO_SIGNAL"

    return RunOutcome(
        outcome_class=outcome,
        injected=injected,
        fault=_fault_dict(fault) if fault else None,
        failures=failures,
        family_residues=family,
        global_residue=global_res,
        global_nonzero=global_nonzero,
        verifier_success=verifier_success,
        panic_loc=panic_loc,
        preflight_crash=preflight_crash,
        prover_crash=prover_crash,
        host_panic=host_panic,
        soundness_escape=soundness_escape,
        combined_output=combined_output,
    )

"""
Additive reward function for cloud1 IV.POS.7 (ProG_Report_2.md §6.1, §8).

Pure functions only — no fuzzer wiring (Phase 6). Lives alongside legacy
`coverage_state.compute_reward`; does not replace it.

Components:
  L_new, F_new, G_new, S_new — marginal discovery counts (§6.1)
  crash, repeat — penalties (§8)

Counterfactual variants for `reward_counterfactuals` table (§12) are in
`compute_counterfactuals`.
"""

from __future__ import annotations

import math
import re
from typing import Any, Dict, Set, Tuple, Union

from a4.standalone.compressed_global_extractor import extract_compressed_global_contexts
from a4.standalone.coverage_state import _is_crash
from a4.standalone.semantic_zones import major_to_opcode_class
from a4.standalone.structural_cells import StructuralCell, make_structural_cell
from a4.standalone.compressed_global_extractor import txn_role_for_kind

RewardComponents = Dict[str, Union[int, bool]]
CounterfactualRewards = Dict[str, Union[int, float]]

# D-A: primary family parse — substring between '@' and '.zir'
_FAMILY_AT_ZIR_RE = re.compile(r"@([^@]+?)\.zir")


def sat(x: float, tau: float) -> float:
    """Saturating transform per Pro §8: sat(x, tau) = 1 - exp(-x/tau)."""
    if tau <= 0:
        return 0.0
    return 1.0 - math.exp(-x / tau)


def compute_reward_v2(
    l_new: int,
    f_new: int,
    g_new: int,
    s_new: int,
    crash: bool,
    repeat: int,
) -> float:
    """Pro §8 verbatim additive reward."""
    return (
        1.00 * sat(float(l_new), 1.0)
        + 0.30 * sat(float(f_new), 1.0)
        + 0.25 * sat(float(g_new), 3.0)
        + 0.15 * sat(float(s_new), 2.0)
        - 0.50 * (1.0 if crash else 0.0)
        - 0.05 * sat(float(repeat), 5.0)
    )


def compute_bandit_success(l_new: int, g_new: int, s_new: int) -> int:
    """Pro §8 Bernoulli success indicator for Thompson sampling."""
    return 1 if (l_new + g_new + s_new) > 0 else 0


def extract_constraint_family(constraint_loc: str) -> str:
    """Map constraint_loc → family label for F_new (D-A).

    Primary: substring between '@' and '.zir'.
    Fallback: name prefix before '@', else stripped full string.
    """
    if not constraint_loc:
        return "unknown"
    m = _FAMILY_AT_ZIR_RE.search(constraint_loc)
    if m:
        return m.group(1)
    if "@" in constraint_loc:
        return constraint_loc.split("@", 1)[0]
    return constraint_loc.strip()


def make_local_v2_ctx_key(constraint_loc: str, major: int, minor: int) -> str:
    """Stable key matching `local_coverage_v2.ctx_key` in coverage_db."""
    return f"{constraint_loc}|{major}|{minor}"


def _failure_local_contexts(exec_result: Any) -> Set[Tuple[str, int, int]]:
    """Distinct (constraint_loc, major, minor) from exec_result.failures."""
    failures = getattr(exec_result, "failures", None) or []
    contexts: Set[Tuple[str, int, int]] = set()
    for f in failures:
        if hasattr(f, "constraint_loc"):
            loc = f.constraint_loc()
            major = f.major
            minor = f.minor
        elif isinstance(f, dict):
            loc = f.get("constraint_loc", "")
            major = int(f.get("major", 0))
            minor = int(f.get("minor", 0))
        else:
            continue
        contexts.add((loc, major, minor))
    return contexts


def _is_crash_or_missing_telemetry(exec_result: Any) -> bool:
    exit_code = int(getattr(exec_result, "exit_code", 0))
    touch_bitmap = getattr(exec_result, "touch_bitmap", None)
    return _is_crash(exit_code) or touch_bitmap is None


def _build_structural_cell(
    mutation_kind: str,
    mutation_zone: str,
    mutation_major: int,
    exec_result: Any,
) -> StructuralCell:
    config = getattr(exec_result, "config", None) or {}
    sub_strategy = None
    for key in ("funct3", "byte_lane", "value_class"):
        if key in config and config[key] is not None:
            sub_strategy = str(config[key])
            break
    return make_structural_cell(
        kind=mutation_kind,
        semantic_zone=mutation_zone,
        opcode_class=major_to_opcode_class(mutation_major),
        mode=str(config.get("mode", "user")),
        txn_role=txn_role_for_kind(mutation_kind),
        sub_strategy=sub_strategy,
    )


def compute_reward_v2_components(
    exec_result: Any,
    seen_local_v2: Set[Tuple[str, int, int]],
    seen_compressed_global: Set[str],
    seen_structural: Set[StructuralCell],
    mutation_kind: str,
    mutation_zone: str,
    mutation_major: int,
) -> RewardComponents:
    """Extract L_new/F_new/G_new/S_new/crash/repeat for one mutation run.

    Mutates the three ``seen_*`` sets to record first-hits from this run.
    ``seen_local_v2`` keys are ``(constraint_loc, major, minor)`` tuples.
    """
    crash = _is_crash_or_missing_telemetry(exec_result)
    local_contexts = _failure_local_contexts(exec_result)

    # D-C / D-B: set semantics per local context tuple
    l_new = sum(1 for ctx in local_contexts if ctx not in seen_local_v2)
    repeat = sum(1 for ctx in local_contexts if ctx in seen_local_v2)

    seen_families = {extract_constraint_family(loc) for loc, _, _ in seen_local_v2}
    run_families = {extract_constraint_family(loc) for loc, _, _ in local_contexts}
    f_new = sum(1 for fam in run_families if fam not in seen_families)

    compressed_ctxs = extract_compressed_global_contexts(
        getattr(exec_result, "family_residues", None),
        getattr(exec_result, "family_details", None),
        mutation_kind,
        mutation_zone,
        mutation_major,
    )
    g_new = 0
    for ctx in compressed_ctxs:
        ctx_key = ctx.to_json_str()
        if ctx_key not in seen_compressed_global:
            g_new += 1

    cell = _build_structural_cell(
        mutation_kind, mutation_zone, mutation_major, exec_result,
    )
    s_new = 0 if cell in seen_structural else 1

    # Side effects: record this run's discoveries
    seen_local_v2.update(local_contexts)
    for ctx in compressed_ctxs:
        seen_compressed_global.add(ctx.to_json_str())
    seen_structural.add(cell)

    return {
        "l_new": l_new,
        "f_new": f_new,
        "g_new": g_new,
        "s_new": s_new,
        "crash": crash,
        "repeat": repeat,
    }


def _compute_no_qloc_reward(legacy_reward_diag: Dict[str, Any]) -> float:
    """Legacy reward with Q_loc forced to 1.0 (D-D)."""
    mode = legacy_reward_diag.get("mode", "normal")
    if mode == "crash":
        return 0.0
    if mode == "accepted":
        return 1.0
    s_val = float(legacy_reward_diag.get("S", 0.0))
    q_rep = float(legacy_reward_diag.get("Q_rep", 1.0))
    q_glob = float(legacy_reward_diag.get("Q_glob", 1.0))
    return min(1.0, q_rep * q_glob * s_val)


def compute_counterfactuals(
    components: RewardComponents,
    legacy_reward_diag: Dict[str, Any],
) -> CounterfactualRewards:
    """Five reward variants per Pro §12 / reward_counterfactuals schema."""
    l_new = int(components["l_new"])
    f_new = int(components["f_new"])
    g_new = int(components["g_new"])
    s_new = int(components["s_new"])
    crash = bool(components["crash"])
    repeat = int(components["repeat"])

    return {
        "current_reward": compute_reward_v2(l_new, f_new, g_new, s_new, crash, repeat),
        "no_qloc_reward": _compute_no_qloc_reward(legacy_reward_diag),
        "fnew_only_reward": 0.30 * sat(float(f_new), 1.0),
        "discovery_binary_reward": compute_bandit_success(l_new, g_new, s_new),
        "compressed_global_reward": 0.25 * sat(float(g_new), 3.0),
    }


__all__ = [
    "sat",
    "compute_reward_v2",
    "compute_bandit_success",
    "extract_constraint_family",
    "make_local_v2_ctx_key",
    "compute_reward_v2_components",
    "compute_counterfactuals",
]

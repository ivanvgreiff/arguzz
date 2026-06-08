"""
Zone classifier — assigns each user_cycle in an InspectionData trace to one
of the 17 semantic zones from ProG_Report_2.md §7.A.

The classifier is the bridge between RAW inspection data (a list of cycles
each with a `major` and `step`) and the SEMANTIC ARM SPACE used by the
new bandit. It runs ONCE per campaign at setup time and produces:

    Dict[int, str]            step → zone
    Dict[str, List[int]]      zone → list of steps

Both views are needed downstream:
    - SemanticArmUniverse uses the zone-to-steps view to enumerate arms
    - SemanticZoneStepSelector uses both: zone-to-steps to sample, and
      step-to-zone to log the chosen zone

Classification rules (in priority order — earlier rules override later):
    1. step 0                                                → "step0"
    2. step T-1                                              → "last_step"
    3. ECALL adjacency: for each cycle with major == 8,
       step e   →  "pre_ecall"    (the ECALL cycle itself; see note)
       step e+1 →  "post_ecall"   (the cycle after, if not already singleton)
    4. MRET adjacency: NOT YET IMPLEMENTED — major detection ambiguous,
       see "Limitations" below.
    5. Halt adjacency: NOT YET IMPLEMENTED — same reason.
    6. Fallback by major:
       0/1/2 → core_arithmetic
       3     → core_mul
       4     → core_div
       5     → core_memory_load
       6     → core_memory_store
       7     → core_branch
       8     → core_other  (ECALL fallback; should not be reached if rule 3 fired)
       9/10  → core_poseidon
       11    → core_sha
       12+   → core_other

Note on rule 3 (ECALL cycle itself classified as "pre_ecall"):
    Pro §7.A lists pre_ecall and post_ecall as adjacent zones but does not
    specify what zone the ECALL cycle itself goes into. We classify the
    ECALL cycle as pre_ecall because the ECALL setup constraints (e.g.
    ECallHostReadSetup@inst_ecall.zir:70) fire AT the ECALL cycle, and we
    want this cycle to be part of a boundary zone so the constrained
    bandit's boundary-zone floor reaches it.

    Documented as a Pro-silent decision in
    `a4/docs/cloud1/CLOUD1_DECISIONS_FOR_PRO_R2.md` (D13).

Limitations (recorded as future work; will be revisited post-IV.POS.7):
    - MRET cycles: rv32im has no separate "MRET major"; MRET is a subset
      of major=7 (CONTROL0) distinguished by minor/instruction-word bits
      that aren't exposed by InspectionData. Without that info we cannot
      cleanly partition CONTROL0 cycles into branches vs MRET. For
      IV.POS.7, pre_mret / post_mret are LEFT EMPTY for sha2-host; MRET
      cycles fall into core_branch via the major-7 fallback.
    - HALT cycles: same problem. pre_halt / post_halt LEFT EMPTY.
    - This means zoned's "5% init" boundary advantage is not fully
      replicated by cTS_semantic_v2 in IV.POS.7 because we lose MRET/halt
      boundary detection. However, MRET/halt cycles are not implicated
      in IV.POS.5's smoking-gun constraints (those were all step=0), so
      this limitation does not affect the main scientific test. We will
      revisit MRET/halt detection if Pro Round 2 flags it.
"""

from collections import defaultdict
from typing import Dict, List, Tuple

from a4.core.inspection_data import InspectionData
from a4.standalone.semantic_zones import (
    SEMANTIC_ZONES, SINGLETON_ZONES, BOUNDARY_ZONES, major_to_zone,
)


# =============================================================================
# Constants (sourced from inspection_data.py:summary lines 224-228)
# =============================================================================

ECALL_MAJOR = 8       # ECALL0 — every cycle with this major is an ECALL


# =============================================================================
# Classifier
# =============================================================================


def classify_zones(data: InspectionData) -> Dict[int, str]:
    """Return a dict mapping every step in `data` to its semantic zone.

    Steps not present in `data.cycles` are not in the returned dict.
    """
    if not data.cycles or data.total_steps <= 0:
        return {}

    T = data.total_steps
    zones: Dict[int, str] = {}

    # ------------------------------------------------------------------
    # Rule 1 — step 0 takes absolute precedence
    # ------------------------------------------------------------------
    zones[0] = "step0"

    # ------------------------------------------------------------------
    # Rule 2 — last step
    # ------------------------------------------------------------------
    if T - 1 != 0:                       # avoid clobbering step 0 if T == 1
        zones[T - 1] = "last_step"

    # ------------------------------------------------------------------
    # Rule 3 — ECALL adjacency
    # Identify all ECALL cycles (major == ECALL_MAJOR). Classify:
    #     - the ECALL cycle itself  → pre_ecall  (Decision D13)
    #     - the cycle right after   → post_ecall (if it exists and is not
    #                                             already a singleton zone)
    # Earlier-set zones (step0, last_step) are not overwritten.
    # ------------------------------------------------------------------
    for cycle in data.cycles:
        if cycle.major != ECALL_MAJOR:
            continue

        e = cycle.step
        if e not in zones:               # don't override step0 / last_step
            zones[e] = "pre_ecall"
        elif zones[e] not in SINGLETON_ZONES:
            # e is already classified by some earlier ECALL rule; keep it
            pass

        # post_ecall is e + 1 if that cycle exists in this trace and is
        # not a singleton already.
        post = e + 1
        if 0 <= post < T and post not in zones:
            zones[post] = "post_ecall"

    # ------------------------------------------------------------------
    # Rule 4/5 — MRET / halt adjacency: NOT YET IMPLEMENTED
    # See docstring "Limitations" section. For IV.POS.7 sha2-host these
    # zones will be empty, which is consistent with D7 (define all 17;
    # runtime-skip empty zones at the arm-universe layer).
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Rule 6 — Fallback by major for everything not yet classified
    # ------------------------------------------------------------------
    for cycle in data.cycles:
        if cycle.step in zones:
            continue
        zones[cycle.step] = major_to_zone(cycle.major)

    return zones


def zone_to_steps(data: InspectionData) -> Dict[str, List[int]]:
    """Return a dict mapping zone name → sorted list of steps in that zone.

    All 17 zones are present in the output dict; empty zones map to [].
    """
    step_to_zone = classify_zones(data)
    result: Dict[str, List[int]] = {z: [] for z in SEMANTIC_ZONES}
    for step, zone in step_to_zone.items():
        if zone in result:               # defensive: drop unknown zones
            result[zone].append(step)
    for z in result:
        result[z].sort()
    return result


def summarize_zones(data: InspectionData) -> str:
    """Human-readable zone population summary (for logs and sanity checks)."""
    z2s = zone_to_steps(data)
    lines = [
        f"Zone populations (total_steps = {data.total_steps}):",
        "  boundary zones:",
    ]
    for z in sorted(BOUNDARY_ZONES):
        n = len(z2s.get(z, []))
        marker = " (EMPTY — see classifier limitations)" if n == 0 else ""
        lines.append(f"    {z:20} {n:>5}{marker}")
    lines.append("  core zones:")
    core_zones = [z for z in SEMANTIC_ZONES if z not in BOUNDARY_ZONES]
    for z in sorted(core_zones):
        n = len(z2s.get(z, []))
        marker = " (empty for this guest)" if n == 0 else ""
        lines.append(f"    {z:20} {n:>5}{marker}")
    total_classified = sum(len(v) for v in z2s.values())
    lines.append(f"  total classified: {total_classified}")
    return "\n".join(lines)


__all__ = [
    "ECALL_MAJOR",
    "classify_zones",
    "zone_to_steps",
    "summarize_zones",
]

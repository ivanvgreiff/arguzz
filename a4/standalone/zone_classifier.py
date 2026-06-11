"""
Zone classifier — assigns each user_cycle to one of 19 semantic zones.

Precedence (D13, D50, D53, D54):
    1. step0 / last_step (singletons)
    2. pre_ecall (step contains ECALL cycle, major=8)
    3. post_ecall (first user-PC Decode step in [e+1, e+5] per ECALL; D53)
    4. kernel_other (primary Decode cycle at kernel PC; D54)
    5. core_* via major_minor_to_core_zone (D50 splits major=4)
"""

from collections import defaultdict
from typing import Dict, List, Optional

from a4.core.inspection_data import InspectionData
from a4.core.trace_parser import A4CycleInfo
from a4.standalone.semantic_zones import (
    SEMANTIC_ZONES,
    SINGLETON_ZONES,
    BOUNDARY_ZONES,
    major_minor_to_core_zone,
    pc_in_kernel,
    pc_in_user,
)

ECALL_MAJOR = 8


def _primary_decode_cycle(step: int, data: InspectionData) -> Optional[A4CycleInfo]:
    """First Decode cycle (major <= 6) at step."""
    for c in data.cycles:
        if c.step == step and c.major <= 6:
            return c
    return None


def classify_zones(data: InspectionData) -> Dict[int, str]:
    if not data.cycles or data.total_steps <= 0:
        return {}

    T = data.total_steps
    zones: Dict[int, str] = {}

    zones[0] = "step0"
    if T - 1 != 0:
        zones[T - 1] = "last_step"

    for cycle in data.cycles:
        if cycle.major != ECALL_MAJOR:
            continue
        e = cycle.step
        if e not in zones:
            zones[e] = "pre_ecall"

    ecall_steps = sorted({c.step for c in data.cycles if c.major == ECALL_MAJOR})
    for e in ecall_steps:
        for k in range(1, 6):
            post = e + k
            if post >= T:
                break
            if post in zones:
                continue
            prim = _primary_decode_cycle(post, data)
            if prim is not None and pc_in_user(prim.pc):
                zones[post] = "post_ecall"
                break

    all_steps = sorted({c.step for c in data.cycles})
    for step in all_steps:
        if step in zones:
            continue
        prim = _primary_decode_cycle(step, data)
        if prim is not None and pc_in_kernel(prim.pc):
            zones[step] = "kernel_other"

    for step in all_steps:
        if step in zones:
            continue
        prim = _primary_decode_cycle(step, data)
        if prim is not None:
            zones[step] = major_minor_to_core_zone(prim.major, prim.minor)
            continue
        cycle = data.get_cycle(step)
        if cycle is not None and cycle.major != ECALL_MAJOR:
            zones[step] = major_minor_to_core_zone(cycle.major, cycle.minor)

    return zones


def zone_to_steps(data: InspectionData) -> Dict[str, List[int]]:
    step_to_zone = classify_zones(data)
    result: Dict[str, List[int]] = {z: [] for z in SEMANTIC_ZONES}
    for step, zone in step_to_zone.items():
        if zone in result:
            result[zone].append(step)
    for z in result:
        result[z].sort()
    return result


def summarize_zones(data: InspectionData) -> str:
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
    "_primary_decode_cycle",
]

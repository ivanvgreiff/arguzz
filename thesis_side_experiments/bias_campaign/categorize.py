"""Constraint category classifier (L1 / L2 / ACCUM / G). Pure functions."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional, Set


def categorize_failure(loc: str, phase: str) -> str:
    """Classify a single constraint failure into L1, L2, or ACCUM."""
    if phase == "accum":
        return "ACCUM"
    if phase == "local":
        if "mem.zir" in loc:
            return "L2"
        return "L1"
    raise ValueError(f"UNKNOWN failure category for phase={phase!r} loc={loc!r}")


def categorize_failures(failures: Iterable[Any]) -> Dict[str, int]:
    """Count failures by category from ConstraintFailure-like objects."""
    counts = {"L1": 0, "L2": 0, "ACCUM": 0}
    for f in failures:
        cat = categorize_failure(f.loc, f.phase)
        counts[cat] += 1
    return counts


def _context_loc(context_key: str) -> str:
    """Extract loc from 'loc|major|minor' context key."""
    return context_key.rsplit("|", 2)[0]


def categorize_touched(local_verbose: Iterable[str], accum_verbose: Iterable[str]) -> Dict[str, int]:
    """
    Classify touched constraint contexts.

    local_verbose entries are 'loc|major|minor'; ACCUM count = len(accum_verbose).
    """
    counts = {"L1": 0, "L2": 0, "ACCUM": 0}
    for key in local_verbose:
        loc = _context_loc(key)
        if "mem.zir" in loc:
            counts["L2"] += 1
        else:
            counts["L1"] += 1
    counts["ACCUM"] = len(list(accum_verbose))
    return counts


def global_failed(
    family_residues: Optional[List[Mapping[str, Any]]],
    global_residue: Optional[Mapping[str, Any]],
) -> Dict[str, Any]:
    """Return per-family nonzero flags and 'any' for the G category."""
    result: Dict[str, Any] = {
        "memory": False,
        "u16": False,
        "u8": False,
        "cycle": False,
        "any": False,
    }
    if family_residues:
        for fam in family_residues:
            name = fam.get("family")
            if name in result and fam.get("nonzero"):
                result[name] = True
    if global_residue and global_residue.get("nonzero"):
        result["any"] = True
    if any(result[k] for k in ("memory", "u16", "u8", "cycle")):
        result["any"] = True
    return result


# Sanity reference: known L2 mem.zir constraint sites (PLAN / C0_SPEC).
KNOWN_L2_MEM_LOCS: Set[str] = {
    "IsRead@mem.zir:79",
    "IsRead@mem.zir:80",
    "MemoryWrite@mem.zir:99",
    "MemoryWrite@mem.zir:100",
    "IsCycle@mem.zir:61",
    "IsCycle@mem.zir:62",
}


def mem_zir_loc_matches(loc: str, short_name: str) -> bool:
    """True if loc refers to the given mem.zir line shorthand (e.g. IsRead@mem.zir:79)."""
    if "@" not in short_name:
        return short_name in loc
    component, rest = short_name.split("@", 1)
    line = rest.split(":", 1)[1]
    if component not in loc:
        return False
    # Host emits both `mem.zir:79` and `mem.zir :79` in loc strings.
    return f"mem.zir:{line}" in loc or f"mem.zir :{line}" in loc

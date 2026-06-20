"""Canonical IV.POS.8 checkpoint variant registry (D2.D).

Descriptive reference for dispatch, smoke, manifests, and D2.G labeling —
not a parallel execution path.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class VariantSpec:
    name: str
    launcher: str  # "cli" | "driver"
    selector: Optional[str]
    driver_module: Optional[str]
    bernoulli_floor: bool
    applied_accounting: bool
    surface: str  # "a4" | "arguzz" | "hybrid"
    archive_reuse: bool
    notes: str


CANONICAL_VARIANTS: dict[str, VariantSpec] = {
    "V5_control": VariantSpec(
        name="V5_control",
        launcher="cli",
        selector="cTS_semantic_v2",
        driver_module=None,
        bernoulli_floor=False,
        applied_accounting=False,
        surface="a4",
        archive_reuse=True,
        notes="checkpoint reuses R2 archive; cTS_semantic_v2 = fresh-equivalent",
    ),
    "V6_uniform": VariantSpec(
        name="V6_uniform",
        launcher="driver",
        selector=None,
        driver_module="a4.standalone.v6_uniform_driver",
        bernoulli_floor=False,
        applied_accounting=False,
        surface="arguzz",
        archive_reuse=False,
        notes="round-robin ArguzzScheduler, no bandit",
    ),
    "V6_cTS": VariantSpec(
        name="V6_cTS",
        launcher="cli",
        selector="v6_cTS",
        driver_module=None,
        bernoulli_floor=True,
        applied_accounting=True,
        surface="arguzz",
        archive_reuse=False,
        notes="all 11 Arguzz kinds, cTS, Bernoulli",
    ),
    "Hybrid_cTS": VariantSpec(
        name="Hybrid_cTS",
        launcher="cli",
        selector="hybrid_cTS",
        driver_module=None,
        bernoulli_floor=True,
        applied_accounting=True,
        surface="hybrid",
        archive_reuse=False,
        notes="4 selected Arguzz + A4 kinds, cTS, Bernoulli",
    ),
}


def resolve_variant(name: str) -> VariantSpec:
    try:
        return CANONICAL_VARIANTS[name]
    except KeyError as exc:
        known = ", ".join(sorted(CANONICAL_VARIANTS))
        raise ValueError(f"unknown variant {name!r}; known: {known}") from exc


def variant_launch_command(
    name: str,
    *,
    host: str,
    db: str,
    seed: int,
    num: int,
    host_args: Optional[List[str]] = None,
) -> List[str]:
    """Reference launch argv for smoke / POS documentation."""
    spec = resolve_variant(name)
    args = list(host_args or [])
    if spec.launcher == "driver":
        if spec.driver_module is None:
            raise ValueError(f"variant {name} has no driver_module")
        cmd = [
            "python", "-m", spec.driver_module,
            "--host", host,
            "--db", db,
            "--seed", str(seed),
            "--num", str(num),
        ]
        if args:
            cmd.extend(["--", *args])
        return cmd
    if spec.selector is None:
        raise ValueError(f"variant {name} has no cli selector")
    cmd = [
        "python", "-m", "a4.standalone.cli", "fuzz",
        "--host", host,
        "--db", db,
        "--seed", str(seed),
        "--num", str(num),
        "--selector", spec.selector,
    ]
    if args:
        cmd.extend(["--", *args])
    return cmd

"""Witgen ``user_cycle`` ↔ executor ``current_step`` map for the Arguzz inject path.

The bandit defines semantic zones and picks steps in **witgen ``user_cycle``** space,
but Arguzz's ``--inject-step`` consumes **executor ``current_step``** space. The two
counters diverge by the running count of MACHINE/HOST ecalls (and exception traps):
``current_step`` bumps for every executed instruction, while ``user_cycle`` bumps only
for instructions whose dispatch returns ``Some`` — and ``machine_ecall`` returns
``Ok(false)`` (host read/write/poseidon2/sha2/bigint/terminate), so host ecalls are
invisible to ``user_cycle``.  See ``a4/docs/cloud3/arguzz_step_domain_fix/`` for the
full derivation (source: ``execute/rv32im.rs:670,716``; ``execute/r0vm.rs:352,364,633``;
``prove/witgen/preflight.rs:555``).

This module builds the bijection on *real guest instructions* (everything except
host ecalls / traps), so the Arguzz injector can be handed the correct executor step.
It self-validates hard: the count of surviving executor steps MUST equal the number of
witgen ``user_cycle`` values, or construction raises.  The map is deterministic for a
fixed ``(guest, input)`` and is rebuilt per guest at bootstrap.

NOTE: this is HARNESS code (a4/standalone).  It does not touch Arguzz's mutation-value
logic or the risc0 binary; it only computes which executor step corresponds to the
witgen step the bandit already chose.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from a4.arguzz_dependent.arguzz_parser import ArguzzTrace, parse_all_traces
from a4.standalone.semantic_zones import pc_in_kernel

# An ecall instruction executed at a kernel PC is a MACHINE/host ecall (machine_ecall →
# Ok(false) → no user_cycle bump).  An ecall at a user PC is a user_ecall (Ok(true) →
# bumps).  `mret` (Ok(true)) and all normal instructions bump too, so only kernel-PC
# ecalls (and traps, absent from a clean baseline) are skipped.
_ECALL_MNEMONICS = {"Eany", "eany", "ecall", "EAny"}


class StepDomainMapError(RuntimeError):
    """Raised when the user_cycle↔current_step map cannot be built/validated."""


@dataclass
class StepDomainMap:
    """Bijection between witgen ``user_cycle`` and executor ``current_step`` on real
    guest instructions, plus the executor pc/mnemonic at each ``current_step`` (used by
    the per-pull verification to confirm the binary mutated the intended instruction)."""

    to_exec: Dict[int, int] = field(default_factory=dict)   # user_cycle -> current_step
    to_user: Dict[int, int] = field(default_factory=dict)   # current_step -> user_cycle
    exec_pc: Dict[int, int] = field(default_factory=dict)    # current_step -> pc
    exec_instr: Dict[int, str] = field(default_factory=dict)  # current_step -> mnemonic
    n_user_cycles: int = 0
    n_host_ecalls: int = 0

    def exec_step(self, user_cycle: int) -> int:
        """Translate a witgen ``user_cycle`` (an arm's step) to the executor
        ``current_step`` to pass as ``--inject-step``.  Raises if unmapped."""
        try:
            return self.to_exec[user_cycle]
        except KeyError:
            raise StepDomainMapError(
                f"user_cycle {user_cycle} has no executor current_step in the "
                f"step-domain map (n_user_cycles={self.n_user_cycles})"
            )

    def expected_pc(self, user_cycle: int) -> int:
        """The executor pc the injector should report mutating for this user_cycle."""
        return self.exec_pc[self.exec_step(user_cycle)]

    def user_cycle_of(self, exec_step: int):
        """The witgen ``user_cycle`` for an executor ``current_step`` (None for a host
        ecall — those have no witgen-visible instruction)."""
        return self.to_user.get(exec_step)

    def exec_step_zone_map(
        self,
        witgen_step_to_zone: dict,
        *,
        host_ecall_zone: str = "pre_ecall",
        default_zone: str = "core_other",
    ) -> dict:
        """Build the executor-keyed zone map the Arguzz surface needs: for each executor
        ``current_step E``, the CORRECT zone = ``witgen_step_to_zone[to_user[E]]`` (the
        witgen zone of the instruction actually at ``E``).  This is the fix for the
        mis-index ``step_to_zone[E]`` (E read as a ``user_cycle``).  Host-ecall executor
        steps (no ``to_user`` entry) get ``host_ecall_zone``."""
        out = {}
        for e in self.exec_pc:
            u = self.to_user.get(e)
            out[e] = (
                witgen_step_to_zone.get(u, default_zone)
                if u is not None
                else host_ecall_zone
            )
        return out


def _first_pass(traces: List[ArguzzTrace]) -> List[ArguzzTrace]:
    """``--trace`` is emitted twice (execute pass + witgen-preflight pass), each a
    monotonic ``current_step`` sequence.  Keep only the first contiguous pass."""
    out: List[ArguzzTrace] = []
    last = -1
    for tr in traces:
        if out and tr.step <= last:
            break  # second pass restarted at a lower step
        out.append(tr)
        last = tr.step
    return out


def build_step_domain_map(
    traces: List[ArguzzTrace],
    total_user_cycles: int,
    *,
    compute_user_cycles: Optional[set] = None,
) -> StepDomainMap:
    """Build + validate the map from a parsed executor ``--trace`` and the witgen
    ``user_cycle`` count (``InspectionData.total_steps``).

    Algorithm (see module docstring): order executor steps; drop host ecalls
    (ecall mnemonic at a kernel pc); the survivors are exactly the witgen-visible
    instructions, in order, so survivor *k* is ``user_cycle k``.

    Validation: the ``R`` survivors map onto ``user_cycle`` ``0..R-1``.  The witgen
    ``total_user_cycles`` can exceed ``R`` by the *trailing phantom* ``user_cycle``
    values — the terminate/suspend/Poseidon special cycles carry the final, already
    incremented ``user_cycle`` with no instruction behind it (verified: they have no
    ``major<=6`` Decode).  We therefore require ``R <= total`` and, if
    ``compute_user_cycles`` is supplied (the set of ``user_cycle`` values that have a
    real ``major<=6`` Decode), that the gap ``[R, total)`` contains **no** compute
    Decode — which would mean we under-counted real instructions.  This catches a
    wrong host-ecall accounting without falsely tripping on trailing phantoms.
    """
    if not traces:
        raise StepDomainMapError("no executor --trace lines to build map from")

    traces = _first_pass(traces)
    traces = sorted(traces, key=lambda t: t.step)

    # Guard against a non-contiguous / duplicated executor stream.
    steps = [t.step for t in traces]
    if steps != list(range(steps[0], steps[0] + len(steps))):
        raise StepDomainMapError(
            f"executor current_step stream is not contiguous: "
            f"start={steps[0]} len={len(steps)} last={steps[-1]}"
        )

    survivors: List[ArguzzTrace] = []
    n_host = 0
    for t in traces:
        is_host_ecall = (t.instruction in _ECALL_MNEMONICS) and pc_in_kernel(t.pc)
        if is_host_ecall:
            n_host += 1
            continue
        survivors.append(t)

    R = len(survivors)
    # 1. We cannot have MORE real instructions than witgen user_cycles.
    if R > total_user_cycles:
        raise StepDomainMapError(
            f"step-domain map over-count: {R} surviving executor instructions > "
            f"{total_user_cycles} witgen user_cycles (host ecalls skipped={n_host}). "
            f"A host ecall was likely not detected; refusing to build."
        )
    # 2. The gap [R, total) must be trailing phantoms (no real compute Decode).
    if compute_user_cycles is not None:
        bad = [u for u in range(R, total_user_cycles) if u in compute_user_cycles]
        if bad:
            raise StepDomainMapError(
                f"step-domain map under-count: witgen user_cycles {bad[:8]} lie in the "
                f"phantom gap [{R},{total_user_cycles}) yet have a real major<=6 Decode. "
                f"Survivor accounting missed real instructions; refusing to build."
            )

    to_exec = {u: survivors[u].step for u in range(R)}
    to_user = {survivors[u].step: u for u in range(R)}

    # Monotonic, non-decreasing offset (current_step - user_cycle == host ecalls so far).
    prev = -1
    for u in range(len(survivors)):
        e = to_exec[u]
        if e < u or e <= prev:
            raise StepDomainMapError(
                f"non-monotonic map at user_cycle {u}: exec={e} prev_exec={prev}"
            )
        prev = e

    return StepDomainMap(
        to_exec=to_exec,
        to_user=to_user,
        exec_pc={t.step: t.pc for t in traces},
        exec_instr={t.step: t.instruction for t in traces},
        n_user_cycles=total_user_cycles,
        n_host_ecalls=n_host,
    )


def build_step_domain_map_from_binary(
    host_binary: str,
    host_args: List[str],
    total_user_cycles: int,
    *,
    timeout: float = 180.0,
) -> StepDomainMap:
    """Convenience: run ``host --trace`` and build the map.  Prefer passing already
    parsed traces (bootstrap captures ``--trace`` once) to avoid a second run."""
    cmd = [host_binary, "--trace", *host_args]
    proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
    out = (proc.stdout or b"").decode("utf-8", "replace") + (
        proc.stderr or b""
    ).decode("utf-8", "replace")
    if proc.returncode != 0:
        raise StepDomainMapError(f"host --trace failed rc={proc.returncode}")
    return build_step_domain_map(parse_all_traces(out), total_user_cycles)


__all__ = [
    "StepDomainMap",
    "StepDomainMapError",
    "build_step_domain_map",
    "build_step_domain_map_from_binary",
]

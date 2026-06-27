"""Step-domain fix regression gate (a4/docs/cloud3/arguzz_step_domain_fix).

THE invariant (both surfaces): the cell actually mutated by an arm belongs to the
semantic `zone` (and `opcode_class`) the arm declares.

- Arguzz arms: step is an executor `current_step`; its true zone is
  `exec_step_to_zone[step] = step_to_zone[to_user[step]]`.
- A4 arms: step is a witgen `user_cycle`; its true zone is `classify_zones[step]`.

These tests need a real risc0-host binary (no prover — only `--trace` + `A4_INSPECT`).
Point STEP_DOMAIN_TEST_BIN at one; defaults to the CVE B2 binary. Skips if absent.
The B2-specific landmark test (remu→444, divu→449) only runs on that guest.
"""

import os
import subprocess

import pytest

from a4.arguzz_dependent.arguzz_parser import parse_all_traces
from a4.core.inspection_data import InspectionData
from a4.standalone.mutations import arguzz_bridge
from a4.standalone.semantic_arm_universe import ArmKey, ARGUZZ_EXEC_FAULT, SemanticArmUniverse
from a4.standalone.step_domain_map import build_step_domain_map
from a4.standalone.zone_classifier import classify_zones

BIN = os.environ.get(
    "STEP_DOMAIN_TEST_BIN",
    "/root/arguzz/workspace/output-a1vuln/target/release/risc0-host",
)
ARGS = os.environ.get("STEP_DOMAIN_TEST_ARGS", "--ctrl 7 --gseed 12345 --rounds 5").split()
IS_B2 = "output-a1vuln" in BIN  # the CVE guest with the known remu/divu landmarks

pytestmark = pytest.mark.skipif(
    not os.path.exists(BIN), reason=f"risc0-host binary not found: {BIN}"
)


@pytest.fixture(scope="module")
def built():
    """Build map + exec_step_to_zone + fixed/legacy arm universes once (no prover)."""
    data = InspectionData.from_inspection(BIN, ARGS)
    proc = subprocess.run([BIN, "--trace", *ARGS], capture_output=True, timeout=300)
    out = (proc.stdout or b"").decode("utf-8", "replace") + (
        proc.stderr or b""
    ).decode("utf-8", "replace")
    traces = parse_all_traces(out)
    baseline_trace = {tr.step: tr.instruction for tr in traces}
    compute_uc = {c.step for c in data.cycles if c.major <= 6}
    m = build_step_domain_map(traces, data.total_steps, compute_user_cycles=compute_uc)
    step_to_zone = classify_zones(data)
    exec_step_to_zone = m.exec_step_zone_map(step_to_zone)
    kinds = list(arguzz_bridge.MUTATION_KINDS_ARGUZZ_FULL)
    fixed = SemanticArmUniverse.build(
        data, [], arguzz_kinds=kinds, baseline_trace=baseline_trace,
        arguzz_step_to_zone=exec_step_to_zone,
    )
    legacy = SemanticArmUniverse.build(
        data, [], arguzz_kinds=kinds, baseline_trace=baseline_trace,
    )
    return dict(
        data=data, traces=traces, baseline_trace=baseline_trace, map=m,
        step_to_zone=step_to_zone, exec_step_to_zone=exec_step_to_zone,
        fixed=fixed, legacy=legacy,
    )


def _arguzz_violations(uni, exec_step_to_zone, opcl):
    bad = total = 0
    for arm, steps in uni.arms.items():
        if arm.surface != ARGUZZ_EXEC_FAULT:
            continue
        for e in steps:
            total += 1
            if exec_step_to_zone.get(e, "core_other") != arm.zone or opcl(e) != arm.opcode_class:
                bad += 1
    return bad, total


# ---- T1: mutation-target consistency (the core guarantee), both directions ----

def test_arguzz_arms_consistent_with_fix(built):
    """Every Arguzz arm step's true (zone, opcode_class) == the arm's labels."""
    opcl = lambda e: arguzz_bridge.opcode_class_for_step(e, built["data"], built["baseline_trace"])
    bad, total = _arguzz_violations(built["fixed"], built["exec_step_to_zone"], opcl)
    assert total > 0, "expected some Arguzz arm steps"
    assert bad == 0, f"{bad}/{total} Arguzz arm steps mislabeled under the fix"


def test_legacy_build_is_detectably_broken(built):
    """Negative control: without the map, the historical mis-index produces violations,
    so the invariant test above is actually capable of catching the bug."""
    opcl = lambda e: arguzz_bridge.opcode_class_for_step(e, built["data"], built["baseline_trace"])
    bad, total = _arguzz_violations(built["legacy"], built["exec_step_to_zone"], opcl)
    assert bad > 0, "legacy build should violate the invariant (guard would be vacuous otherwise)"


def test_a4_arms_zone_consistent(built):
    """T5: A4 arms (witgen user_cycle) — arm.zone == classify_zones[step]. Build a small
    A4 universe and check the witgen-native labeling is self-consistent."""
    data = built["data"]
    a4 = SemanticArmUniverse.build(data, ["INSTR_WORD_MOD"])  # pure-A4, witgen space
    s2z = built["step_to_zone"]
    bad = total = 0
    for arm, steps in a4.arms.items():
        if arm.surface == ARGUZZ_EXEC_FAULT:
            continue
        for s in steps:
            total += 1
            if s2z.get(s, "core_other") != arm.zone:
                bad += 1
    assert total > 0 and bad == 0, f"A4 arm zone mismatch: {bad}/{total}"


def test_reward_inputs_use_correct_zone_major(built):
    """The bandit reward (s_new structural cell + g_new CGC) is keyed on
    (mutation_zone, mutation_major). The fix did NOT change reward logic — it corrects the
    INPUTS via `_arguzz_zone_major`. Verify that input equals the arm's true zone for every
    Arguzz arm step, and (B2) that the remu's reward input is (core_div, 4) where the
    historical mis-indexed lookup gave a wrong zone."""
    import types

    from a4.standalone.fuzzer import A4Fuzzer

    stub = types.SimpleNamespace(
        _arguzz_step_map=built["map"],
        _exec_step_to_zone=built["exec_step_to_zone"],
        _step_to_zone=built["step_to_zone"],
        data=built["data"],
        _baseline_trace=built["baseline_trace"],
    )
    bad = tot = 0
    for arm, steps in built["fixed"].arms.items():
        if arm.surface != ARGUZZ_EXEC_FAULT:
            continue
        for e in steps:
            tot += 1
            zone, _major = A4Fuzzer._arguzz_zone_major(stub, e)
            if zone != arm.zone:
                bad += 1
    assert tot > 0 and bad == 0, f"reward-input zone != arm zone for {bad}/{tot} steps"
    if IS_B2:
        zone, major = A4Fuzzer._arguzz_zone_major(stub, 444)  # remu executor step
        assert (zone, major) == ("core_div", 4), f"remu reward input ({zone},{major}) != (core_div,4)"
        # the historical mis-index would have fed the WRONG zone into the reward:
        assert built["step_to_zone"].get(444) != "core_div"


# ---- T2: map golden + structural self-checks ----

def test_map_monotone_and_phantom_gap(built):
    m = built["map"]
    prev = -1
    for u in sorted(m.to_exec):
        e = m.to_exec[u]
        assert e >= u and e > prev, "map must be monotone with to_exec(u) >= u"
        prev = e
    assert 0 <= built["data"].total_steps - len(m.to_exec) <= 8, "phantom gap should be tiny (trailing)"


def test_per_pull_guard_fires_on_wrong_zone(built):
    """The runtime Layer-1 guard must accept a correctly-labeled arm and ABORT on a
    wrong zone — this is the guarantee that no pull mutates under a wrong semantic label."""
    import types

    from a4.standalone.fuzzer import A4Fuzzer

    stub = types.SimpleNamespace(
        _arguzz_step_map=built["map"],
        _exec_step_to_zone=built["exec_step_to_zone"],
        _baseline_trace=built["baseline_trace"],
        data=built["data"],
    )
    arm, steps = next(
        (a, s) for a, s in built["fixed"].arms.items()
        if a.surface == ARGUZZ_EXEC_FAULT and s
    )
    e = steps[0]
    A4Fuzzer._assert_arguzz_target(stub, arm, e)  # correct arm: must not raise
    wrong_zone = "core_div" if arm.zone != "core_div" else "core_memory_store"
    bad = ArmKey(ARGUZZ_EXEC_FAULT, arm.kind, wrong_zone, arm.opcode_class, arm.pre_post)
    with pytest.raises(RuntimeError, match="step-domain guard"):
        A4Fuzzer._assert_arguzz_target(stub, bad, e)


@pytest.mark.skipif(not IS_B2, reason="landmark values are specific to the CVE B2 guest")
def test_b2_divide_landmarks(built):
    m, bt = built["map"], built["baseline_trace"]
    assert m.exec_step(436) == 444 and bt[444] == "RemU"
    assert m.exec_step(441) == 449 and bt[449] == "DivU"
    # core_div|INSTR_WORD must now hold the real divides, not lw/ori
    div_steps = sorted({
        e for arm, steps in built["fixed"].arms.items()
        if arm.surface == ARGUZZ_EXEC_FAULT and arm.zone == "core_div"
        and arm.kind == "INSTR_WORD_MOD" for e in steps
    })
    assert div_steps == [444, 449], f"core_div|INSTR_WORD steps = {div_steps}, want [444, 449]"

"""IV.POS.9 V0/V8 — gated integration test on the real holed Seam-B binary.

Reproduces the V0/V8 setup + selector validation WITHOUT proving (just one inspection +
`--trace` + scheduler picks): V0 builds the semantic arm universe; V8 builds the
ArguzzScheduler + the executor→user_cycle step-domain map and returns only VALID
`(kind, user_cycle)` picks with INSTR_TYPE_MOD reachable. Makes the otherwise-manual
real-binary validation reproducible + committed. Skipped when the holed binary isn't
built (gitignored). One module-scoped inspection is shared across both tests (the binary
run dominates wall-time on the dev box).
"""
import os

import pytest

ROOT = "/root/arguzz"
HOLED = os.path.join(ROOT, "a4/builds/ap_seamb/bench-verifyopcode/risc0-host")
ARGS = ["--ctrl", "7", "--gseed", "12345", "--rounds", "5"]

pytestmark = pytest.mark.skipif(
    not os.path.exists(HOLED), reason="holed Seam-B binary not built (gitignored)"
)


@pytest.fixture(scope="module")
def fuzzer():
    import sys
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    from a4.standalone.fuzzer import A4Fuzzer
    f = A4Fuzzer(host_binary=HOLED, host_args=ARGS, db_path="/tmp/_v0v8_integ.db",
                 selector_strategy="a4_arguzz_sched", seed=1234)
    f.run_inspection()  # ONE inspection, reused by both tests
    return f


def test_v8_setup_and_picks_valid_on_real_binary(fuzzer):
    fuzzer._setup_v8_arguzz_sched(6)  # builds ArguzzScheduler + step-domain map (+ a --trace)
    sel = fuzzer.selector
    assert sel.step_map.n_user_cycles > 0
    assert len(sel.sched._candidate_instrs) > 0
    valid = {k: set(fuzzer.data.get_valid_steps_for_kind(k)) for k in fuzzer.MUTATION_KINDS}
    picks = [sel.select_arm_then_step() for _ in range(200)]
    # every pick is a valid (kind, user_cycle): the executor→user_cycle translation is sound
    assert all(u in valid[k] for k, u in picks), "V8 returned an invalid (kind, user_cycle)"
    assert "INSTR_TYPE_MOD" in {k for k, _ in picks}  # bug-reaching kind reachable under V8


def test_v0_setup_and_picks_valid_on_real_binary(fuzzer):
    fuzzer._setup_a4_uniform_semantic(6)  # reuses fuzzer.data (no extra binary run)
    sel = fuzzer.selector
    au = fuzzer.semantic_arm_universe
    assert au.num_arms > 0
    valid = {(arm.kind, s) for arm in au.available_arms for s in au.steps_for_arm(arm)}
    picks = [sel.select_arm_then_step() for _ in range(200)]
    assert all((k, u) in valid for k, u in picks), "V0 returned an invalid (kind, step)"
    assert "INSTR_TYPE_MOD" in {k for k, _ in picks}

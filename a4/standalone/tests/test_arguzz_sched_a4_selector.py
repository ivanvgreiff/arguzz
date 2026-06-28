"""IV.POS.9 V8 — tests for `ArguzzSchedA4Selector` (Arguzz instruction-balanced site
selection driving A4 mutations; NO arms, NO bandit).

Unit-tested with fakes for the ArguzzScheduler + StepDomainMap + InspectionData so the
selection LOGIC — executor→user_cycle translation, host-ecall skip, no-valid-kind skip,
uniform-over-valid-A4-kinds (option b) — is verified without a binary. See
a4/docs/cloud3/bug_race_a4_arguzz_scheduler/.
"""
from collections import Counter

import pytest

from a4.standalone.step_selector import ArguzzSchedA4Selector


class _FakeSched:
    """ArguzzScheduler stand-in: .pick() cycles a fixed (instr, exec_step, kind) list."""
    def __init__(self, picks):
        self.picks = list(picks)
        self.i = 0

    def pick(self):
        p = self.picks[self.i % len(self.picks)]
        self.i += 1
        return p


class _FakeStepMap:
    def __init__(self, to_user):
        self.to_user = dict(to_user)

    def user_cycle_of(self, exec_step):
        return self.to_user.get(exec_step)


class _FakeData:
    def __init__(self, valid_by_kind):
        self.valid_by_kind = {k: list(v) for k, v in valid_by_kind.items()}

    def get_valid_steps_for_kind(self, kind):
        return list(self.valid_by_kind.get(kind, []))


def test_translates_exec_to_user_cycle_and_picks_valid_kind():
    sel = ArguzzSchedA4Selector(
        _FakeSched([("add", 10, "X")]), _FakeStepMap({10: 7}),
        _FakeData({"INSTR_TYPE_MOD": {7}, "COMP_OUT_MOD": {99}}),
        ["INSTR_TYPE_MOD", "COMP_OUT_MOD"], seed=1,
    )
    kind, u = sel.select_arm_then_step()
    assert u == 7 and kind == "INSTR_TYPE_MOD"  # translated to user_cycle, only ITM valid @7


def test_skips_host_ecall_steps():
    # exec_step 5 is a host ecall (no user_cycle); 10 -> user_cycle 7.
    sel = ArguzzSchedA4Selector(
        _FakeSched([("eany", 5, "X"), ("add", 10, "X")]), _FakeStepMap({10: 7}),
        _FakeData({"INSTR_TYPE_MOD": {7}}), ["INSTR_TYPE_MOD"], seed=1,
    )
    assert sel.select_arm_then_step() == ("INSTR_TYPE_MOD", 7)
    assert sel.n_host_ecall_skips == 1


def test_skips_sites_with_no_valid_a4_kind():
    sel = ArguzzSchedA4Selector(
        _FakeSched([("add", 10, "X"), ("sub", 20, "X")]), _FakeStepMap({10: 7, 20: 8}),
        _FakeData({"INSTR_TYPE_MOD": {8}}), ["INSTR_TYPE_MOD"], seed=1,
    )
    assert sel.select_arm_then_step() == ("INSTR_TYPE_MOD", 8)  # 7 has no valid kind -> skip
    assert sel.n_no_kind_skips == 1


def test_uniform_over_valid_kinds_at_site():
    """Option (b): at a fixed site, the kind is uniform over the A4 kinds valid there."""
    sel = ArguzzSchedA4Selector(
        _FakeSched([("add", 10, "X")]), _FakeStepMap({10: 7}),
        _FakeData({"INSTR_TYPE_MOD": {7}, "COMP_OUT_MOD": {7}}),
        ["INSTR_TYPE_MOD", "COMP_OUT_MOD"], seed=5,
    )
    counts = Counter(sel.select_arm_then_step()[0] for _ in range(4000))
    assert set(counts) == {"INSTR_TYPE_MOD", "COMP_OUT_MOD"}
    assert abs(counts["INSTR_TYPE_MOD"] - 2000) < 250  # ~uniform


def test_raises_when_no_valid_site_after_retries():
    sel = ArguzzSchedA4Selector(
        _FakeSched([("eany", 5, "X")]), _FakeStepMap({}),  # everything is a host ecall
        _FakeData({"INSTR_TYPE_MOD": {7}}), ["INSTR_TYPE_MOD"], seed=1, max_retries=10,
    )
    with pytest.raises(RuntimeError):
        sel.select_arm_then_step()


def test_determinism():
    mk = lambda: ArguzzSchedA4Selector(
        _FakeSched([("add", 10, "X"), ("sub", 20, "X")]), _FakeStepMap({10: 7, 20: 8}),
        _FakeData({"INSTR_TYPE_MOD": {7, 8}, "COMP_OUT_MOD": {7, 8}}),
        ["INSTR_TYPE_MOD", "COMP_OUT_MOD"], seed=99,
    )
    s1, s2 = mk(), mk()
    assert [s1.select_arm_then_step() for _ in range(40)] == \
           [s2.select_arm_then_step() for _ in range(40)]


def test_select_step_legacy_raises():
    sel = ArguzzSchedA4Selector(
        _FakeSched([("add", 10, "X")]), _FakeStepMap({10: 7}),
        _FakeData({"INSTR_TYPE_MOD": {7}}), ["INSTR_TYPE_MOD"], seed=1,
    )
    with pytest.raises(NotImplementedError):
        sel.select_step(data=None, kind="INSTR_TYPE_MOD")

#!/usr/bin/env python3
"""Phase 2 — V6-cTS Bernoulli decision-sequence golden trace (§6 Layer-2)."""

from __future__ import annotations

import json
from pathlib import Path

from a4.standalone.bandit_ts import ConstrainedTSScheduler, ConstantFloor
from a4.standalone.tests.test_bandit_ts import _decision_trace, _small_universe

_FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "d2_bernoulli_v6_cts_decision_seq_seed777_n200.json"
)


class TestD2BernoulliFloorGoldenTrace:
    def test_v6_cts_bernoulli_decision_trace_matches_fixture(self):
        assert _FIXTURE.is_file(), f"missing golden fixture: {_FIXTURE}"
        expected = [tuple(row) for row in json.loads(_FIXTURE.read_text())]

        seed = 777
        n = 200
        successes = [1 if i % 7 == 0 else 0 for i in range(n)]
        sched = ConstrainedTSScheduler(
            _small_universe(),
            cold_start_pulls_per_arm=1,
            forced_singleton_pulls=2,
            epoch_size=100,
            seed=seed,
            floor_schedule=ConstantFloor(0.55),
            bernoulli_floor=True,
        )
        actual = _decision_trace(sched, n, successes)

        assert actual == expected
        modes_seen = {row[1] for row in actual}
        assert modes_seen >= {"cold", "floor", "adaptive"}

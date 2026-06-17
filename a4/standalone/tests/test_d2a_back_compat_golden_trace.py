#!/usr/bin/env python3
"""D2.A Batch 1 — V5 golden trace must match pre-refactor baseline."""

from __future__ import annotations

import json
from pathlib import Path

from a4.standalone.bandit_ts import ConstrainedTSScheduler
from a4.standalone.tests.test_bandit_ts import _decision_trace, _small_universe

_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "d2a_golden_v5_trace_seed42_n200.json"


class TestD2ABackCompatGoldenTrace:
    def test_v5_decision_trace_matches_pre_d2a_baseline(self):
        assert _FIXTURE.is_file(), f"missing golden fixture: {_FIXTURE}"
        expected = [tuple(row) for row in json.loads(_FIXTURE.read_text())]

        seed = 42
        n = 200
        successes = [1 if i % 7 == 0 else 0 for i in range(n)]
        sched = ConstrainedTSScheduler(_small_universe(), seed=seed)
        actual = _decision_trace(sched, n, successes)

        assert actual == expected
        modes_seen = {row[1] for row in actual}
        assert modes_seen >= {"cold", "floor", "adaptive"}

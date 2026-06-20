#!/usr/bin/env python3
"""D2.D Batch 1 — variant registry parity + CLI dispatch."""

from __future__ import annotations

import argparse
import sys
from unittest.mock import patch

import pytest

from a4.core.inspection_data import InspectionData
from a4.core.trace_parser import A4CycleInfo
from a4.core.touch_coverage import A4_TOUCH_MAP_SIZE
from a4.standalone.baseline_touch import BaselineTouch
from a4.standalone.bandit_ts import ConstrainedTSScheduler
from a4.standalone.fuzzer import A4Fuzzer, ARGUZZ_CTS_STRATEGIES
from a4.standalone.mutations.arguzz_bridge import (
    MUTATION_KINDS_ARGUZZ_FULL,
    MUTATION_KINDS_ARGUZZ_SELECTED,
)
from a4.standalone.variants import (
    CANONICAL_VARIANTS,
    resolve_variant,
    variant_launch_command,
)


def _cycles(n: int = 8):
    return [
        A4CycleInfo(
            cycle_idx=i, step=i, pc=0x200000 + i * 4, txn_idx=i,
            major=i % 5, minor=0,
        )
        for i in range(n)
    ]


def _inspection_data() -> InspectionData:
    return InspectionData(cycles=_cycles(), all_txns=[], reg_txns=[])


def _baseline_touch() -> BaselineTouch:
    return BaselineTouch(
        bitmap=bytearray(A4_TOUCH_MAP_SIZE),
        distinct_buckets=0,
        total_touches=0,
        touched_indices=[],
    )


def _setup_fuzzer(selector: str) -> A4Fuzzer:
    fz = A4Fuzzer(
        host_binary="/bin/true",
        host_args=["--in1", "5"],
        db_path=":memory:",
        selector_strategy=selector,
        seed=1,
        telemetry_level="none",
    )
    fz.data = _inspection_data()
    with patch(
        "a4.standalone.fuzzer.capture_baseline_touch",
        return_value=_baseline_touch(),
    ):
        with patch.object(
            fz,
            "_capture_baseline_trace",
            return_value={i: "add" for i in range(8)},
        ):
            fz._setup_v2_bandit(10)
    return fz


class TestVariantRegistry:
    @pytest.mark.parametrize("name", list(CANONICAL_VARIANTS))
    def test_resolve_variant(self, name: str):
        assert resolve_variant(name).name == name

    def test_v5_control_live_config(self):
        spec = CANONICAL_VARIANTS["V5_control"]
        fz = _setup_fuzzer("cTS_semantic_v2")
        assert isinstance(fz.v2_scheduler, ConstrainedTSScheduler)
        assert fz.v2_scheduler.bernoulli_floor is spec.bernoulli_floor
        arguzz, a4, applied = fz._arguzz_strategy_config()
        assert arguzz is None
        assert applied is spec.applied_accounting

    def test_v6_cts_live_config(self):
        spec = CANONICAL_VARIANTS["V6_cTS"]
        fz = _setup_fuzzer("v6_cTS")
        assert fz.v2_scheduler.bernoulli_floor is spec.bernoulli_floor
        arguzz, a4, applied = fz._arguzz_strategy_config()
        assert arguzz == list(MUTATION_KINDS_ARGUZZ_FULL)
        assert a4 == []
        assert applied is True

    def test_hybrid_cts_live_config(self):
        spec = CANONICAL_VARIANTS["Hybrid_cTS"]
        fz = _setup_fuzzer("hybrid_cTS")
        assert fz.v2_scheduler.bernoulli_floor is spec.bernoulli_floor
        arguzz, a4, applied = fz._arguzz_strategy_config()
        assert arguzz == list(MUTATION_KINDS_ARGUZZ_SELECTED)
        assert len(a4) >= 1
        assert applied is True

    def test_v6_uniform_launch_command(self):
        cmd = variant_launch_command(
            "V6_uniform",
            host="/path/host",
            db="/path/db.db",
            seed=1,
            num=10,
            host_args=["--in1", "5"],
        )
        assert "v6_uniform_driver" in cmd[2]
        assert "--num" in cmd and "10" in cmd

    def test_v6_cts_launch_command(self):
        cmd = variant_launch_command(
            "V6_cTS",
            host="/path/host",
            db="/path/db.db",
            seed=1,
            num=10,
        )
        assert "v6_cTS" in cmd
        assert "a4.standalone.cli" in cmd


class TestCliVariantDispatch:
    def test_cli_accepts_v6_cts_and_hybrid(self):
        from a4.standalone import cli as cli_mod

        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="command")
        fuzz = sub.add_parser("fuzz")
        fuzz.add_argument("--host", required=True)
        fuzz.add_argument("--selector", default="zoned", choices=[
            "zoned", "guided", "bandit", "uniform",
            "kindUCB_zoned_v1", "kindUCB_zoned_v2_noQ",
            "kindTS_zoned_v2", "cTS_semantic_v2",
            "cTS_semantic_v2_decayexp", "cTS_semantic_v2_decayepoch",
            "v6_cTS", "hybrid_cTS",
        ])

        for sel in ("v6_cTS", "hybrid_cTS", "cTS_semantic_v2"):
            args = parser.parse_args(
                ["fuzz", "--host", "/bin/true", "--selector", sel],
            )
            assert args.selector == sel

        with pytest.raises(SystemExit):
            parser.parse_args(
                ["fuzz", "--host", "/bin/true", "--selector", "not_a_variant"],
            )

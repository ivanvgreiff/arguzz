#!/usr/bin/env python3
"""
Phase II.0 test: baseline (unmutated) run with A4_COVERAGE_TOUCH=1 produces a valid touch bitmap.

Requires A4_TEST_HOST and optionally A4_TEST_HOST_ARGS (same pattern as determinism tests).
Run: A4_TEST_HOST=./workspace/output/target/release/risc0-host A4_TEST_HOST_ARGS="--in1 5 --in4 10" python -m pytest a4/standalone/tests/test_baseline_touch.py -v
"""

import os
import tempfile
from pathlib import Path

import pytest

from a4.standalone.baseline_touch import (
    capture_baseline_touch,
    save_baseline,
    load_baseline,
    BaselineTouch,
)
from a4.core.touch_coverage import A4_TOUCH_MAP_SIZE


@pytest.mark.skipif(
    not os.environ.get("A4_TEST_HOST"),
    reason="Set A4_TEST_HOST (and optionally A4_TEST_HOST_ARGS) to run",
)
def test_baseline_produces_touch_bitmap():
    """Baseline (unmutated) run with touch enabled must produce a valid bitmap."""
    host_binary = os.environ["A4_TEST_HOST"].strip()
    host_args_str = os.environ.get("A4_TEST_HOST_ARGS", "--in1 5 --in4 10").strip()
    host_args = host_args_str.split() if host_args_str else []

    baseline = capture_baseline_touch(host_binary, host_args)

    assert baseline.bitmap is not None
    assert len(baseline.bitmap) == A4_TOUCH_MAP_SIZE

    # Plausibility: some constraints must be evaluated (>0), but not every bucket (< MAP_SIZE)
    assert baseline.distinct_buckets > 0, "No constraint contexts touched — instrumentation issue?"
    assert baseline.distinct_buckets < A4_TOUCH_MAP_SIZE, "Every bucket touched — likely a bug"

    # Based on Phase 3.2 measurement (~1599 distinct for mutated run), baseline should be similar
    assert baseline.distinct_buckets > 500, (
        f"Only {baseline.distinct_buckets} distinct buckets — expected ~1000+ for this guest program"
    )

    assert baseline.total_touches > 0
    assert len(baseline.touched_indices) == baseline.distinct_buckets
    assert baseline.touched_indices == sorted(baseline.touched_indices)

    print(f"  Baseline distinct_buckets: {baseline.distinct_buckets}")
    print(f"  Baseline total_touches: {baseline.total_touches}")


@pytest.mark.skipif(
    not os.environ.get("A4_TEST_HOST"),
    reason="Set A4_TEST_HOST (and optionally A4_TEST_HOST_ARGS) to run",
)
def test_baseline_save_load_roundtrip():
    """Save and load baseline; verify indices and stats survive."""
    host_binary = os.environ["A4_TEST_HOST"].strip()
    host_args_str = os.environ.get("A4_TEST_HOST_ARGS", "--in1 5 --in4 10").strip()
    host_args = host_args_str.split() if host_args_str else []

    baseline = capture_baseline_touch(host_binary, host_args)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        tmp_path = Path(f.name)

    try:
        save_baseline(baseline, tmp_path)
        loaded = load_baseline(tmp_path)

        assert loaded.distinct_buckets == baseline.distinct_buckets
        assert loaded.total_touches == baseline.total_touches
        assert loaded.touched_indices == baseline.touched_indices
        # Loaded bitmap is binary (0/1) not original counters, but non-zero indices match
        for i in baseline.touched_indices:
            assert loaded.bitmap[i] > 0
    finally:
        tmp_path.unlink(missing_ok=True)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

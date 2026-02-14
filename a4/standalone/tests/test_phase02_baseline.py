#!/usr/bin/env python3
"""
Phase 0.2 baseline test: unmutated guest run must produce zero constraint failures.

Runs the host without A4_MUTATION_CONFIG or CONSTRAINT_CONTINUE. A valid witness
should not trigger any <constraint_fail> output.

Requires A4_TEST_HOST and optionally A4_TEST_HOST_ARGS (same as determinism test).
Run: A4_TEST_HOST=./workspace/output/target/release/risc0-host A4_TEST_HOST_ARGS="--in1 5 --in4 10" python -m pytest a4/standalone/tests/test_phase02_baseline.py -v
"""

import os

import pytest

from a4.core.executor import run_baseline
from a4.core.constraint_parser import parse_all_constraint_failures


@pytest.mark.skipif(
    not os.environ.get("A4_TEST_HOST"),
    reason="Set A4_TEST_HOST (and optionally A4_TEST_HOST_ARGS) to run",
)
def test_baseline_zero_constraint_failures():
    """Unmutated run must produce no <constraint_fail> lines."""
    host_binary = os.environ["A4_TEST_HOST"].strip()
    host_args_str = os.environ.get("A4_TEST_HOST_ARGS", "--in1 5 --in4 10").strip()
    host_args = host_args_str.split() if host_args_str else []

    output = run_baseline(host_binary, host_args)
    failures = parse_all_constraint_failures(output)

    assert len(failures) == 0, (
        f"Baseline (unmutated) run produced {len(failures)} constraint failure(s); expected 0. "
        "First few: " + str([f.constraint_loc() for f in failures[:5]])
    )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

#!/usr/bin/env python3
"""
Phase 0.1 determinism test: same mutation config run twice yields identical failure set.

Requires:
- A4-patched RISC Zero host built in release mode (SeqForward when A4_MUTATION_CONFIG set).
- Env A4_TEST_HOST: path to risc0-host binary.
- Env A4_TEST_HOST_ARGS: host arguments, e.g. "--in1 5 --in4 10" (space-separated).
- Optional A4_TEST_CONFIG: path to a fixed mutation config JSON. If unset, the test
  runs inspection once, creates one COMP_OUT_MOD config at the first valid step with
  a fixed mutated value, then runs the mutation twice.

Compares failure sets by context_id() (constraint_loc, major, minor) and by signature()
(step, pc, major, minor, short_loc). Fails if the two runs differ.

Run: A4_TEST_HOST=./workspace/output/target/release/risc0-host A4_TEST_HOST_ARGS="--in1 5 --in4 10" python -m pytest a4/standalone/tests/test_determinism.py -v
Or:  A4_TEST_HOST=... A4_TEST_HOST_ARGS="..." python -m a4.standalone.tests.test_determinism
"""

import os
import tempfile
from pathlib import Path

import pytest

from a4.core.executor import run_a4_mutation
from a4.core.constraint_parser import parse_all_constraint_failures
from a4.core.inspection_data import InspectionData
from a4.standalone.mutations.comp_out_mod import get_targets_at_step, create_config as create_comp_out_config


def _get_test_config_path() -> Path:
    """Path to optional pre-made config file."""
    path = os.environ.get("A4_TEST_CONFIG", "").strip()
    return Path(path) if path else None


def _build_config_from_inspection(host_binary: str, host_args: list) -> Path:
    """Run inspection, create one COMP_OUT_MOD config at first valid step; return config path."""
    data = InspectionData.from_inspection(host_binary, host_args)
    valid_steps = data.get_valid_steps_for_kind("COMP_OUT_MOD")
    if not valid_steps:
        raise RuntimeError("No valid COMP_OUT_MOD steps from inspection")
    target = None
    for step in valid_steps:
        target = get_targets_at_step(step, data)
        if target is not None:
            break
    if not target:
        raise RuntimeError("No COMP_OUT_MOD target at any valid step")
    step = target.step
    # Fixed mutated value for determinism
    mutated_value = 0xDEADBEEF
    fd, path = tempfile.mkstemp(suffix=".json", prefix="a4_determinism_")
    os.close(fd)
    config_path = Path(path)
    create_comp_out_config(target, mutated_value, config_path)
    return config_path


@pytest.mark.skipif(
    not os.environ.get("A4_TEST_HOST"),
    reason="Set A4_TEST_HOST (path to risc0-host) and A4_TEST_HOST_ARGS to run",
)
def test_same_config_same_failure_set_by_context_id():
    """Two runs with same config must yield the same set of context_id()."""
    host_binary = os.environ["A4_TEST_HOST"].strip()
    host_args_str = os.environ.get("A4_TEST_HOST_ARGS", "--in1 5 --in4 10").strip()
    host_args = host_args_str.split() if host_args_str else []

    config_path = _get_test_config_path()
    temp_config = None
    if config_path is None or not config_path.is_file():
        config_path = _build_config_from_inspection(host_binary, host_args)
        temp_config = config_path

    try:
        r1 = run_a4_mutation(host_binary, host_args, config_path)
        r2 = run_a4_mutation(host_binary, host_args, config_path)

        failures1 = parse_all_constraint_failures(r1.combined_output)
        failures2 = parse_all_constraint_failures(r2.combined_output)

        set1 = set(f.context_id() for f in failures1)
        set2 = set(f.context_id() for f in failures2)

        assert set1 == set2, (
            f"context_id sets differ: only in run1 {set1 - set2!r}, only in run2 {set2 - set1!r}"
        )
    finally:
        if temp_config and temp_config.exists():
            temp_config.unlink(missing_ok=True)


@pytest.mark.skipif(
    not os.environ.get("A4_TEST_HOST"),
    reason="Set A4_TEST_HOST (path to risc0-host) and A4_TEST_HOST_ARGS to run",
)
def test_same_config_same_failure_set_by_signature():
    """Two runs with same config must yield the same set of signature() (stricter)."""
    host_binary = os.environ["A4_TEST_HOST"].strip()
    host_args_str = os.environ.get("A4_TEST_HOST_ARGS", "--in1 5 --in4 10").strip()
    host_args = host_args_str.split() if host_args_str else []

    config_path = _get_test_config_path()
    temp_config = None
    if config_path is None or not config_path.is_file():
        config_path = _build_config_from_inspection(host_binary, host_args)
        temp_config = config_path

    try:
        r1 = run_a4_mutation(host_binary, host_args, config_path)
        r2 = run_a4_mutation(host_binary, host_args, config_path)

        failures1 = parse_all_constraint_failures(r1.combined_output)
        failures2 = parse_all_constraint_failures(r2.combined_output)

        set1 = set(f.signature() for f in failures1)
        set2 = set(f.signature() for f in failures2)

        assert set1 == set2, (
            f"signature sets differ: only in run1 {set1 - set2!r}, only in run2 {set2 - set1!r}"
        )
    finally:
        if temp_config and temp_config.exists():
            temp_config.unlink(missing_ok=True)


@pytest.mark.skipif(
    not os.environ.get("A4_TEST_HOST"),
    reason="Set A4_TEST_HOST (path to risc0-host) and A4_TEST_HOST_ARGS to run",
)
def test_same_config_same_touch_bitmap():
    """Two runs with same config must yield byte-identical touch bitmaps (Phase 3.4)."""
    host_binary = os.environ["A4_TEST_HOST"].strip()
    host_args_str = os.environ.get("A4_TEST_HOST_ARGS", "--in1 5 --in4 10").strip()
    host_args = host_args_str.split() if host_args_str else []

    config_path = _get_test_config_path()
    temp_config = None
    if config_path is None or not config_path.is_file():
        config_path = _build_config_from_inspection(host_binary, host_args)
        temp_config = config_path

    try:
        r1 = run_a4_mutation(host_binary, host_args, config_path)
        r2 = run_a4_mutation(host_binary, host_args, config_path)

        assert r1.touch_bitmap is not None, "Run 1 did not produce a touch bitmap"
        assert r2.touch_bitmap is not None, "Run 2 did not produce a touch bitmap"
        assert len(r1.touch_bitmap) == len(r2.touch_bitmap), (
            f"Bitmap lengths differ: {len(r1.touch_bitmap)} vs {len(r2.touch_bitmap)}"
        )

        if r1.touch_bitmap != r2.touch_bitmap:
            differing = sum(1 for a, b in zip(r1.touch_bitmap, r2.touch_bitmap) if a != b)
            assert False, (
                f"Touch bitmaps differ at {differing} of {len(r1.touch_bitmap)} bytes"
            )
    finally:
        if temp_config and temp_config.exists():
            temp_config.unlink(missing_ok=True)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

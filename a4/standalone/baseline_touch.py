"""
Baseline Touch Snapshot (Phase II.0)

Captures the touch bitmap from an unmutated (baseline) run of the host.
The baseline touch set records which constraint contexts are evaluated
during normal witness generation without any mutation applied.

Used for diagnostic comparison with mutated runs, not for the reward function
(which compares against the campaign's growing global bitmap, starting from zeros).

See a4/docs/touch/Phase II/PHASE_II_0_IMPLEMENTATION_PLAN.md for details.
"""

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List

from a4.core.executor import run_baseline
from a4.core.touch_coverage import (
    parse_touch_bitmap,
    distinct_touched,
    total_touches,
    A4_TOUCH_MAP_SIZE,
)


@dataclass
class BaselineTouch:
    """Snapshot of the touch bitmap from an unmutated run."""
    bitmap: bytes
    distinct_buckets: int
    total_touches: int
    touched_indices: List[int]


def capture_baseline_touch(host_binary: str, host_args: List[str]) -> BaselineTouch:
    """
    Run the host without mutation, with A4_COVERAGE_TOUCH=1, and parse the touch bitmap.

    Returns a BaselineTouch snapshot with the bitmap and summary statistics.
    Raises RuntimeError if the touch bitmap could not be parsed from the output.
    """
    output = run_baseline(host_binary, host_args, extra_env={"A4_COVERAGE_TOUCH": "1"})
    bitmap = parse_touch_bitmap(output)
    if bitmap is None:
        raise RuntimeError(
            "Baseline run did not produce a valid <a4_touch_coverage> tag. "
            "Ensure the host binary was built with Phase 3.2 C++ changes and "
            "that A4_COVERAGE_TOUCH is being read by the C++ code."
        )
    indices = sorted(i for i in range(A4_TOUCH_MAP_SIZE) if bitmap[i] > 0)
    return BaselineTouch(
        bitmap=bitmap,
        distinct_buckets=distinct_touched(bitmap),
        total_touches=total_touches(bitmap),
        touched_indices=indices,
    )


def save_baseline(baseline: BaselineTouch, path: Path) -> None:
    """Save baseline statistics to a JSON file (indices + stats, not the full bitmap)."""
    data = {
        "distinct_buckets": baseline.distinct_buckets,
        "total_touches": baseline.total_touches,
        "touched_indices": baseline.touched_indices,
    }
    path.write_text(json.dumps(data, indent=2))


def load_baseline(path: Path) -> BaselineTouch:
    """
    Load baseline statistics from a JSON file saved by save_baseline.

    Reconstructs the bitmap from the touched_indices list (binary: 1 for touched, 0 for not).
    Note: the reconstructed bitmap has 0/1 entries, not the original saturating counters.
    """
    data = json.loads(path.read_text())
    buf = bytearray(A4_TOUCH_MAP_SIZE)
    for i in data["touched_indices"]:
        buf[i] = 1
    return BaselineTouch(
        bitmap=bytes(buf),
        distinct_buckets=data["distinct_buckets"],
        total_touches=data["total_touches"],
        touched_indices=data["touched_indices"],
    )

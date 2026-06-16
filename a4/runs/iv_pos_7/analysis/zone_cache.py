"""Cached step→zone map from canonical guest inspection (IV.POS.7 host args)."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Dict

_REPO = Path(__file__).resolve().parents[4]
_DEFAULT_HOST = _REPO / "workspace/output/target/release/risc0-host"
_HOST_ARGS = ["--in1", "5", "--in4", "10"]


@lru_cache(maxsize=1)
def step_to_zone_map(host: str | None = None) -> Dict[int, str]:
    """classify_zones(InspectionData) — shared across all IV.POS.7 DBs (same guest)."""
    from a4.core.inspection_data import InspectionData
    from a4.standalone.zone_classifier import classify_zones

    h = host or str(_DEFAULT_HOST)
    data = InspectionData.from_inspection(h, _HOST_ARGS)
    return classify_zones(data)

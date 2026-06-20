"""C1/C2/C5 rejection-channel classifier (D2.G §5.3)."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Dict, List

import pandas as pd

from .discover import flat_db_list, parse_d2f_run_dir


def _config_dict(raw: str | None) -> dict:
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {}


def classify_mutation_row(
    outcome: str | None,
    local_failures: int,
    config: dict,
) -> str:
    """Return channel label: C1, C2, C5, applied, or other."""
    outcome = outcome or ""
    if outcome == "skipped":
        # Arguzz path: skipped ⟺ C5 (start+panic in arguzz_invoke); fuzzer config_json
        # omits host_panic/prover_status (F20) — classify from outcome alone.
        return "C5"
    if outcome == "applied":
        if local_failures > 0:
            return "C1"
        if config.get("failure_recording_gap"):
            return "C2"
        if config.get("soundness_signal"):
            return "accepted"
        return "applied_other"
    if outcome == "error":
        return "error"
    return "other"


def rejection_channels_for_db(db_path: Path) -> List[Dict[str, object]]:
    variant, seed, n = parse_d2f_run_dir(db_path.parent)
    rows: List[Dict[str, object]] = []
    with sqlite3.connect(db_path) as conn:
        q = """
            SELECT m.id, m.step, m.kind, m.outcome, m.config_json,
                   (SELECT COUNT(*) FROM failures f WHERE f.mutation_id = m.id) AS local_f
            FROM mutations m
            ORDER BY m.id
        """
        for mid, step, kind, outcome, cfg_raw, local_f in conn.execute(q):
            cfg = _config_dict(cfg_raw)
            channel = classify_mutation_row(outcome, int(local_f), cfg)
            rows.append({
                "variant": variant,
                "seed": seed,
                "expected_n": n,
                "mutation_id": mid,
                "step": step,
                "kind": kind,
                "outcome": outcome,
                "channel": channel,
                "local_failures": local_f,
            })
    return rows


def rejection_channels_frame(collection_root: Path) -> pd.DataFrame:
    all_rows: List[Dict[str, object]] = []
    for db in flat_db_list(collection_root):
        all_rows.extend(rejection_channels_for_db(db))
    return pd.DataFrame(all_rows)


def rejection_channels_summary(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return pd.DataFrame()
    return (
        df.groupby(["variant", "seed", "channel"], dropna=False)
        .size()
        .reset_index(name="count")
    )

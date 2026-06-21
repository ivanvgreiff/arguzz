#!/usr/bin/env python3
"""Smoke test for run_one + collect (B4 Item 0, ≤10 jobs, requires real binary)."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[4]
MANIFEST = (
    REPO / "a4/runs/iv_pos_8/d2f/prod/artifacts/d2g/triage_at_scale_b4"
    / "d2g_triage_rerun_manifest.csv"
)


@pytest.mark.skipif(os.environ.get("A4_REAL_BINARY") != "1", reason="A4_REAL_BINARY=1 required")
class TestRunOneSmoke:
    def test_run_one_roundtrip_and_collect(self, tmp_path: Path):
        if not MANIFEST.is_file():
            pytest.skip(f"manifest missing: {MANIFEST} — run pipeline first")
        host = os.environ.get(
            "A4_TEST_HOST", "workspace/output/target/release/risc0-host",
        )
        if not Path(host).is_file():
            pytest.skip(f"missing host: {host}")

        import pandas as pd
        from a4.runs.iv_pos_8.d2g.triage_at_scale import collect_results, run_one

        manifest = pd.read_csv(MANIFEST).head(3)
        results_dir = tmp_path / "results"
        results_dir.mkdir()
        for _, row in manifest.iterrows():
            run_id = triage_run_id(
                str(row["variant"]),
                int(row["seed"]),
                str(row["kind"]),
                int(row["step"]),
                int(row["iter_seed"]),
            )
            row_out = run_one(
                variant=str(row["variant"]),
                seed=int(row["seed"]),
                step=int(row["step"]),
                kind=str(row["kind"]),
                iter_seed=int(row["iter_seed"]),
                host=host,
                mutation_id=int(row.get("mutation_id", 0)),
                run_id=run_id,
                results_dir=results_dir,
            )
            assert "class" in row_out
            assert "evidence" in row_out
            assert (results_dir / f"{run_id}.json").is_file()

        out_csv = tmp_path / "collected.csv"
        df = collect_results(results_dir, out_csv)
        assert len(df) == len(manifest)
        assert set(df.columns) >= {"class", "evidence", "kind", "variant"}
        allowed = {
            "", "strong", "weak", "cosmetic", "word_truncated",
            "identity", "cf_inert",
        }
        assert set(df["evidence"].unique()).issubset(allowed)


def test_dedupe_collected_triage_prefers_canonical_run_id():
    import pandas as pd
    from a4.runs.iv_pos_8.d2g.triage_at_scale import dedupe_collected_triage, triage_run_id

    canonical = triage_run_id("V6_cTS", 1234, "POST_EXEC_PC_MOD", 0, 1234000929)
    df = pd.DataFrame([
        {
            "variant": "V6_cTS", "seed": 1234, "kind": "POST_EXEC_PC_MOD",
            "step": 0, "iter_seed": 1234000929, "run_id": "test_fixed",
            "class": "accepted_noop", "evidence": "cf_inert",
        },
        {
            "variant": "V6_cTS", "seed": 1234, "kind": "POST_EXEC_PC_MOD",
            "step": 0, "iter_seed": 1234000929, "run_id": canonical,
            "class": "accepted_noop", "evidence": "cf_inert",
        },
    ])
    out, n_removed = dedupe_collected_triage(df)
    assert n_removed == 1
    assert len(out) == 1
    assert out.iloc[0]["run_id"] == canonical

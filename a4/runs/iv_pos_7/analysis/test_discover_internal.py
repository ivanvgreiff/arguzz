"""Tests for discover.py V0/V6 extensions."""
from __future__ import annotations

from pathlib import Path

import pytest

from .discover import (
    ALL_VARIANTS_ORDER,
    V6_EXPECTED_SEEDS,
    discover_dbs,
    discover_status,
    parse_db_path,
)


@pytest.mark.parametrize(
    "name,variant,selector,seed",
    [
        ("pos_iv_pos_7_u_b1a_uniform_seed1234_n6000.db", "V0", "uniform", 1234),
        ("pos_iv_pos_7_v6_b1b_arguzz_seed1236_n6000.db", "V6", "arguzz", 1236),
        ("pos_iv_pos_7_ta_b1_zoned_seed1234_n6000.db", "V1", "zoned", 1234),
        ("pos_iv_pos_7_ts_b3_cTS_semantic_v2_seed1236_n6000.db", "V5", "cTS_semantic_v2", 1236),
    ],
)
def test_parse_db_path_selectors(name: str, variant: str, selector: str, seed: int):
    v, s, sd, _ = parse_db_path(Path(name))
    assert v == variant
    assert s == selector
    assert sd == seed


@pytest.mark.parametrize(
    "name,variant,selector,seed",
    [
        (
            "pos_iv_pos_8_d1a_b1_cTS_semantic_v2_decayexp_seed1234_n6000.db",
            "V5-decayexp",
            "cTS_semantic_v2_decayexp",
            1234,
        ),
        (
            "pos_iv_pos_8_d1a_b1_cTS_semantic_v2_decayepoch_seed1234_n6000.db",
            "V5-decayepoch",
            "cTS_semantic_v2_decayepoch",
            1234,
        ),
        (
            "pos_iv_pos_7_ts_b5_cTS_semantic_v2_seed1238_n6000.db",
            "V5",
            "cTS_semantic_v2",
            1238,
        ),
    ],
)
def test_parse_db_path_decay_selectors_longest_first(
    name: str, variant: str, selector: str, seed: int,
):
    v, s, sd, _ = parse_db_path(Path(name))
    assert v == variant
    assert s == selector
    assert sd == seed


def test_all_variants_order_includes_v0_v6():
    assert "V0" in ALL_VARIANTS_ORDER
    assert "V6" in ALL_VARIANTS_ORDER
    assert ALL_VARIANTS_ORDER.index("V0") < ALL_VARIANTS_ORDER.index("V1")
    assert ALL_VARIANTS_ORDER.index("V5") < ALL_VARIANTS_ORDER.index("V6")


def test_discover_finds_r2_dbs():
    m = discover_dbs()
    for variant in ("V1", "V2", "V3", "V4", "V5"):
        assert len(m[variant]) == 10, f"{variant} should have 10 seeds"


def test_discover_status_keys():
    st = discover_status()
    assert "v6_partial" in st
    assert "v0_seed_count" in st
    assert st["v6_expected_seeds"] == V6_EXPECTED_SEEDS


def test_v6_skips_db_without_ok_marker(tmp_path: Path):
    """In-flight V6 DBs without .OK must not be discovered."""
    incomplete = tmp_path / "pos_iv_pos_7_v6_b1b_arguzz_seed1236_n6000.db"
    incomplete.write_bytes(b"")
    m = discover_dbs(tmp_path, variants=("V6",))
    assert len(m["V6"]) == 0


def test_v6_includes_db_with_ok_marker(tmp_path: Path):
    run_dir = tmp_path / "2026-06-15_run"
    run_dir.mkdir()
    (run_dir / "RUN.OK").write_text("ok")
    db = run_dir / "pos_iv_pos_7_v6_b1b_arguzz_seed1236_n6000.db"
    db.write_bytes(b"")
    m = discover_dbs(tmp_path, variants=("V6",))
    assert m["V6"][1236] == db


def test_v6_includes_db_with_meta_json_exit_ok(tmp_path: Path):
    run_dir = tmp_path / "pos_iv_pos_7_v6_b1b_arguzz_seed1236_n6000"
    run_dir.mkdir()
    (run_dir / "meta.json").write_text(
        '{"exit_code":0,"ended_at_epoch":1781572377}'
    )
    db = run_dir / "pos_iv_pos_7_v6_b1b_arguzz_seed1236_n6000.db"
    db.write_bytes(b"")
    m = discover_dbs(tmp_path, variants=("V6",))
    assert m["V6"][1236] == db


def test_v6_skips_inflight_meta_json(tmp_path: Path):
    run_dir = tmp_path / "pos_iv_pos_7_v6_b1b_arguzz_seed1236_n6000"
    run_dir.mkdir()
    (run_dir / "meta.json").write_text('{"exit_code":null}')
    db = run_dir / "pos_iv_pos_7_v6_b1b_arguzz_seed1236_n6000.db"
    db.write_bytes(b"")
    m = discover_dbs(tmp_path, variants=("V6",))
    assert len(m["V6"]) == 0


def test_v0_does_not_require_ok_marker(tmp_path: Path):
    db = tmp_path / "pos_iv_pos_7_u_b1a_uniform_seed1234_n6000.db"
    db.write_bytes(b"")
    m = discover_dbs(tmp_path, variants=("V0",))
    assert m["V0"][1234] == db

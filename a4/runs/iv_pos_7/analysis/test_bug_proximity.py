"""Unit tests for bug_proximity.py (D1.C Batch 1)."""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

import pytest

from .bug_proximity import (
    CONTINUOUS_TIER1_SIGNALS,
    KIND_TO_SUBSTRATEGY_FIELDS,
    NON_SATURATION_MIN_FIRE_RATE,
    ROLLING_DISCOVERY_WINDOW,
    SUBSTRATEGY_COLUMNS,
    TIER1_SIGNALS,
    TIER2_METRICS,
    TIER2_CSV_COLUMNS,
    _co_failure_graph_stats,
    _load_co_failure_graph,
    composite_substrategy_key,
    compute_correlation_matrix,
    compute_disjoint_fire_rate,
    compute_recent_marginal_discovery_rates,
    compute_tier2_metrics_row,
    d_loc_le_2_flag,
    extract_existing_channels_per_db,
    extract_tier1_signals_per_db,
    f_new_flag,
    mutation_substrategy_uniqueness,
    pearson_r,
    pro_b_wall_clock_per_normalized_discovery,
    pro_s5_co_failure_graph_degree_distribution,
    pro_s5_d_loc_distribution,
    pro_s5_proof_generated_zero_residue_rejected_rate,
    pro_s5_singleton_failure_rate,
    pro_s5_verifier_accepted_invalid_count,
    pro_s8_unique_locs_with_d_glob_le_1,
    pro_s8_unique_locs_with_d_loc_le_2,
    recent_marginal_discovery_rate,
    singleton_failure_flag,
)
from .discover import discover_dbs


def test_tier1_signals_constant_matches_spec():
    assert len(TIER1_SIGNALS) == 5
    assert "f_new_flag" in TIER1_SIGNALS
    assert "recent_marginal_discovery_rate" in CONTINUOUS_TIER1_SIGNALS


def test_tier2_metrics_declares_eight_names():
    assert len(TIER2_METRICS) == 8


def test_f_new_flag_exact_proxy_zero():
    assert f_new_flag(0.0) == 0


def test_f_new_flag_exact_proxy_small_positive():
    assert f_new_flag(0.0001) == 1


def test_f_new_flag_exact_proxy_typical_positive():
    assert f_new_flag(0.1896) == 1


def test_singleton_failure_flag_edge_cases():
    assert singleton_failure_flag(0) == 0
    assert singleton_failure_flag(1) == 1
    assert singleton_failure_flag(2) == 0


def test_d_loc_le_2_flag_boundary():
    assert d_loc_le_2_flag(2) == 1
    assert d_loc_le_2_flag(3) == 0
    assert d_loc_le_2_flag(0) == 1


def test_recent_marginal_discovery_rate_at_mut_zero():
    assert recent_marginal_discovery_rate([0]) == 0.0


def test_recent_marginal_discovery_rate_at_mut_fifty():
    bits = [0] * 50 + [1]
    assert recent_marginal_discovery_rate(bits) == pytest.approx(1 / 51)


def test_recent_marginal_discovery_rate_at_mut_hundred_full_window():
    bits = [1] * 50 + [0] * 50
    assert recent_marginal_discovery_rate(bits[-100:]) == pytest.approx(0.5)


def test_recent_marginal_discovery_rate_at_mut_six_thousand():
    bits = [0] * 5900 + [1] * 100
    rate = recent_marginal_discovery_rate(bits[-ROLLING_DISCOVERY_WINDOW :])
    assert rate == pytest.approx(1.0)


def test_compute_recent_marginal_discovery_rates_length():
    bits = [0, 1, 0, 1, 1]
    rates = compute_recent_marginal_discovery_rates(bits, window=3)
    assert len(rates) == len(bits)
    assert rates[-1] == pytest.approx(2 / 3)


def test_composite_substrategy_key_instr_word_mod_sur():
    row = {
        "opcode": 1,
        "rd": 2,
        "rs1": 3,
        "rs2": 4,
        "funct3": 5,
        "funct7": 6,
        "imm": 7,
        "byte_lane": None,
        "bit_mask": None,
        "value_class": None,
    }
    key = composite_substrategy_key("INSTR_WORD_MOD_SUR", row)
    assert key == (1, 2, 3, 4, 5, 6, 7)


def test_composite_substrategy_key_mem_val_mod():
    row = {
        "opcode": None,
        "rd": None,
        "rs1": None,
        "rs2": None,
        "funct3": None,
        "funct7": None,
        "imm": None,
        "byte_lane": 3,
        "bit_mask": 255,
        "value_class": "small",
    }
    key = composite_substrategy_key("MEM_VAL_MOD", row)
    assert key == (3, 255, "small")


def test_mutation_substrategy_uniqueness_first_only():
    seen: set = set()
    instr_row = (1, 2, 3, 4, 5, 6, 7, None, None, None)
    mem_row = (None, None, None, None, None, None, None, 1, 2, "x")
    assert mutation_substrategy_uniqueness("INSTR_WORD_MOD_SUR", instr_row, seen) == 1
    assert mutation_substrategy_uniqueness("INSTR_WORD_MOD_SUR", instr_row, seen) == 0
    assert mutation_substrategy_uniqueness("MEM_VAL_MOD", mem_row, seen) == 1
    assert mutation_substrategy_uniqueness("MEM_VAL_MOD", mem_row, seen) == 0


def test_kind_to_substrategy_fields_has_instr_and_mem():
    assert "INSTR_WORD_MOD_SUR" in KIND_TO_SUBSTRATEGY_FIELDS
    assert "MEM_VAL_MOD" in KIND_TO_SUBSTRATEGY_FIELDS
    assert "byte_lane" in KIND_TO_SUBSTRATEGY_FIELDS["MEM_VAL_MOD"]


def _make_tier2_db(path: Path, *, with_cat_b: bool = False) -> None:
    with sqlite3.connect(path) as conn:
        conn.executescript(
            """
            CREATE TABLE mutations (
                id INTEGER PRIMARY KEY,
                kind TEXT,
                verifier_accepted INTEGER,
                num_failures INTEGER,
                proof_generated INTEGER,
                proof_verify_failed INTEGER,
                elapsed_ms REAL
            );
            CREATE TABLE failures (
                mutation_id INTEGER,
                constraint_loc TEXT
            );
            CREATE TABLE mutation_rewards (
                mutation_id INTEGER PRIMARY KEY,
                d_loc INTEGER,
                d_glob INTEGER
            );
            CREATE TABLE coverage (
                constraint_loc TEXT PRIMARY KEY,
                first_hit_mutation_id INTEGER
            );
            CREATE TABLE campaign_params (selector TEXT);
            INSERT INTO campaign_params VALUES ('zoned');
            """
        )
        conn.execute(
            "INSERT INTO mutations (id, kind, verifier_accepted, num_failures) VALUES (1, 'K', 1, 2)"
        )
        conn.execute(
            "INSERT INTO mutations (id, kind, verifier_accepted, num_failures) VALUES (2, 'K', 0, 1)"
        )
        conn.execute(
            "INSERT INTO mutations (id, kind, verifier_accepted, num_failures) VALUES (3, 'K', 1, 0)"
        )
        conn.executemany(
            "INSERT INTO failures (mutation_id, constraint_loc) VALUES (?, ?)",
            [
                (1, "loc_a"),
                (1, "loc_b"),
                (2, "loc_c"),
            ],
        )
        conn.executemany(
            "INSERT INTO mutation_rewards (mutation_id, d_loc, d_glob) VALUES (?, ?, ?)",
            [(1, 2, 2), (2, 3, 2), (3, 1, 2)],
        )
        conn.executemany(
            "INSERT INTO coverage (constraint_loc, first_hit_mutation_id) VALUES (?, ?)",
            [("loc_a", 1), ("loc_b", 2), ("loc_c", 3)],
        )
        if with_cat_b:
            conn.execute(
                """
                UPDATE mutations SET proof_generated=1, proof_verify_failed=1, elapsed_ms=100.0
                WHERE id=1
                """
            )
            conn.execute(
                """
                UPDATE mutations SET proof_generated=0, proof_verify_failed=0, elapsed_ms=50.0
                WHERE id=2
                """
            )
            conn.execute(
                """
                UPDATE mutations SET proof_generated=1, proof_verify_failed=0, elapsed_ms=75.0
                WHERE id=3
                """
            )


def test_pro_s5_verifier_accepted_invalid_count_matches_d1a_spec():
    """Aligned with IV_POS_8_D1_A_SPEC.md:539 locked SQL."""
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "tier2.db"
        _make_tier2_db(db)
        with sqlite3.connect(db) as conn:
            assert pro_s5_verifier_accepted_invalid_count(conn) == 1
            direct = conn.execute(
                """
                SELECT COUNT(*) FROM mutations
                WHERE verifier_accepted=1 AND num_failures>0
                """
            ).fetchone()[0]
            assert direct == 1


def test_pro_s5_verifier_accepted_invalid_count_positive_row():
    """Direct unit test: one verifier-accepted pull with failures."""
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "verifier.db"
        with sqlite3.connect(db) as conn:
            conn.execute(
                "CREATE TABLE mutations (id INTEGER PRIMARY KEY, verifier_accepted INTEGER, num_failures INTEGER)"
            )
            conn.execute(
                "INSERT INTO mutations VALUES (1, 1, 3), (2, 1, 0), (3, 0, 2)"
            )
            assert pro_s5_verifier_accepted_invalid_count(conn) == 1


def test_co_failure_graph_empty():
    with sqlite3.connect(":memory:") as conn:
        conn.execute("CREATE TABLE failures (mutation_id INTEGER, constraint_loc TEXT)")
        assert _load_co_failure_graph(conn) == {}


def test_co_failure_graph_disconnected_components():
    with sqlite3.connect(":memory:") as conn:
        conn.executescript(
            """
            CREATE TABLE failures (mutation_id INTEGER, constraint_loc TEXT);
            INSERT INTO failures VALUES (1, 'a'), (1, 'b');
            INSERT INTO failures VALUES (2, 'c'), (2, 'd');
            """
        )
        adj = _load_co_failure_graph(conn)
        n_nodes, n_edges, density, degrees = _co_failure_graph_stats(adj)
        assert n_nodes == 4
        assert n_edges == 2
        assert density == pytest.approx(2 * 2 / (4 * 3))
        dist = pro_s5_co_failure_graph_degree_distribution(conn)
        assert dist["p95"] == 1.0


def test_co_failure_graph_single_node_no_edge():
    with sqlite3.connect(":memory:") as conn:
        conn.executescript(
            """
            CREATE TABLE failures (mutation_id INTEGER, constraint_loc TEXT);
            INSERT INTO failures VALUES (1, 'solo');
            """
        )
        dist = pro_s5_co_failure_graph_degree_distribution(conn)
        assert dist["n_nodes"] == 1
        assert dist["n_edges"] == 0
        assert dist["density"] == 0.0


def test_pro_s5_singleton_failure_rate_over_all_mutations():
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "tier2.db"
        _make_tier2_db(db)
        with sqlite3.connect(db) as conn:
            assert pro_s5_singleton_failure_rate(conn) == pytest.approx(1 / 3)


def test_pro_s5_d_loc_distribution_p95_ge_median():
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "tier2.db"
        _make_tier2_db(db)
        with sqlite3.connect(db) as conn:
            dist = pro_s5_d_loc_distribution(conn)
            assert dist["p95"] >= dist["median"]


def test_pro_s8_unique_locs_with_d_loc_le_2():
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "tier2.db"
        _make_tier2_db(db)
        with sqlite3.connect(db) as conn:
            assert pro_s8_unique_locs_with_d_loc_le_2(conn) == 2


def test_pro_s8_unique_locs_with_d_glob_le_1():
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "tier2.db"
        _make_tier2_db(db)
        with sqlite3.connect(db) as conn:
            assert pro_s8_unique_locs_with_d_glob_le_1(conn) == 0


def test_cat_b_proof_rate_none_without_proof_column_population():
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "tier2.db"
        _make_tier2_db(db, with_cat_b=False)
        with sqlite3.connect(db) as conn:
            assert pro_s5_proof_generated_zero_residue_rejected_rate(conn) is None


def test_cat_b_proof_rate_computed_when_populated():
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "tier2.db"
        _make_tier2_db(db, with_cat_b=True)
        with sqlite3.connect(db) as conn:
            conn.execute("UPDATE mutation_rewards SET d_glob=0 WHERE mutation_id=1")
            rate = pro_s5_proof_generated_zero_residue_rejected_rate(conn)
            assert rate == pytest.approx(1 / 3)


def test_cat_b_wall_clock_none_without_elapsed_ms():
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "tier2.db"
        _make_tier2_db(db, with_cat_b=False)
        with sqlite3.connect(db) as conn:
            assert pro_b_wall_clock_per_normalized_discovery(conn, db_path=db) is None


def test_cat_b_wall_clock_computed_when_populated():
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "tier2.db"
        _make_tier2_db(db, with_cat_b=True)
        with sqlite3.connect(db) as conn:
            val = pro_b_wall_clock_per_normalized_discovery(
                conn, local_context_final=3
            )
            assert val == pytest.approx((100.0 + 50.0 + 75.0) / 3 / 3)


def test_compute_tier2_metrics_row_csv_columns():
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "tier2.db"
        _make_tier2_db(db, with_cat_b=True)
        row = compute_tier2_metrics_row(db)
        for col in TIER2_CSV_COLUMNS:
            assert col in row
        assert 0.0 <= row["cat_a_pro_s5_singleton_failure_rate"] <= 1.0


def test_tier2_metrics_constant_count():
    assert len(TIER2_METRICS) == 8
    assert len(TIER2_CSV_COLUMNS) == 8


def test_pearson_r_perfect_positive():
    x = [0, 1, 0, 1, 1]
    y = [0, 1, 0, 1, 1]
    r, note = pearson_r(x, y)
    assert r == pytest.approx(1.0)
    assert note == ""


def test_pearson_r_anti_correlation():
    x = [1, 1, 1, 0, 0, 0]
    y = [0, 0, 0, 1, 1, 1]
    r, _ = pearson_r(x, y)
    assert r == pytest.approx(-1.0)


def test_pearson_r_independence_zero_variance():
    x = [1, 1, 1, 1]
    y = [0, 1, 0, 1]
    r, note = pearson_r(x, y)
    assert r == 0.0
    assert note == "zero_variance"


def test_compute_correlation_matrix_excludes_self_cell():
    signals = {
        "f_new_flag": [0, 1, 0, 1],
        "singleton_failure_flag": [1, 0, 1, 0],
    }
    channels = {
        "discovery_binary_reward": [1, 1, 0, 0],
        "f_new_flag": [0, 1, 0, 1],
    }
    matrix = compute_correlation_matrix(
        signals, channels, window=(0, 4), continuous_signals=frozenset()
    )
    assert "f_new_flag" not in matrix["f_new_flag"]
    assert "discovery_binary_reward" in matrix["f_new_flag"]


def test_compute_disjoint_fire_rate():
    signal = [0] * 3000 + [1, 0, 1, 1, 0] + [0] * 2995
    channel = [0] * 3000 + [0, 1, 1, 0, 1] + [0] * 2995
    rate = compute_disjoint_fire_rate(signal, channel, window=(3000, 3005))
    assert rate == pytest.approx(2 / 3)


def test_pro_s5_d_loc_p95_is_integer():
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "tier2.db"
        _make_tier2_db(db)
        with sqlite3.connect(db) as conn:
            dist = pro_s5_d_loc_distribution(conn)
            assert isinstance(dist["p95"], int)


def _make_mini_db(path: Path, rows: list[tuple]) -> None:
    with sqlite3.connect(path) as conn:
        conn.executescript(
            """
            CREATE TABLE mutations (id INTEGER PRIMARY KEY, kind TEXT);
            CREATE TABLE failures (mutation_id INTEGER, constraint_loc TEXT);
            CREATE TABLE mutation_rewards (mutation_id INTEGER PRIMARY KEY, d_loc INTEGER);
            CREATE TABLE reward_counterfactuals (
                mutation_id INTEGER PRIMARY KEY,
                fnew_only_reward REAL,
                discovery_binary_reward INTEGER
            );
            CREATE TABLE mutation_substrategy (
                mutation_id INTEGER PRIMARY KEY,
                opcode INTEGER, rd INTEGER, rs1 INTEGER, rs2 INTEGER,
                funct3 INTEGER, funct7 INTEGER, imm INTEGER,
                byte_lane INTEGER, bit_mask INTEGER, value_class TEXT
            );
            """
        )
        for mid, kind, fnew, disc, d_loc, fail_n, sub in rows:
            conn.execute(
                "INSERT INTO mutations (id, kind) VALUES (?, ?)", (mid, kind)
            )
            conn.execute(
                """
                INSERT INTO reward_counterfactuals
                (mutation_id, fnew_only_reward, discovery_binary_reward)
                VALUES (?, ?, ?)
                """,
                (mid, fnew, disc),
            )
            conn.execute(
                "INSERT INTO mutation_rewards (mutation_id, d_loc) VALUES (?, ?)",
                (mid, d_loc),
            )
            for _ in range(fail_n):
                conn.execute(
                    "INSERT INTO failures (mutation_id, constraint_loc) VALUES (?, ?)",
                    (mid, f"loc_{mid}_{_}"),
                )
            if sub is not None:
                conn.execute(
                    f"""
                    INSERT INTO mutation_substrategy
                    (mutation_id, {", ".join(SUBSTRATEGY_COLUMNS)})
                    VALUES (?, {", ".join("?" * len(SUBSTRATEGY_COLUMNS))})
                    """,
                    (mid, *sub),
                )


def test_extract_tier1_signals_per_db_synthetic():
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "mini.db"
        _make_mini_db(
            db,
            [
                (1, "INSTR_WORD_MOD_SUR", 0.0, 1, 2, 1, (1, 2, 3, 4, 5, 6, 7, None, None, None)),
                (2, "INSTR_WORD_MOD_SUR", 0.0001, 0, 3, 2, (1, 2, 3, 4, 5, 6, 7, None, None, None)),
                (3, "MEM_VAL_MOD", 0.1896, 1, 1, 0, (None, None, None, None, None, None, None, 1, 2, "a")),
            ],
        )
        signals = extract_tier1_signals_per_db(db)
        for name in TIER1_SIGNALS:
            assert len(signals[name]) == 3
        assert signals["f_new_flag"] == [0, 1, 1]
        assert signals["singleton_failure_flag"] == [1, 0, 0]
        assert signals["d_loc_le_2_flag"] == [1, 0, 1]
        assert signals["mutation_substrategy_uniqueness"] == [1, 0, 1]


@pytest.fixture(scope="module")
def sample_v5_db() -> Path:
    return discover_dbs()["V5"][1234]


def test_extract_existing_channels_per_db_integration(sample_v5_db: Path):
    channels = extract_existing_channels_per_db(sample_v5_db)
    assert set(channels) == {"discovery_binary_reward", "f_new_flag"}
    n = len(channels["discovery_binary_reward"])
    assert n == len(channels["f_new_flag"]) == 6000
    assert all(v in (0, 1) for v in channels["discovery_binary_reward"])
    assert all(v in (0, 1) for v in channels["f_new_flag"])


def test_extract_tier1_signals_per_db_integration(sample_v5_db: Path):
    signals = extract_tier1_signals_per_db(sample_v5_db)
    n = 6000
    for name in TIER1_SIGNALS:
        assert len(signals[name]) == n
    # f_new_flag proxy consistency on real DB
    channels = extract_existing_channels_per_db(sample_v5_db)
    assert signals["f_new_flag"] == channels["f_new_flag"]
    # recent_marginal_discovery_rate is continuous in [0, 1]
    rates = signals["recent_marginal_discovery_rate"]
    assert all(0.0 <= r <= 1.0 for r in rates)
    assert rates[0] == pytest.approx(float(channels["discovery_binary_reward"][0]))

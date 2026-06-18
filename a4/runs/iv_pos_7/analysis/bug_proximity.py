"""D1.C bug-proximity Tier-1 signal extractors (analysis-only).

Per IV_POS_8_D1_C_SPEC.md v0.3. Does NOT modify production code.
"""

from __future__ import annotations

import sqlite3
from collections import defaultdict
from pathlib import Path
from statistics import median
from typing import Any, Optional

import numpy as np

from .metrics import compute_metrics_for_db

TIER1_SIGNALS = (
    "f_new_flag",
    "recent_marginal_discovery_rate",
    "singleton_failure_flag",
    "mutation_substrategy_uniqueness",
    "d_loc_le_2_flag",
)

TIER2_METRICS = (
    "pro_s5_verifier_accepted_invalid_count",
    "pro_s5_co_failure_graph_degree_p95",
    "pro_s5_singleton_failure_rate",
    "pro_s5_d_loc_p95",
    "pro_s8_unique_locs_with_d_loc_le_2",
    "pro_s8_unique_locs_with_d_glob_le_1",
    "pro_s5_proof_generated_zero_residue_rejected_rate",
    "pro_b_wall_clock_per_normalized_discovery",
)

CORRELATION_THRESHOLD = 0.4
NON_SATURATION_WINDOW = (3000, 6000)
NON_SATURATION_MIN_FIRE_RATE = 0.05
ROLLING_DISCOVERY_WINDOW = 100

SUBSTRATEGY_COLUMNS = (
    "opcode",
    "rd",
    "rs1",
    "rs2",
    "funct3",
    "funct7",
    "imm",
    "byte_lane",
    "bit_mask",
    "value_class",
)

# Empirically derived from 30-DB Cat-A corpus (build_substrategy_field_audit.py).
# INSTR_TYPE_MOD rows exist but all substrategy columns are NULL — empty tuple.
KIND_TO_SUBSTRATEGY_FIELDS: dict[str, tuple[str, ...]] = {
    "COMP_OUT_MOD": ("value_class",),
    "INSTR_TYPE_MOD": (),
    "INSTR_WORD_MOD_FULL": ("opcode", "rd", "rs1", "rs2", "funct3", "funct7", "imm"),
    "INSTR_WORD_MOD_SUR": ("opcode", "rd", "rs1", "rs2", "funct3", "funct7", "imm"),
    "LOAD_VAL_MOD": ("value_class",),
    "MEM_VAL_MOD": ("byte_lane", "bit_mask", "value_class"),
    "PRE_EXEC_REG_MOD": ("value_class",),
    "STORE_OUT_MOD": ("value_class",),
}

CONTINUOUS_TIER1_SIGNALS = frozenset({"recent_marginal_discovery_rate"})

TIER2_CSV_COLUMNS = (
    "cat_a_pro_s5_verifier_accepted_invalid_count",
    "cat_a_pro_s5_co_failure_graph_degree_p95",
    "cat_a_pro_s5_singleton_failure_rate",
    "cat_a_pro_s5_d_loc_p95",
    "cat_a_pro_s8_unique_locs_with_d_loc_le_2",
    "cat_a_pro_s8_unique_locs_with_d_glob_le_1",
    "cat_b_pro_s5_proof_generated_zero_residue_rejected_rate",
    "cat_b_pro_b_wall_clock_per_normalized_discovery",
)

_BATCH2_MSG = "Batch 2 — see IV_POS_8_D1_C_SPEC.md §2.2"


def _percentile(values: list[int | float], pct: float) -> float:
    if not values:
        return 0.0
    return float(np.percentile(values, pct))


def _mutations_has_column(conn: sqlite3.Connection, column: str) -> bool:
    cols = {row[1] for row in conn.execute("PRAGMA table_info(mutations)")}
    return column in cols


def _mutations_column_populated(conn: sqlite3.Connection, column: str) -> bool:
    if not _mutations_has_column(conn, column):
        return False
    row = conn.execute(
        f"SELECT COUNT(*) FROM mutations WHERE {column} IS NOT NULL"
    ).fetchone()
    return bool(row and row[0] > 0)


def _load_co_failure_graph(conn: sqlite3.Connection) -> dict[str, set[str]]:
    """Return adj[constraint_loc] = {co-failing constraint_locs across the campaign}."""
    grouped: dict[int, list[str]] = defaultdict(list)
    for mid, loc in conn.execute(
        "SELECT mutation_id, constraint_loc FROM failures"
    ):
        grouped[int(mid)].append(str(loc))
    adj: dict[str, set[str]] = defaultdict(set)
    all_locs: set[str] = set()
    for locs in grouped.values():
        all_locs.update(locs)
    for loc in all_locs:
        adj.setdefault(loc, set())
    for locs in grouped.values():
        for i in range(len(locs)):
            for j in range(i + 1, len(locs)):
                adj[locs[i]].add(locs[j])
                adj[locs[j]].add(locs[i])
    return dict(adj)


def _co_failure_graph_stats(
    adj: dict[str, set[str]],
) -> tuple[int, int, float, list[int]]:
    """Return (n_nodes, n_edges, density, degree_list)."""
    nodes = set(adj.keys())
    for neighbors in adj.values():
        nodes.update(neighbors)
    n_nodes = len(nodes)
    if n_nodes == 0:
        return 0, 0, 0.0, []
    n_edges = sum(len(v) for v in adj.values()) // 2
    density = (
        0.0
        if n_nodes <= 1
        else (2.0 * n_edges) / (n_nodes * (n_nodes - 1))
    )
    degrees = [len(adj.get(node, set())) for node in nodes]
    return n_nodes, n_edges, density, degrees


def f_new_flag(fnew_only_reward: float) -> int:
    """Cat-A. Exact proxy for f_new >= 1. See §1.4.

    fnew_only_reward = 0.30 * sat(f_new, 1.0); fnew_only_reward > 0 iff f_new >= 1.
    Cost: O(1) per pull. Source: reward_counterfactuals.fnew_only_reward.
    Pro Report 3 §8 (f_new channel).
    """
    return 1 if fnew_only_reward > 0.0 else 0


def recent_marginal_discovery_rate(
    rolling_discovery_bits: list[int],
    window: int = ROLLING_DISCOVERY_WINDOW,
) -> float:
    """Cat-A. Rolling fraction of pulls in the trailing window that discovered something.

    Defined on reward_counterfactuals.discovery_binary_reward (=
    compute_bandit_success(l_new, g_new, s_new), the OR of l+g+s) per §1.4
    Option A. NOT the integer sum of l_new+g_new+s_new (which would require
    Option C replay).

    SEMANTICS (Composer audit pushback B): this is a 'discovery momentum'
    or 'smoothed bandit-success rate' signal, NOT a strong-orthogonality
    candidate. A rolling mean of a binary signal correlates highly with
    its instantaneous bit BY CONSTRUCTION (Pearson r tends to be O(0.4-0.7)
    on stationary stretches). We include it because (i) it may still
    discriminate the post-saturation regime if discovery_binary_reward goes
    from 'fires every pull' to 'fires occasionally' as the campaign saturates
    (timing detector for the saturation boundary itself), and (ii) it could
    be useful as a continuous-valued signal in a future scalar bandit
    (NFP-9) even if it fails the binary ortho gate in §1.3.3. The shortlist
    rationale template in Batch 3 explicitly handles 'rejected for ortho
    failure but kept as scalar-bandit candidate' as a distinct deferred
    category.

    ``rolling_discovery_bits`` is the trailing window slice (up to ``window``
    most recent discovery_binary_reward bits, including the current pull).

    Returns float in [0, 1]. Cost: O(1) amortized per pull with a deque.
    Source: reward_counterfactuals.discovery_binary_reward.
    """
    if not rolling_discovery_bits:
        return 0.0
    bits = rolling_discovery_bits[-window:]
    return sum(bits) / len(bits)


def singleton_failure_flag(failures_count_for_mid: int) -> int:
    """Cat-A. 1 iff exactly one constraint_loc broke this pull.

    Source: SELECT COUNT(*) FROM failures WHERE mutation_id=?;
    Cost: O(1) with pre-grouped index. Pro Report 3 §5.
    """
    return 1 if failures_count_for_mid == 1 else 0


def composite_substrategy_key(kind: str, row: dict[str, Any]) -> tuple[Any, ...]:
    """Return a hashable composite key from non-null kind-specific fields.

    Per coverage_db.py:351-354 comment: 'For INSTR_WORD_MOD_SUR this captures
    funct3/funct7/etc.; for MEM_VAL_MOD: byte_lane; etc. All fields nullable
    since each kind populates only its own.'

    Uses KIND_TO_SUBSTRATEGY_FIELDS (empirically derived on 30-DB corpus).
    """
    fields = KIND_TO_SUBSTRATEGY_FIELDS.get(kind)
    if fields is None:
        fields = tuple(
            c for c in SUBSTRATEGY_COLUMNS if row.get(c) is not None
        )
    return tuple(row.get(f) for f in fields)


def mutation_substrategy_uniqueness(
    kind: str,
    substrategy_row: tuple[Any, ...],
    seen_composite_keys: set[tuple[str, tuple[Any, ...]]],
) -> int:
    """Cat-A. 1 iff this is the first occurrence of (kind, composite_key).

    composite_key = tuple of non-null kind-specific column values. Caller
    constructs this from the row tuple by filtering NULLs (kind-specific:
    INSTR_WORD_MOD_SUR uses opcode+funct3+funct7+rd+rs1+rs2+imm; MEM_VAL_MOD
    uses byte_lane+bit_mask+value_class; etc.). Helper:
      composite_substrategy_key(kind, row) -> tuple
    Cost: O(1) per pull (set membership). Pro Report 3 §5.
    """
    row_dict = dict(zip(SUBSTRATEGY_COLUMNS, substrategy_row))
    comp = composite_substrategy_key(kind, row_dict)
    key = (kind, comp)
    if key in seen_composite_keys:
        return 0
    seen_composite_keys.add(key)
    return 1


def d_loc_le_2_flag(d_loc: int) -> int:
    """Cat-A. 1 iff mutation_rewards.d_loc <= 2 (Pro Report 3 §8).

    Substituted for revisit plan §3.2's 'sliding-window d_loc rate' (per-pull
    threshold flag is simpler/cheaper; sliding-window variant deferred to
    D1.C v2 if Batch 3 cross-correlation shows the flag underperforms).
    Source: mutation_rewards.d_loc. Cost: O(1) per pull.
    """
    return 1 if d_loc <= 2 else 0


def discretize_continuous_signal(value: float, threshold: float) -> int:
    """Return 1 if continuous Tier-1 signal meets fire threshold (§1.3.2)."""
    return 1 if value >= threshold else 0


def _substrategy_row_from_tuple(row: Optional[tuple[Any, ...]]) -> tuple[Any, ...]:
    if row is None:
        return tuple(None for _ in SUBSTRATEGY_COLUMNS)
    return row


def compute_recent_marginal_discovery_rates(
    discovery_bits: list[int],
    window: int = ROLLING_DISCOVERY_WINDOW,
) -> list[float]:
    """Per-pull rolling mean of discovery_binary_reward."""
    out: list[float] = []
    for i in range(len(discovery_bits)):
        start = max(0, i - window + 1)
        out.append(recent_marginal_discovery_rate(discovery_bits[start : i + 1], window))
    return out


def extract_existing_channels_per_db(db_path: Path) -> dict[str, list[int]]:
    """Return per-mutation existing-channel signals (length N_mutations).

    Output keys:
      discovery_binary_reward  -> int 0/1   (from reward_counterfactuals)
      f_new_flag               -> int 0/1   (derived: fnew_only_reward > 0)

    Replay (Option C per §1.4) is deferred to Batch 1.5 if needed.
    """
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT rc.discovery_binary_reward, rc.fnew_only_reward
            FROM mutations m
            LEFT JOIN reward_counterfactuals rc ON rc.mutation_id = m.id
            ORDER BY m.id
            """
        ).fetchall()

    discovery: list[int] = []
    fnew: list[int] = []
    for disc, fnew_reward in rows:
        discovery.append(int(disc or 0))
        fnew.append(f_new_flag(float(fnew_reward or 0.0)))
    return {
        "discovery_binary_reward": discovery,
        "f_new_flag": fnew,
    }


def extract_tier1_signals_per_db(db_path: Path) -> dict[str, list[int | float]]:
    """Return per-mutation Tier-1 signals for the DB (length N_mutations per signal)."""
    with sqlite3.connect(db_path) as conn:
        mutation_rows = conn.execute(
            "SELECT id, kind FROM mutations ORDER BY id"
        ).fetchall()
        n = len(mutation_rows)
        if n == 0:
            return {name: [] for name in TIER1_SIGNALS}

        failure_counts: dict[int, int] = defaultdict(int)
        for mid, _ in conn.execute(
            "SELECT mutation_id, COUNT(*) FROM failures GROUP BY mutation_id"
        ):
            failure_counts[int(mid)] = int(_)

        d_loc_by_mid: dict[int, int] = {}
        for mid, d_loc in conn.execute(
            "SELECT mutation_id, d_loc FROM mutation_rewards"
        ):
            d_loc_by_mid[int(mid)] = int(d_loc)

        rc_by_mid: dict[int, tuple[float, int]] = {}
        for mid, fnew, disc in conn.execute(
            """
            SELECT mutation_id, fnew_only_reward, discovery_binary_reward
            FROM reward_counterfactuals
            """
        ):
            rc_by_mid[int(mid)] = (float(fnew), int(disc))

        substrategy_by_mid: dict[int, tuple[Any, ...]] = {}
        for row in conn.execute(
            f"""
            SELECT mutation_id, {", ".join(SUBSTRATEGY_COLUMNS)}
            FROM mutation_substrategy
            """
        ):
            substrategy_by_mid[int(row[0])] = tuple(row[1:])

    discovery_bits: list[int] = []
    fnew_flags: list[int] = []
    singleton_flags: list[int] = []
    dloc_flags: list[int] = []
    substrategy_unique: list[int] = []
    seen_keys: set[tuple[str, tuple[Any, ...]]] = set()

    for mid, kind in mutation_rows:
        mid = int(mid)
        fnew_reward, disc = rc_by_mid.get(mid, (0.0, 0))
        discovery_bits.append(int(disc))
        fnew_flags.append(f_new_flag(fnew_reward))
        singleton_flags.append(singleton_failure_flag(failure_counts.get(mid, 0)))
        dloc_flags.append(d_loc_le_2_flag(d_loc_by_mid.get(mid, 0)))
        sub_row = _substrategy_row_from_tuple(substrategy_by_mid.get(mid))
        substrategy_unique.append(
            mutation_substrategy_uniqueness(kind, sub_row, seen_keys)
        )

    marginal_rates = compute_recent_marginal_discovery_rates(discovery_bits)

    return {
        "f_new_flag": fnew_flags,
        "recent_marginal_discovery_rate": marginal_rates,
        "singleton_failure_flag": singleton_flags,
        "mutation_substrategy_uniqueness": substrategy_unique,
        "d_loc_le_2_flag": dloc_flags,
    }


def fire_rate(
    signal: list[int | float],
    window: tuple[int, int],
    *,
    is_continuous: bool = False,
    threshold: float = NON_SATURATION_MIN_FIRE_RATE,
) -> float:
    """Fraction of pulls in [window[0], window[1]) where signal fires."""
    lo, hi = window
    if hi <= lo:
        return 0.0
    slice_ = signal[lo:hi]
    if not slice_:
        return 0.0
    if is_continuous:
        fires = sum(1 for v in slice_ if v >= threshold)
    else:
        fires = sum(1 for v in slice_ if v == 1)
    return fires / len(slice_)


# --- Tier-2 per-campaign metrics (Batch 2) ---


def pro_s5_verifier_accepted_invalid_count(conn: sqlite3.Connection) -> int:
    """Cat-A. ALIGNED with IV_POS_8_D1_A_SPEC.md:539 locked SQL:
      SELECT COUNT(*) FROM mutations WHERE verifier_accepted=1 AND num_failures>0
    Pro §5 framing: 'mutations where verifier said yes but failures existed.'
    Source: mutations.verifier_accepted, mutations.num_failures.
    Cost: O(1) indexed scan. Returns int.
    """
    row = conn.execute(
        """
        SELECT COUNT(*) FROM mutations
        WHERE verifier_accepted = 1 AND num_failures > 0
        """
    ).fetchone()
    return int(row[0] if row else 0)


def pro_s5_co_failure_graph_degree_distribution(conn: sqlite3.Connection) -> dict:
    """Cat-A. Co-failure graph degree distribution (Pro Report 3 §5).

    Builds graph once via _load_co_failure_graph. Returns
    {mean, median, p95, p99, density, n_nodes, n_edges}.
    Cost: moderate — O(pulls × avg_failures²) per DB.
    """
    adj = _load_co_failure_graph(conn)
    n_nodes, n_edges, density, degrees = _co_failure_graph_stats(adj)
    if not degrees:
        return {
            "mean": 0.0,
            "median": 0.0,
            "p95": 0.0,
            "p99": 0.0,
            "density": 0.0,
            "n_nodes": n_nodes,
            "n_edges": n_edges,
        }
    return {
        "mean": float(sum(degrees) / len(degrees)),
        "median": float(median(degrees)),
        "p95": _percentile(degrees, 95),
        "p99": _percentile(degrees, 99),
        "density": density,
        "n_nodes": n_nodes,
        "n_edges": n_edges,
    }


def pro_s5_singleton_failure_rate(conn: sqlite3.Connection) -> float:
    """Cat-A. Fraction of mutations where exactly one constraint_loc broke.

    Source: failures grouped by mutation_id vs mutations row count.
    Cost: O(1) with index. Pro Report 3 §5. Returns float in [0, 1].
    """
    n_mut = int(conn.execute("SELECT COUNT(*) FROM mutations").fetchone()[0])
    if n_mut == 0:
        return 0.0
    n_singleton = int(
        conn.execute(
            """
            SELECT COUNT(*) FROM (
                SELECT mutation_id FROM failures
                GROUP BY mutation_id
                HAVING COUNT(*) = 1
            )
            """
        ).fetchone()[0]
    )
    return n_singleton / n_mut


def pro_s5_d_loc_distribution(conn: sqlite3.Connection) -> dict:
    """Cat-A. {mean, median, p95, p99} of mutation_rewards.d_loc.

    Source: mutation_rewards.d_loc. Pro Report 3 §5 / §8.
    Cost: O(N) single pass. Returns dict.
    """
    d_locs = [int(r[0]) for r in conn.execute("SELECT d_loc FROM mutation_rewards")]
    if not d_locs:
        return {"mean": 0.0, "median": 0.0, "p95": 0.0, "p99": 0.0}
    return {
        "mean": float(sum(d_locs) / len(d_locs)),
        "median": float(median(d_locs)),
        "p95": int(round(_percentile(d_locs, 95))),
        "p99": int(round(_percentile(d_locs, 99))),
    }


def pro_s8_unique_locs_with_d_loc_le_2(conn: sqlite3.Connection) -> int:
    """Cat-A. Distinct constraint_loc ever seen with d_loc <= 2 (Pro Report 3 §8).

    Source: failures JOIN mutation_rewards. Cost: O(N). Returns int.
    """
    row = conn.execute(
        """
        SELECT COUNT(DISTINCT f.constraint_loc)
        FROM failures f
        JOIN mutation_rewards mr ON mr.mutation_id = f.mutation_id
        WHERE mr.d_loc <= 2
        """
    ).fetchone()
    return int(row[0] if row else 0)


def pro_s8_unique_locs_with_d_glob_le_1(conn: sqlite3.Connection) -> int:
    """Cat-A. Distinct constraint_loc ever seen with d_glob <= 1 (Pro Report 3 §8).

    Paired with pro_s8_unique_locs_with_d_loc_le_2 per ProG_Report_3.md:163.
    Source: failures JOIN mutation_rewards. Cost: O(N). Returns int.
    """
    row = conn.execute(
        """
        SELECT COUNT(DISTINCT f.constraint_loc)
        FROM failures f
        JOIN mutation_rewards mr ON mr.mutation_id = f.mutation_id
        WHERE mr.d_glob <= 1
        """
    ).fetchone()
    return int(row[0] if row else 0)


def pro_s5_proof_generated_zero_residue_rejected_rate(
    conn: sqlite3.Connection,
) -> Optional[float]:
    """Cat-B. Fraction of mutations where proof_generated=1, d_glob=0, proof_verify_failed=1.

    Uses d_glob=0 as 'family_residues all zero' heuristic per spec §2.2.
    Source: mutations + mutation_rewards. Returns None if proof_generated
    column is NULL on R2 DBs. Pro Report 3 §5.
    """
    if not _mutations_column_populated(conn, "proof_generated"):
        return None
    row = conn.execute(
        """
        SELECT
            SUM(CASE
                WHEN m.proof_generated = 1
                 AND mr.d_glob = 0
                 AND m.proof_verify_failed = 1
                THEN 1 ELSE 0 END) * 1.0 / COUNT(*) AS rate
        FROM mutations m
        JOIN mutation_rewards mr ON mr.mutation_id = m.id
        """
    ).fetchone()
    return float(row[0]) if row and row[0] is not None else None


def pro_b_wall_clock_per_normalized_discovery(
    conn: sqlite3.Connection,
    *,
    db_path: Optional[Path] = None,
    local_context_final: Optional[int] = None,
) -> Optional[float]:
    """Cat-B. mean(elapsed_ms) / local_context_final per revisit plan :160.

    Source: mutations.elapsed_ms + local_context_final from metrics.py.
    Returns None if elapsed_ms column is NULL (R2 DBs).
    """
    if not _mutations_column_populated(conn, "elapsed_ms"):
        return None
    row = conn.execute(
        "SELECT AVG(elapsed_ms) FROM mutations WHERE elapsed_ms IS NOT NULL"
    ).fetchone()
    mean_elapsed = float(row[0]) if row and row[0] is not None else None
    if mean_elapsed is None:
        return None
    if local_context_final is None:
        if db_path is None:
            raise ValueError("db_path or local_context_final required")
        local_context_final = int(
            compute_metrics_for_db(db_path)["local_context_final"]
        )
    if local_context_final == 0:
        return None
    return mean_elapsed / local_context_final


def _read_local_context_final(conn: sqlite3.Connection, db_path: Path) -> int:
    try:
        return int(compute_metrics_for_db(db_path)["local_context_final"])
    except ValueError:
        row = conn.execute("SELECT COUNT(*) FROM coverage").fetchone()
        return int(row[0] if row else 0)


def compute_tier2_metrics_row(
    db_path: Path,
    *,
    conn: Optional[sqlite3.Connection] = None,
) -> dict[str, Optional[float | int]]:
    """Compute all 8 Tier-2 metrics flattened to D2.G CSV column names."""
    own_conn = conn is None
    if own_conn:
        conn = sqlite3.connect(db_path)
    try:
        local_final = _read_local_context_final(conn, db_path)
        cofail = pro_s5_co_failure_graph_degree_distribution(conn)
        dloc = pro_s5_d_loc_distribution(conn)
        return {
            "cat_a_pro_s5_verifier_accepted_invalid_count": (
                pro_s5_verifier_accepted_invalid_count(conn)
            ),
            "cat_a_pro_s5_co_failure_graph_degree_p95": cofail["p95"],
            "cat_a_pro_s5_singleton_failure_rate": (
                pro_s5_singleton_failure_rate(conn)
            ),
            "cat_a_pro_s5_d_loc_p95": int(dloc["p95"]),
            "cat_a_pro_s8_unique_locs_with_d_loc_le_2": (
                pro_s8_unique_locs_with_d_loc_le_2(conn)
            ),
            "cat_a_pro_s8_unique_locs_with_d_glob_le_1": (
                pro_s8_unique_locs_with_d_glob_le_1(conn)
            ),
            "cat_b_pro_s5_proof_generated_zero_residue_rejected_rate": (
                pro_s5_proof_generated_zero_residue_rejected_rate(conn)
            ),
            "cat_b_pro_b_wall_clock_per_normalized_discovery": (
                pro_b_wall_clock_per_normalized_discovery(
                    conn,
                    db_path=db_path,
                    local_context_final=local_final,
                )
            ),
            "_local_context_final": local_final,
            "_co_failure_graph_n_nodes": cofail["n_nodes"],
            "_co_failure_graph_n_edges": cofail["n_edges"],
            "_co_failure_graph_density": cofail["density"],
            "_d_loc_median": dloc["median"],
        }
    finally:
        if own_conn and conn is not None:
            conn.close()


def _slice_window(
    values: list[int | float],
    window: tuple[int, int] = NON_SATURATION_WINDOW,
) -> list[int | float]:
    lo, hi = window
    return values[lo:hi]


def pearson_r(x: list[int | float], y: list[int | float]) -> tuple[float, str]:
    """Pearson correlation with zero-variance guard."""
    if len(x) != len(y) or len(x) < 2:
        return 0.0, "insufficient_length"
    import math

    mx = sum(x) / len(x)
    my = sum(y) / len(y)
    vx = sum((float(v) - mx) ** 2 for v in x)
    vy = sum((float(v) - my) ** 2 for v in y)
    if vx == 0.0 or vy == 0.0:
        return 0.0, "zero_variance"
    cov = sum((float(a) - mx) * (float(b) - my) for a, b in zip(x, y))
    return cov / math.sqrt(vx * vy), ""


def compute_disjoint_fire_rate(
    signal: list[int | float],
    channel: list[int],
    *,
    window: tuple[int, int] = NON_SATURATION_WINDOW,
    continuous_threshold: float = NON_SATURATION_MIN_FIRE_RATE,
    is_continuous: bool = False,
) -> float:
    """Fraction of signal fires where channel is 0 (§1.3.3)."""
    sig = _slice_window(signal, window)
    ch = _slice_window(channel, window)
    fires = 0
    disjoint = 0
    for s, c in zip(sig, ch):
        fired = (
            float(s) >= continuous_threshold
            if is_continuous
            else int(s) == 1
        )
        if fired:
            fires += 1
            if int(c) == 0:
                disjoint += 1
    return disjoint / fires if fires else 0.0


def compute_correlation_matrix(
    signals_per_mutation: dict[str, list[int | float]],
    existing_channels: dict[str, list[int]],
    *,
    window: tuple[int, int] = NON_SATURATION_WINDOW,
    continuous_signals: frozenset[str] = CONTINUOUS_TIER1_SIGNALS,
    continuous_threshold: float = NON_SATURATION_MIN_FIRE_RATE,
) -> dict[str, dict[str, float]]:
    """Pearson r matrix for post-local window; excludes trivial self-pairs.

    Continuous Tier-1 signals (``recent_marginal_discovery_rate``) are
    discretized at ``continuous_threshold`` (default 0.05, same as the
    non-saturation fire gate) before Pearson r is computed. Binary signals
    use raw ``{0, 1}`` values.
    """
    out: dict[str, dict[str, float]] = {}
    for sig_name, sig_vals in signals_per_mutation.items():
        out[sig_name] = {}
        sig_slice = _slice_window(sig_vals, window)
        is_cont = sig_name in continuous_signals
        if is_cont:
            sig_for_r = [
                1 if float(v) >= continuous_threshold else 0 for v in sig_slice
            ]
        else:
            sig_for_r = [int(v) for v in sig_slice]
        for ch_name, ch_vals in existing_channels.items():
            if sig_name == "f_new_flag" and ch_name == "f_new_flag":
                continue
            ch_slice = [int(v) for v in _slice_window(ch_vals, window)]
            r, _ = pearson_r(sig_for_r, ch_slice)
            out[sig_name][ch_name] = r
    return out

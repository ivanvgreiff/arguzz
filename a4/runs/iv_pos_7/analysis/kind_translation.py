"""V6-vs-A4 kind decomposition — shared, A4-only, V6-only kind sets."""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Set

import pandas as pd

from .discover import ALL_VARIANTS_ORDER, discover_dbs

SHARED_KINDS: tuple[str, ...] = (
    "COMP_OUT_MOD",
    "LOAD_VAL_MOD",
    "STORE_OUT_MOD",
    "PRE_EXEC_REG_MOD",
)
A4_ONLY_KINDS: tuple[str, ...] = (
    "INSTR_TYPE_MOD",
    "MEM_VAL_MOD",
    "INSTR_WORD_MOD_FULL",
    "INSTR_WORD_MOD_SUR",
)
V6_ONLY_KINDS: tuple[str, ...] = (
    "PRE_EXEC_PC_MOD",
    "POST_EXEC_PC_MOD",
    "POST_EXEC_REG_MOD",
    "PRE_EXEC_MEM_MOD",
    "POST_EXEC_MEM_MOD",
    "INSTR_WORD_MOD",
    "BR_NEG_COND",
)

KIND_GROUPS: Dict[str, str] = {}
for k in SHARED_KINDS:
    KIND_GROUPS[k] = "shared"
for k in A4_ONLY_KINDS:
    KIND_GROUPS[k] = "a4_only"
for k in V6_ONLY_KINDS:
    KIND_GROUPS[k] = "v6_only"

INTERNAL_VARIANTS = ("V0", "V1", "V5", "V6")


def _kind_stats_for_db(db_path: Path) -> Dict[str, Dict[str, int]]:
    pulls: Dict[str, int] = {}
    discoveries: Dict[str, int] = {}
    with sqlite3.connect(db_path) as conn:
        for kind, n in conn.execute(
            "SELECT kind, COUNT(*) FROM mutations GROUP BY kind"
        ):
            pulls[kind] = int(n)
        for _loc, mid in conn.execute(
            "SELECT constraint_loc, first_hit_mutation_id FROM coverage"
        ):
            row = conn.execute(
                "SELECT kind FROM mutations WHERE id = ?", (mid,)
            ).fetchone()
            if row:
                k = row[0]
                discoveries[k] = discoveries.get(k, 0) + 1
    return {"pulls": pulls, "discoveries": discoveries}


def kind_translation_frame(
    dbs_root: Optional[Path] = None,
    variants: tuple[str, ...] = INTERNAL_VARIANTS,
) -> pd.DataFrame:
    """Per (variant, seed, kind): pulls, discoveries, rate, kind_group."""
    mapping = discover_dbs(dbs_root, variants=variants) if dbs_root else discover_dbs(variants=variants)
    rows: List[dict] = []
    for variant in variants:
        for seed, db in sorted(mapping.get(variant, {}).items()):
            stats = _kind_stats_for_db(db)
            all_kinds: Set[str] = set(stats["pulls"]) | set(stats["discoveries"])
            for kind in sorted(all_kinds):
                pulls = stats["pulls"].get(kind, 0)
                disc = stats["discoveries"].get(kind, 0)
                rate = (1000.0 * disc / pulls) if pulls else float("nan")
                rows.append({
                    "variant": variant,
                    "seed": seed,
                    "kind": kind,
                    "kind_group": KIND_GROUPS.get(kind, "other"),
                    "pulls": pulls,
                    "discoveries": disc,
                    "discovery_rate_per_1k": rate,
                })
    return pd.DataFrame(rows)


def kind_translation_summary(df: pd.DataFrame) -> pd.DataFrame:
    """Pool pulls/discoveries per (variant, kind) across seeds."""
    if df.empty:
        return df
    agg = (
        df.groupby(["variant", "kind", "kind_group"])[["pulls", "discoveries"]]
        .sum()
        .reset_index()
    )
    agg["discovery_rate_per_1k"] = agg.apply(
        lambda r: (1000.0 * r["discoveries"] / r["pulls"]) if r["pulls"] else float("nan"),
        axis=1,
    )
    return agg.sort_values(["variant", "kind_group", "kind"]).reset_index(drop=True)


def shared_kind_comparison(df: pd.DataFrame) -> pd.DataFrame:
    """Shared-kind rows only — apples-to-apples discovery rates."""
    return df[df["kind_group"] == "shared"].copy()


def kind_set_inventory(df: pd.DataFrame) -> pd.DataFrame:
    """One row per kind_group with kind lists and total pulls per variant."""
    rows: List[dict] = []
    for variant in df["variant"].unique():
        sub = df[df["variant"] == variant]
        for group in ("shared", "a4_only", "v6_only", "other"):
            gsub = sub[sub["kind_group"] == group]
            if gsub.empty and group != "shared":
                continue
            rows.append({
                "variant": variant,
                "kind_group": group,
                "kinds": ";".join(sorted(gsub["kind"].unique())),
                "total_pulls": int(gsub["pulls"].sum()),
                "total_discoveries": int(gsub["discoveries"].sum()),
            })
    return pd.DataFrame(rows)

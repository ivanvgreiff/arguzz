#!/usr/bin/env python3
"""D2.F — manifest generator unit tests (local, no POS)."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

import pytest

from a4.pos.generate_d2f_manifests import (
    DEFAULT_NODES,
    SMOKE_SEEDS,
    make_production_rows,
    make_smoke_rows,
    remote_cmd,
    run_id,
)
from a4.standalone.variants import CANONICAL_VARIANTS, variant_launch_command


def _parse_rows(rows):
    return [(b, n, r, c) for b, n, r, c in rows]


class TestManifestGenerator:
    def test_smoke_has_eight_jobs_one_per_node(self):
        rows = _parse_rows(make_smoke_rows())
        assert len(rows) == 8
        nodes = [r[1] for r in rows]
        assert len(set(nodes)) == 8
        assert set(nodes) == set(DEFAULT_NODES)

    def test_smoke_covers_all_variants_and_two_seeds(self):
        rows = _parse_rows(make_smoke_rows())
        variants = set()
        seeds = set()
        for _, _, rid, _ in rows:
            m = re.match(
                r"pos_iv_pos_8_d2f_(.+)_seed(\d+)_n(\d+)", rid,
            )
            assert m
            variants.add(m.group(1))
            seeds.add(int(m.group(2)))
            assert int(m.group(3)) == 100
        assert variants == set(CANONICAL_VARIANTS)
        assert seeds == set(SMOKE_SEEDS)

    def test_production_two_batches_for_r3(self):
        rows = _parse_rows(make_production_rows((1234, 1235, 1236)))
        assert len(rows) == 12
        batches = Counter(r[0] for r in rows)
        assert batches["d2f_prod_b1"] == 8
        assert batches["d2f_prod_b2"] == 4
        b2_nodes = [r[1] for r in rows if r[0] == "d2f_prod_b2"]
        assert len(b2_nodes) == len(set(b2_nodes))

    def test_no_two_concurrent_jobs_on_same_node_per_batch(self):
        for rows_fn in (
            lambda: make_smoke_rows(),
            lambda: make_production_rows((1234, 1235, 1236)),
        ):
            rows = _parse_rows(rows_fn())
            by_batch: dict[str, list[str]] = {}
            for batch, node, _, _ in rows:
                by_batch.setdefault(batch, []).append(node)
            for batch, nodes in by_batch.items():
                assert len(nodes) == len(set(nodes)), f"duplicate node in {batch}"

    def test_remote_cmd_matches_variants_registry(self):
        for name in CANONICAL_VARIANTS:
            rid = run_id(name, 4242, 50)
            cmd = remote_cmd(name, 4242, 50, rid)
            ref = variant_launch_command(
                name,
                host="/root/a4_campaign/bin/risc0-host",
                db=f"/tmp/chainjob_{rid}/run.db",
                seed=4242,
                num=50,
                host_args=["--in1", "5", "--in4", "10"],
            )
            for token in ref:
                assert token in cmd, f"{name}: missing {token!r} in remote_cmd"
            assert "A4_COVERAGE_TOUCH=1" in cmd
            assert "A4_FAMILY_RESIDUE=1" in cmd
            if CANONICAL_VARIANTS[name].launcher == "cli":
                assert "A4_GLOBAL_RESIDUE=1" in cmd
                assert "--telemetry-level" in cmd
                assert CANONICAL_VARIANTS[name].selector in cmd

    def test_chain_file_well_formed(self):
        chain = Path(__file__).resolve().parents[2] / "pos" / "manifests" / "iv_pos_8" / "d2f_smoke.chain"
        if not chain.is_file():
            pytest.skip("d2f_smoke.chain not generated yet")
        for line in chain.read_text().splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split("|", 3)
            assert len(parts) == 4, line
            batch, node, rid, cmd = parts
            assert batch
            assert node in DEFAULT_NODES
            assert rid.startswith("pos_iv_pos_8_d2f_")
            assert "cd /root/a4_campaign/repo" in cmd

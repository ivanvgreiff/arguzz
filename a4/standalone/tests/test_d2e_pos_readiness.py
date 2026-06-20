#!/usr/bin/env python3
"""D2.E — POS-readiness aggregator (Gates A–F)."""

from __future__ import annotations

from pathlib import Path

import pytest

CHECKLIST_PATH = (
    Path(__file__).resolve().parents[2]
    / "docs" / "cloud2" / "POS_READINESS_CHECKLIST.md"
)


GATE_MODULES = [
    "a4.standalone.tests.test_d2e_normalize_loc_parity",
    "a4.standalone.tests.test_d2e_cross_variant_schema_parity",
    "a4.standalone.tests.test_d2e_cgc_parity",
    "a4.standalone.tests.test_d2e_variant_e2e_smoke",
    "a4.standalone.tests.test_d2e_pos_path_mimic",
    "a4.standalone.tests.test_d2e_d2g_ingestion_dryrun",
    "a4.standalone.tests.test_d2c_golden_trace_v5_decision_seq",
    "a4.standalone.tests.test_d2c_golden_trace_v5_db_byte_identity",
    "a4.standalone.tests.test_d2_bernoulli_floor_golden_trace",
]


class TestPOSReadinessAggregator:
    def test_checklist_artifact_exists(self):
        assert CHECKLIST_PATH.is_file(), (
            f"missing POS readiness checklist: {CHECKLIST_PATH}"
        )
        text = CHECKLIST_PATH.read_text()
        assert "Gate A" in text
        assert "Gate B" in text
        assert "F15" in text

    @pytest.mark.parametrize("module", GATE_MODULES)
    def test_gate_module_importable(self, module: str):
        __import__(module)

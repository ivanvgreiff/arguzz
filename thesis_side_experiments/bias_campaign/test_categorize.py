#!/usr/bin/env python3
"""Unit tests for categorize.py."""

from __future__ import annotations

import unittest

from thesis_side_experiments.bias_campaign.categorize import (
    categorize_failure,
    categorize_failures,
    categorize_touched,
    global_failed,
    mem_zir_loc_matches,
)


class FakeFailure:
    def __init__(self, loc: str, phase: str):
        self.loc = loc
        self.phase = phase


class TestCategorizeFailure(unittest.TestCase):
    def test_isread_mem_is_l2(self):
        loc = (
            "loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:22) at  "
            "MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))"
        )
        self.assertEqual(categorize_failure(loc, "local"), "L2")

    def test_decode_is_l1(self):
        self.assertEqual(
            categorize_failure("DecodeInst(zirgen/circuit/rv32im/v2/dsl/inst.zir:29)", "local"),
            "L1",
        )

    def test_accum_phase(self):
        self.assertEqual(
            categorize_failure("OneHot(zirgen/circuit/rv32im/v2/dsl/one_hot.zir:11)", "accum"),
            "ACCUM",
        )

    def test_unknown_phase_raises(self):
        with self.assertRaises(ValueError):
            categorize_failure("Foo", "unknown")


class TestCategorizeFailures(unittest.TestCase):
    def test_counts(self):
        fails = [
            FakeFailure("MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)", "local"),
            FakeFailure("DecodeInst(zirgen/circuit/rv32im/v2/dsl/inst.zir:29)", "local"),
            FakeFailure("OneHot(zirgen/circuit/rv32im/v2/dsl/one_hot.zir:11)", "accum"),
        ]
        self.assertEqual(categorize_failures(fails), {"L1": 1, "L2": 1, "ACCUM": 1})


class TestCategorizeTouched(unittest.TestCase):
    def test_split(self):
        local = [
            "DecodeInst(zirgen/circuit/rv32im/v2/dsl/inst.zir:29)|0|0",
            "MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)|0|0",
        ]
        accum = ["OneHot(zirgen/circuit/rv32im/v2/dsl/one_hot.zir:11)|0|0"]
        self.assertEqual(categorize_touched(local, accum), {"L1": 1, "L2": 1, "ACCUM": 1})


class TestGlobalFailed(unittest.TestCase):
    def test_memory_nonzero(self):
        fam = [{"family": "memory", "nonzero": True}, {"family": "u16", "nonzero": False}]
        g = global_failed(fam, {"nonzero": True})
        self.assertTrue(g["memory"])
        self.assertTrue(g["any"])
        self.assertFalse(g["u16"])

    def test_all_zero(self):
        fam = [{"family": "memory", "nonzero": False}]
        g = global_failed(fam, {"nonzero": False})
        self.assertFalse(g["any"])


class TestMemZirHelper(unittest.TestCase):
    def test_match(self):
        loc = "MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)"
        self.assertTrue(mem_zir_loc_matches(loc, "MemoryWrite@mem.zir:99"))


if __name__ == "__main__":
    unittest.main()

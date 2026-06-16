#!/usr/bin/env python3
"""Parse A4_INSPECT witness dump from audit host logs."""

from __future__ import annotations

import gzip
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

META_RE = re.compile(r"<a4_inspect_meta>(\{.*?\})</a4_inspect_meta>")
CYCLE_RE = re.compile(r"<a4_cycle_info>(\{.*?\})</a4_cycle_info>")
TXN_RE = re.compile(r"<a4_all_txn>(\{.*?\})</a4_all_txn>")
SUMMARY_RE = re.compile(r"<a4_all_txn_summary>(\{.*?\})</a4_all_txn_summary>")
FAULT_RE = re.compile(r"<fault>(\{.*?\})</fault>", re.DOTALL)
VERIFIER_OK = re.compile(r'"context":"Verifier", "status":"success"')
CONSTRAINT_FAIL = re.compile(r"<constraint_fail>")


def read_log(path: Path) -> str:
    if str(path).endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            return f.read()
    return path.read_text(encoding="utf-8", errors="replace")


def parse_trace(text: str) -> dict:
    meta_m = META_RE.search(text)
    meta = json.loads(meta_m.group(1)) if meta_m else {}

    cycles = [json.loads(m.group(1)) for m in CYCLE_RE.finditer(text)]
    txns = [json.loads(m.group(1)) for m in TXN_RE.finditer(text)]
    cycles.sort(key=lambda c: c["cycle_idx"])
    txns.sort(key=lambda t: t["txn_idx"])

    summary_m = SUMMARY_RE.search(text)
    summary = json.loads(summary_m.group(1)) if summary_m else {}

    fault_m = FAULT_RE.search(text)
    fault = json.loads(fault_m.group(1)) if fault_m else None

    return {
        "meta": meta,
        "summary": summary,
        "cycles": cycles,
        "txns": txns,
        "verifier_success": VERIFIER_OK.search(text) is not None,
        "constraint_fail_count": len(CONSTRAINT_FAIL.findall(text)),
        "fault": fault,
    }


def check_completeness(parsed: dict) -> tuple[bool, str]:
    mc = parsed["meta"].get("cycles")
    mt = parsed["meta"].get("txns")
    sc = len(parsed["cycles"])
    st = len(parsed["txns"])
    tot = parsed["summary"].get("total")
    if mc is None or mt is None:
        return False, "missing meta counts"
    if sc != mc:
        return False, f"cycles len {sc} != meta.cycles {mc}"
    if st != mt:
        return False, f"txns len {st} != meta.txns {mt}"
    if tot is not None and st != tot:
        return False, f"txns len {st} != summary.total {tot}"
    return True, "ok"


def cycle_key(c: dict) -> tuple:
    return (
        c["cycle_idx"],
        c.get("step"),
        c.get("pc"),
        c.get("major"),
        c.get("minor"),
        c.get("txn_idx"),
    )


def txn_key(t: dict) -> tuple:
    return (
        t["txn_idx"],
        t.get("step"),
        t.get("txn_type"),
        t.get("addr"),
        t.get("cycle"),
        t.get("word"),
        t.get("prev_cycle"),
        t.get("prev_word"),
    )


def struct_txn_key(t: dict) -> tuple:
    return (
        t["txn_idx"],
        t.get("step"),
        t.get("txn_type"),
        t.get("addr"),
        t.get("cycle"),
    )


def txn_values(t: dict) -> tuple:
    return (t.get("word"), t.get("prev_cycle"), t.get("prev_word"))


def value_diff_keys(base: dict, other: dict) -> set:
    bt = {struct_txn_key(t): txn_values(t) for t in base["txns"]}
    ot = {struct_txn_key(t): txn_values(t) for t in other["txns"]}
    return {k for k in set(bt) | set(ot) if bt.get(k) != ot.get(k)}


def txn_cycle_idx(cycles: List[dict], txn_idx: int) -> Optional[int]:
    cycle_idx = 0
    for c in cycles:
        if c["txn_idx"] <= txn_idx:
            cycle_idx = c["cycle_idx"]
        else:
            break
    return cycle_idx


def diff_traces(base: dict, other: dict) -> dict:
    bc = {cycle_key(c): c for c in base["cycles"]}
    oc = {cycle_key(c): c for c in other["cycles"]}
    bt = {txn_key(t): t for t in base["txns"]}
    ot = {txn_key(t): t for t in other["txns"]}

    changed_cycles = []
    for k in sorted(set(bc) | set(oc)):
        if bc.get(k) != oc.get(k):
            changed_cycles.append({"key": k, "baseline": bc.get(k), "other": oc.get(k)})

    changed_txns = []
    for k in sorted(set(bt) | set(ot)):
        if bt.get(k) != ot.get(k):
            changed_txns.append({"key": k, "baseline": bt.get(k), "other": ot.get(k)})

    return {
        "empty": not changed_cycles and not changed_txns,
        "changed_cycles": changed_cycles,
        "changed_txns": changed_txns,
        "n_changed_cycles": len(changed_cycles),
        "n_changed_txns": len(changed_txns),
    }


def semantic_diff_traces(
    base: dict,
    other: dict,
    noise_keys: Optional[set] = None,
) -> dict:
    """Diff witness structure, excluding baseline word/prev_word encoder noise."""
    raw = diff_traces(base, other)
    if noise_keys is None:
        noise_keys = set()

    bs = {struct_txn_key(t) for t in base["txns"]}
    os = {struct_txn_key(t) for t in other["txns"]}
    struct_added = sorted(os - bs)
    struct_removed = sorted(bs - os)

    value_keys = value_diff_keys(base, other) - noise_keys
    changed_cycle_idx: set = set()
    for row in raw["changed_cycles"]:
        for side in ("baseline", "other"):
            c = row.get(side) or {}
            if c.get("cycle_idx") is not None:
                changed_cycle_idx.add(c["cycle_idx"])

    cycles_ref = base["cycles"] if base["cycles"] else other["cycles"]
    for key in struct_added + struct_removed:
        changed_cycle_idx.add(txn_cycle_idx(cycles_ref, key[0]))
    for key in value_keys:
        changed_cycle_idx.add(txn_cycle_idx(cycles_ref, key[0]))

    semantic_empty = (
        not raw["changed_cycles"]
        and not struct_added
        and not struct_removed
        and not value_keys
    )

    return {
        **raw,
        "semantic_empty": semantic_empty,
        "struct_added": struct_added,
        "struct_removed": struct_removed,
        "value_diff_keys": sorted(value_keys),
        "n_value_diff_beyond_noise": len(value_keys),
        "changed_cycle_idx": sorted(changed_cycle_idx),
        "n_changed_cycle_idx": len(changed_cycle_idx),
        "n_noise_txn_values": len(value_diff_keys(base, other) & noise_keys),
    }


def structural_determinism(base: dict, other: dict) -> dict:
    """C1 check: cycles and txn topology must match; word values may differ."""
    bc = {cycle_key(c) for c in base["cycles"]}
    oc = {cycle_key(c) for c in other["cycles"]}
    bs = {struct_txn_key(t) for t in base["txns"]}
    os = {struct_txn_key(t) for t in other["txns"]}
    return {
        "cycles_match": bc == oc,
        "txn_topology_match": bs == os,
        "n_cycle_diff": len(bc ^ oc),
        "n_struct_txn_diff": len(bs ^ os),
        "n_value_diff": len(value_diff_keys(base, other)),
        "pass": bc == oc and bs == os,
    }


def parse_log_file(path: Path) -> dict:
    text = read_log(path)
    parsed = parse_trace(text)
    ok, msg = check_completeness(parsed)
    parsed["c2_ok"] = ok
    parsed["c2_msg"] = msg
    parsed["log_path"] = str(path)
    return parsed

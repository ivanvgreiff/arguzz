"""Shared trace diff assertion helpers for D2.B attestation (Q16)."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


class SoundnessBugSuspected(AssertionError):
    """Mutation applied + trace changed + no constraint failed + no error emitted."""


def collect_txn_field_diffs(
    pre_txns: Iterable[Dict[str, Any]],
    post_txns: Iterable[Dict[str, Any]],
    *,
    fields: Tuple[str, ...] = ("word", "prev_word", "prev_cycle", "cycle", "addr"),
) -> List[Dict[str, Any]]:
    """Return per-txn field diffs between pre and post mutation snapshots."""
    pre_list = list(pre_txns)
    post_list = list(post_txns)
    diffs: List[Dict[str, Any]] = []
    for before, after in zip(pre_list, post_list):
        idx = before.get("txn_idx", after.get("txn_idx"))
        changed = {
            field: {"before": before.get(field), "after": after.get(field)}
            for field in fields
            if before.get(field) != after.get(field)
        }
        if changed:
            diffs.append({"txn_idx": idx, "changed": changed})
    if len(pre_list) != len(post_list):
        diffs.append(
            {
                "txn_idx": None,
                "changed": {
                    "len": {"before": len(pre_list), "after": len(post_list)},
                },
            }
        )
    return diffs


def assert_trace_diff_matches_signature(
    diff: List[Dict[str, Any]],
    expected_signature: Dict[str, Any],
) -> None:
    """
    Compare actual diff against expected signature.

    expected_signature shape:
        {
            "primary": {"txn_idx": int, "field": str, "old": int, "new": int},
            "cascade": Optional[List[str]],
        }
    """
    primary = expected_signature["primary"]
    txn_idx = primary["txn_idx"]
    field = primary["field"]
    old_val = primary["old"]
    new_val = primary["new"]

    matching = [
        d for d in diff
        if d.get("txn_idx") == txn_idx and field in d.get("changed", {})
    ]
    if not matching:
        raise AssertionError(
            f"Expected change on txn {txn_idx}.{field} {old_val}->{new_val}; diff={diff}"
        )

    actual = matching[0]["changed"][field]
    if actual["before"] != old_val or actual["after"] != new_val:
        raise AssertionError(
            f"Signature mismatch on txn {txn_idx}.{field}: "
            f"expected {old_val}->{new_val}, got {actual}; diff={diff}"
        )

    cascade = expected_signature.get("cascade") or []
    for entry in diff:
        if entry.get("txn_idx") == txn_idx:
            continue
        extra_fields = set(entry.get("changed", {}).keys()) - set(cascade)
        if extra_fields:
            raise AssertionError(
                f"Unexpected cascade fields {extra_fields} on txn {entry.get('txn_idx')}; "
                f"allowed cascade={cascade}; diff={diff}"
            )


def check_soundness_bug_guard(
    *,
    mutation_applied: bool,
    trace_changed: bool,
    constraint_failed: bool,
    error_emitted: bool,
    proof_verify_failed: bool = False,
    broken_families_nonzero: bool = False,
    verifier_accepted: bool = False,
) -> None:
    """
    Raise SoundnessBugSuspected when a mutation edits the trace but every
    rejection channel is silent *and* the verifier accepts.

    Rejection channels (any one means NOT a soundness bug; mirrors fuzzer.py:345):
      - parsed <constraint_fail> tags (C1)
      - <a4_error> from the mutation dispatcher (C4)
      - prover self-check failure ("verify segment" — C2)
      - Hook 3 family residue nonzero (<a4_family_residue>; requires A4_FAMILY_RESIDUE=1 — C3)

    A true soundness bug is verifier_accepted=True after a confirmed trace edit.
    """
    if mutation_applied and trace_changed and verifier_accepted:
        raise SoundnessBugSuspected(
            "SOUNDNESS-BUG GUARD: mutation applied, trace changed, and verifier "
            "accepted — candidate NFP for Pro review"
        )
    if (
        mutation_applied
        and trace_changed
        and not constraint_failed
        and not error_emitted
        and not proof_verify_failed
        and not broken_families_nonzero
    ):
        raise SoundnessBugSuspected(
            "SOUNDNESS-BUG GUARD: mutation applied and trace changed without "
            "constraint failure, a4_error, proof verification failure, or Hook 3 "
            "family residue — candidate NFP for Pro review"
        )

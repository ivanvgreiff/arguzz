"""Phase 7d architecture audits.

Each audit is an executable Python script. Acceptance criterion: exit code 0
AND final line is `=== Ax RESULT: PASS ===` (or `=== Bx RESULT: PASS ===`).

Run all 7d.1 audits in order:
    python -m a4.audits.A1_trace_determinism
    python -m a4.audits.A2_zone_classifier_correctness
    python -m a4.audits.A3_arm_step_integrity
    python -m a4.audits.A4_universe_completeness
    python -m a4.audits.A5_canonical_match

See PHASE_7D_ARCHITECTURE_AUDIT.md for full spec.
"""

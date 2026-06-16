#!/usr/bin/env bash
# Phase 7d Inc 5 — single-command E5 pipeline driver.
set -uo pipefail
cd /root/arguzz

LOG=a4/audits/audit_output/E5_run.log
mkdir -p a4/audits/audit_output/per_arm_evidence/_stubs
: >"$LOG"

echo "=== INC5 E5 pipeline start $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a "$LOG"

# Step 1: preflight
PYTHONPATH=/root/arguzz python3 -m a4.audits.inc5_preflight 2>&1 | tee -a "$LOG"
preflight_rc=${PIPESTATUS[0]}
if [[ $preflight_rc -ne 0 ]]; then
  echo "INC5 GATE: FAIL: preflight" | tee -a "$LOG"
  exit 1
fi

# Step 2: per-arm evidence generation (~2-3 hr)
PYTHONPATH=/root/arguzz python3 -m a4.audits.E5_per_arm_evidence 2>&1 | tee -a "$LOG"
evidence_rc=${PIPESTATUS[0]}
if [[ $evidence_rc -ne 0 ]]; then
  echo "INC5 GATE: FAIL: evidence_gen (rc=$evidence_rc)" | tee -a "$LOG"
  exit 2
fi

# Step 3: build index + summary
PYTHONPATH=/root/arguzz python3 -m a4.audits.E5_build_index 2>&1 | tee -a "$LOG"
index_rc=${PIPESTATUS[0]}
if [[ $index_rc -ne 0 ]]; then
  echo "INC5 GATE: FAIL: index (rc=$index_rc)" | tee -a "$LOG"
  exit 3
fi

# Step 4: stub generation for multi-guest-only arms
PYTHONPATH=/root/arguzz python3 -m a4.audits.E5_per_arm_evidence --stubs-only 2>&1 | tee -a "$LOG"

# Step 5: acceptance gate
PYTHONPATH=/root/arguzz python3 - <<'PY' 2>&1 | tee -a "$LOG"
import json, sys
s = json.load(open("a4/audits/audit_output/E5_summary.json"))
assert s["verdict"] == "PASS", f"verdict={s['verdict']}"
assert s["n_arms_correct"] >= 48, f"only {s['n_arms_correct']}/48 arms ✓"
assert s["n_arms_incorrect"] == 0, f"{s['n_arms_incorrect']} arms ✗"
print(
    f"INC5 GATE: PASS ({s['n_arms_correct']}/48 ✓, "
    f"{s['n_arms_warning']} ⚠, {s['n_arms_incorrect']} ✗)"
)
PY
gate_rc=${PIPESTATUS[0]}
if [[ $gate_rc -ne 0 ]]; then
  echo "INC5 GATE: FAIL: acceptance" | tee -a "$LOG"
  exit 4
fi

echo "=== INC5 E5 pipeline done $(date -u +%Y-%m-%dT%H:%M:%SZ) ===" | tee -a "$LOG"

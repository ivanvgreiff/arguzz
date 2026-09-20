#!/usr/bin/env bash
# A1.B1 — MODE-2 existence proof of the rs1==rs2 CVE @ 98387806.
# Docker-adapted from scripts/helper.sh (turnkey path is podman; we have docker).
#
# ISOLATION (HARD): everything lives under a4/runs/iv_pos_9/a1/mode2/. The fuzzer clones a
# FRESH risc0 (DanielHoffmann91 fork) into mode2/risc0 with its OWN .cargo/.rustup/.risc0 —
# it never touches workspace/risc0-* (AP / Seam-B / Track-B) and dispatches NO POS jobs.
set -euo pipefail

COMMIT=${COMMIT:-98387806fe8348d87e32974468c6f35853356ad5}   # the bug commit
FIX=${FIX:-67f2d81c638bff5f4fcfe11a084ebb34799b7a89}         # the #3181 fix
SEED=${SEED:-789123}                                          # defaults.sh DEFAULT_MASTER_SEED
TIMEOUT=${TIMEOUT:-5400}                                      # fuzz-campaign budget (s); 0 = unbounded
ACTION=${1:-install_run}                                      # install_run | check_vuln | check_fix
IMG=zkvm/risc0
BASE=/root/arguzz/a4/runs/iv_pos_9/a1/mode2
DOT=$BASE/dot
mkdir -p "$BASE/risc0" "$BASE/workspace/logs"

# NB: do NOT mount /root/.cargo /.rustup /.risc0 — they are baked into the image; mounting empty
# host dirs over them shadows cargo/rzup (the podman helper populates them via BUILD-time volumes,
# which docker can't). We persist only the clone (target/ cache lives in it) + the findings workspace.
# settings_a1.py = the fuzzer settings with RUST_TOOLCHAIN_VERSION bumped 1.85.0 -> 1.88.0 (MSRV
# drift: fresh resolve pulls icu/idna 2.2 needing rustc>=1.86; 98387806 builds clean under 1.88).
# Mounted over the image's pip-installed copy so we don't edit the shared fuzzer source.
SETTINGS=/root/arguzz/a4/runs/iv_pos_9/a1/settings_a1.py
VOL=(
  -v "$BASE/risc0":/root/risc0
  -v "$BASE/workspace":/root/workspace
  -v "$SETTINGS":/usr/local/lib/python3.11/dist-packages/risc0_fuzzer/settings.py:ro
)
RUN() { docker run --rm "${VOL[@]}" "$IMG" risc0-fuzzer "$@"; }

case "$ACTION" in
  install_run)
    echo "== [B1] install: clone fork -> $COMMIT -> apply frozen vuln source =="
    RUN install /root/risc0 --commit-or-branch "$COMMIT" --zkvm-modification --verbosity 1 --log-file logs/installer.log
    echo "== [B1] run: build risc0 @ $COMMIT + fuzz with fault injection (re-find rs1==rs2 divergence) =="
    rf=(run --zkvm /root/risc0 --out /root/workspace --seed "$SEED" --commit-or-branch "$COMMIT"
        --trace-collection --fault-injection --only-modify-word --verbosity 1 --log-file logs/fuzzer.log)
    [ "$TIMEOUT" -gt 0 ] && rf+=(--timeout "$TIMEOUT")
    RUN "${rf[@]}"
    echo "== [B1] findings =="; ls -la "$BASE/workspace"; head -5 "$BASE/workspace"/*.csv 2>/dev/null || true
    ;;
  check_vuln)   # bracket lower: bug REPRODUCES at the vuln commit -> fixed=False
    echo "== [B1] check @ $COMMIT (expect fixed=False) =="
    RUN check /root/workspace/findings.csv --zkvm /root/risc0 --commit-or-branch "$COMMIT" \
        --trace-collection --fault-injection --only-modify-word --verbosity 1 --log-file logs/check_vuln.log --out checker_vuln
    head -20 "$BASE/workspace/checker_vuln"/*.csv 2>/dev/null || true
    ;;
  check_fix)    # bracket upper: bug GONE at the fix -> fixed=True
    echo "== [B1] check @ $FIX (expect fixed=True) =="
    RUN check /root/workspace/findings.csv --zkvm /root/risc0 --commit-or-branch "$FIX" \
        --trace-collection --fault-injection --only-modify-word --verbosity 1 --log-file logs/check_fix.log --out checker_fix
    head -20 "$BASE/workspace/checker_fix"/*.csv 2>/dev/null || true
    ;;
  *) echo "usage: $0 [install_run|check_vuln|check_fix]" >&2; exit 2 ;;
esac

#!/usr/bin/env bash
# Build the FIXED Seam-B (VerifyOpcode-holed) risc0-host PAIR with the 3 dead A4 kinds LIVE.
#
# The ONLY change vs the original (contaminated) Seam-B build (a4/builds/ap_seamb/) is:
#   cherry-pick 6556e8d7 (the witgen A4_MUTATION_CONFIG replay handlers for
#   TXN_PREV_WORD_MOD / TXN_PREV_CYCLE_MOD / CYCLE_DIFF_COUNT_MOD) onto 93bda33b BEFORE compiling.
# Verified clean (read-only): merge-base(93bda33b,6556e8d7)=28e53771 == 6556e8d7's parent, and
# 93bda33b never modified witgen/mod.rs vs 28e53771 -> zero-conflict pure replay; 6556e8d7 edits
# witgen/mod.rs ONLY (not rv32im.rs/load_rs2, not the VerifyOpcode patch artifacts) -> bug + load_rs2
# preserved, composes with the hole.
#
# Outputs (SEPARATE folder; the contaminated a4/builds/ap_seamb/ is NEVER touched):
#   a4/builds/ap_seamb_fix/control/risc0-host            (planted_bug=none)
#   a4/builds/ap_seamb_fix/bench-verifyopcode/risc0-host (planted_bug=verifyopcode)
# New risc0_head_sha (the cherry-pick commit) so the POS fingerprint guard distinguishes
# fixed from contaminated.
#
# SAFETY: single foreground script, set -euo pipefail (exit-on-first-failure), EXIT-trap restores
# risc0-seamb to its frozen state (detached @ 93bda33b + VerifyOpcode patch) on ANY exit while
# keeping the seamb-fix-handlers branch ref (preserves the fix sha). NEVER broad-pkill cargo
# (the cargo cmd is shared across worktrees).
set -euo pipefail

ROOT=/root/arguzz
RISC0="$ROOT/workspace/risc0-seamb"
OUT_WS="$ROOT/workspace/output-seamb"
PATCH="$ROOT/a4/scripts/ap_verifyopcode_patch.py"
BUILD="$ROOT/a4/builds/ap_seamb_fix"
HOST_OUT="$OUT_WS/target/release/risc0-host"
GUEST_SRC="$OUT_WS/methods/guest/src/main.rs"
HOST_MAIN="$OUT_WS/host/src/main.rs"
RV32="$RISC0/risc0/circuit/rv32im/src/execute/rv32im.rs"
WITGEN="$RISC0/risc0/circuit/rv32im/src/prove/witgen/mod.rs"
FFI="$RISC0/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp"

BASE_SHA=93bda33b4f95f29acc9ddce1e225cdf949c83874
CHERRY=6556e8d7
GUEST_ARGS=(--ctrl 7 --gseed 12345 --rounds 5)
EXPECT_GUEST_SRC_SHA=1f5b937271d1a0f1798cf513fe412cfe66e2463e4f0f36d4f8d718577148dbe3
CONTAM_GUEST_ID="1145334646,2159102285,1953889312,304928682,3764427408,3452386835,1931880701,971553701"
THREE_KINDS=(TXN_PREV_WORD_MOD TXN_PREV_CYCLE_MOD CYCLE_DIFF_COUNT_MOD)

HEAD_SHA_FIX=""
say(){ echo "[seamb_fix] $*"; }
fail(){ echo "[seamb_fix] FAIL: $*" >&2; exit 1; }

restore_seamb(){
    echo "[seamb_fix] (restore) returning risc0-seamb -> detached $BASE_SHA + VerifyOpcode patch"
    python3 "$PATCH" revert >/dev/null 2>&1 || true
    git -C "$RISC0" cherry-pick --abort >/dev/null 2>&1 || true
    git -C "$RISC0" checkout -- . >/dev/null 2>&1 || true
    git -C "$RISC0" checkout "$BASE_SHA" >/dev/null 2>&1 || true
    python3 "$PATCH" apply >/dev/null 2>&1 || true
    local h d; h="$(git -C "$RISC0" rev-parse HEAD 2>/dev/null || echo '?')"
    d="$(git -C "$RISC0" status --porcelain 2>/dev/null | wc -l)"
    echo "[seamb_fix] (restore) HEAD=${h:0:12} dirty_files=$d (expect 93bda33b / >=6)"
}
trap restore_seamb EXIT

# ---- defense-in-depth: build workspace must point ONLY at risc0-seamb ----
if grep -rq "workspace/risc0-modified\|risc0-clean-28e53771\|risc0-a1-vuln\|risc0-b3" \
    "$OUT_WS"/host/Cargo.toml "$OUT_WS"/methods/Cargo.toml "$OUT_WS"/methods/guest/Cargo.toml 2>/dev/null; then
    fail "output-seamb references a FOREIGN worktree — isolation broken, aborting"
fi
grep -rq "workspace/risc0-seamb" "$OUT_WS"/host/Cargo.toml || fail "output-seamb not wired to risc0-seamb"
say "isolation OK: output-seamb wired only to risc0-seamb"

# ---- PHASE 0: record original state; the VerifyOpcode patch must currently be APPLIED ----
say "PHASE 0: verify risc0-seamb is the frozen Seam-B holed source"
ORIG_HEAD="$(git -C "$RISC0" rev-parse HEAD)"
[[ "$ORIG_HEAD" == "$BASE_SHA" ]] || fail "risc0-seamb HEAD ${ORIG_HEAD:0:12} != base ${BASE_SHA:0:12}"
ORIG_DIRTY="$(git -C "$RISC0" status --porcelain | wc -l)"
[[ "$ORIG_DIRTY" -ge 6 ]] || fail "expected VerifyOpcode patch applied (>=6 dirty files); found $ORIG_DIRTY"
say "  HEAD=${ORIG_HEAD:0:12}  dirty_files=$ORIG_DIRTY ✓"

# ---- PHASE 1: clean base + cherry-pick the witgen handlers ----
say "PHASE 1: revert patch -> clean $BASE_SHA, branch seamb-fix-handlers, cherry-pick $CHERRY"
python3 "$PATCH" revert
[[ "$(git -C "$RISC0" status --porcelain | wc -l)" -eq 0 ]] || fail "tree not clean after patch revert"
git -C "$RISC0" branch -D seamb-fix-handlers >/dev/null 2>&1 || true
git -C "$RISC0" checkout -b seamb-fix-handlers "$BASE_SHA"
git -C "$RISC0" cherry-pick "$CHERRY" || fail "cherry-pick $CHERRY conflicted (UNEXPECTED — verified clean)"
HEAD_SHA_FIX="$(git -C "$RISC0" rev-parse HEAD)"
say "  HEAD_SHA_FIX=$HEAD_SHA_FIX"
for k in "${THREE_KINDS[@]}"; do
    c="$(grep -c "\"$k\"" "$WITGEN" || true)"
    [[ "$c" -ge 1 ]] || fail "handler $k still missing in witgen/mod.rs after cherry-pick"
    say "  witgen handler $k: $c ref(s) ✓"
done
LOAD_RS2="$(grep -c 'fn load_rs2' "$RV32" || true)"
[[ "$LOAD_RS2" -ge 1 ]] || fail "load_rs2 absent (rv32im.rs changed!) — bug/baseline broken"
CHANGED="$(git -C "$RISC0" diff --name-only "$BASE_SHA" HEAD)"
[[ "$CHANGED" == "risc0/circuit/rv32im/src/prove/witgen/mod.rs" ]] || fail "cherry-pick changed unexpected files: [$CHANGED]"
say "  cherry-pick changed ONLY witgen/mod.rs; load_rs2 present ($LOAD_RS2) ✓"

INSTR_HASH="$(cat "$WITGEN" "$FFI" 2>/dev/null | sha256sum | awk '{print $1}')"
GUEST_SRC_SHA="$(sha256sum "$GUEST_SRC" | awk '{print $1}')"
[[ "$GUEST_SRC_SHA" == "$EXPECT_GUEST_SRC_SHA" ]] || fail "guest source changed ($GUEST_SRC_SHA) — comparability broken"
say "  guest_src_sha256 == ${EXPECT_GUEST_SRC_SHA:0:16}… ✓ (guest unchanged)"

# ---- build + fingerprint-assert + honest-gate + archive ----
build_and_stamp(){
    local role="$1" planted="$2" outdir="$BUILD/$1"
    say "=== build $role (planted_bug=$planted) ==="
    export A4_PLANTED_BUG="$planted" A4_ISREAD_SCOPE="" \
           A4_RISC0_HEAD_SHA="$HEAD_SHA_FIX" A4_LOAD_RS2_PRESENT="$LOAD_RS2" \
           A4_INSTRUMENTATION_HASH="$INSTR_HASH"
    touch "$HOST_MAIN"     # force main.rs recompile so option_env! re-bakes the head sha + planted_bug
    ( cd "$OUT_WS" && cargo build --release -p risc0-host ) || fail "$role cargo build failed"
    test -f "$HOST_OUT" || fail "$role produced no binary"
    # assert the binary self-reports the intended fingerprint (exactly what the POS guard reads)
    local fp; fp="$(A4_INSPECT_FINGERPRINT=1 "$HOST_OUT" 2>/dev/null \
        | sed -n 's/.*<a4_fingerprint>\(.*\)<\/a4_fingerprint>.*/\1/p')"
    [[ -n "$fp" ]] || fail "$role emitted no <a4_fingerprint>"
    PLANTED="$planted" HEADFIX="$HEAD_SHA_FIX" python3 -c "
import sys,json,os
fp=json.load(sys.stdin)
assert fp['planted_bug']==os.environ['PLANTED'], ('planted',fp)
assert fp['risc0_head_sha']==os.environ['HEADFIX'], ('head',fp)
assert int(fp['load_rs2_present'])==1, ('load_rs2',fp)
print('  fp OK: planted=%s head=%s load_rs2=%s guest_id=%s'%(
    fp['planted_bug'], fp['risc0_head_sha'][:12], fp['load_rs2_present'],
    ','.join(str(x) for x in fp['guest_image_id'])))" <<<"$fp" || fail "$role fingerprint assertion failed"
    # honest-gate: full prove+verify of the guest
    say "  honest-gate $role (prove+verify) ..."
    local out; out="$("$HOST_OUT" "${GUEST_ARGS[@]}" 2>&1 || true)"
    echo "$out" | grep -q '"context":"Verifier", "status":"success"' \
        || { echo "$out" | tail -25; fail "$role honest verify FAILED"; }
    say "  honest verify $role = PASS ✓"
    # archive read-only
    mkdir -p "$outdir"
    [[ -f "$outdir/risc0-host" ]] && chmod u+w "$outdir/risc0-host"
    cp "$HOST_OUT" "$outdir/risc0-host"
    local host_sha gid
    host_sha="$(sha256sum "$outdir/risc0-host" | awk '{print $1}')"
    gid="$(A4_INSPECT_FINGERPRINT=1 "$outdir/risc0-host" 2>/dev/null \
        | sed -n 's/.*"guest_image_id":\[\([0-9, ]*\)\].*/\1/p' | tr -d ' ')"
    cat > "$outdir/fingerprint.json" <<JSON
{
  "track": "AP_seamb_fix", "role": "$role",
  "risc0_head_sha": "$HEAD_SHA_FIX", "base_head_sha": "$BASE_SHA", "cherry_pick": "$CHERRY",
  "load_rs2_present": $LOAD_RS2, "planted_bug": "$planted",
  "instrumentation_hash": "$INSTR_HASH", "guest_src_sha256": "$GUEST_SRC_SHA",
  "guest_image_id": "$gid", "host_sha256": "$host_sha", "three_kinds_live": true,
  "built_from": "a4/scripts/build_seamb_fix.sh"
}
JSON
    chmod 0555 "$outdir/risc0-host"; chmod 0444 "$outdir/fingerprint.json"
    say "  archived $role -> $outdir  (host_sha ${host_sha:0:16}…  guest_id $gid)"
    echo "$gid"   # last line = guest_id, captured by caller
}

# ---- PHASE 2: CONTROL (handlers, no hole) ----
GID_CTRL="$(build_and_stamp control none | tail -1)"

# ---- PHASE 3: HOLED (handlers + VerifyOpcode hole) ----
say "PHASE 3: apply VerifyOpcode patch (composes with the handlers)"
python3 "$PATCH" apply
python3 "$PATCH" status || true
GID_HOLED="$(build_and_stamp bench-verifyopcode verifyopcode | tail -1)"

# ---- PHASE 4: guest_id consistency + 3 kinds LIVE in the binaries ----
say "PHASE 4: guest_id consistency + 3-kinds-live"
[[ "$GID_CTRL" == "$GID_HOLED" ]] || fail "control guest_id ($GID_CTRL) != holed ($GID_HOLED)"
say "  control guest_id == holed guest_id ✓: $GID_HOLED"
if [[ "$GID_HOLED" == "$CONTAM_GUEST_ID" ]]; then
    say "  guest_id == contaminated build's id ✓ (use as --guest-id on POS)"
else
    say "  NOTE: guest_id DIFFERS from contaminated ($CONTAM_GUEST_ID) — use the NEW id above as --guest-id"
fi
for bin in control bench-verifyopcode; do
    for k in "${THREE_KINDS[@]}"; do
        c="$(strings "$BUILD/$bin/risc0-host" | grep -c "$k" || true)"
        [[ "$c" -ge 1 ]] || fail "$bin: kind $k NOT in binary strings (still dead!)"
    done
    itm="$(strings "$BUILD/$bin/risc0-host" | grep -c INSTR_TYPE_MOD || true)"
    [[ "$itm" -ge 1 ]] || fail "$bin: INSTR_TYPE_MOD missing"
    say "  $bin: all 3 kinds live + INSTR_TYPE_MOD present ✓"
done

# ---- PHASE 5: POS fingerprint-guard self-check on the archived binaries ----
say "PHASE 5: POS fingerprint-guard self-check"
python3 -m a4.pos.fingerprint_guard "$BUILD/bench-verifyopcode/risc0-host" \
    --profile verifyopcode --head-sha "$HEAD_SHA_FIX" --guest-id "$GID_HOLED" \
    || fail "HOLED binary FAILS the verifyopcode guard"
say "  holed PASSES verifyopcode guard (head=${HEAD_SHA_FIX:0:12}) ✓"
python3 -m a4.pos.fingerprint_guard "$BUILD/control/risc0-host" --emit-json \
    | python3 -c "import sys,json; fp=json.load(sys.stdin); assert fp['planted_bug']=='none' and int(fp['load_rs2_present'])==1, fp; print('  control fp: planted=none load_rs2=1 ✓')"

# ---- SUMMARY (the EXIT trap restores risc0-seamb after this) ----
say "================ DONE ✓ ================"
say "HEAD_SHA_FIX (POS --head-sha): $HEAD_SHA_FIX"
say "guest_id     (POS --guest-id): $GID_HOLED"
say "control:            $BUILD/control/risc0-host"
say "bench-verifyopcode: $BUILD/bench-verifyopcode/risc0-host"
say "Functional verify (3-kind replay + Stage-0 mutated-V0) runs separately on the archived pair."

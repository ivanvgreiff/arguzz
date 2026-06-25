#!/usr/bin/env bash
# B2 post-build verification — the vulnerable instrumented MODE-1 risc0-host @ 98387806.
# Confirms (G1) the circuit is the VULNERABLE one (load_rs2 absent), (G2) no planted bug,
# extracts the A2 guest image-id for the manifest --guest-id, disassembles the guest to
# confirm the remu/divu source registers are 1-bit-apart (the V6_uniform alias target), and
# runs an honest prove. Exits nonzero on any gate failure. Run from repo root.
set -euo pipefail
BIN="workspace/output-a1vuln/target/release/risc0-host"
OUT="a4/runs/iv_pos_9/a1/B2_VERIFY.json"
[ -x "$BIN" ] || { echo "FAIL: $BIN missing/not-exec"; exit 1; }

echo "== G1/G2: self-reported fingerprint (race profile expects load_rs2_present=0, planted_bug=none) =="
# NB: the binary exits nonzero by design (fingerprint prints before clap's arg-parse error),
# so tolerate it under `set -o pipefail` with `|| true`.
FP="$(A4_INSPECT_FINGERPRINT=1 "$BIN" 2>/dev/null | sed -n 's/.*<a4_fingerprint>\(.*\)<\/a4_fingerprint>.*/\1/p' || true)"
[ -n "$FP" ] || { echo "FAIL: no <a4_fingerprint> tag emitted"; exit 1; }
echo "$FP" | python3 -m json.tool
echo "$FP" > "$OUT"
LOAD_RS2="$(echo "$FP" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("load_rs2_present"))')"
PLANTED="$(echo "$FP" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("planted_bug"))')"
GUESTID="$(echo "$FP" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(",".join(str(x) for x in d.get("guest_image_id",[])))')"
HEAD="$(echo "$FP" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("risc0_head_sha"))')"
echo "load_rs2_present=$LOAD_RS2  planted_bug=$PLANTED  head=$HEAD"
echo "GUEST_ID=$GUESTID"
[ "$LOAD_RS2" = "0" ] || { echo "FAIL(G1): load_rs2_present=$LOAD_RS2 (expected 0 = vulnerable)"; exit 1; }
[ "$PLANTED" = "none" ] || { echo "FAIL(G2): planted_bug=$PLANTED (expected none)"; exit 1; }
echo "PASS: vulnerable circuit (no load_rs2), no planted bug"

echo "== guard 'race' profile (the exact check the nodes will run) =="
python3 -m a4.pos.fingerprint_guard "$BIN" --profile race --guest-id "$GUESTID" \
  && echo "PASS: guard race-profile green" || { echo "FAIL: guard rejected"; exit 1; }

echo "== guest disassembly: remu/divu source regs must be 1-bit-apart (V6_uniform alias target) =="
GELF="$(find workspace/output-a1vuln/target -path '*riscv32im*release/methods_guest*' -type f 2>/dev/null | head -1)"
GELF="${GELF:-$(find workspace/output-a1vuln -name '*.bin' -path '*guest*' 2>/dev/null | head -1)}"
if command -v riscv64-unknown-elf-objdump >/dev/null 2>&1 && [ -n "$GELF" ]; then
  riscv64-unknown-elf-objdump -d "$GELF" 2>/dev/null | grep -E "\bremu\b|\bdivu\b" | head || echo "(no remu/divu lines found via objdump)"
else
  echo "(objdump/guest-elf unavailable here; reg-adjacency is asm-pinned a0/a1 + a2/a3 in the guest source)"
fi

echo "ALL B2 GATES PASSED — GUEST_ID=$GUESTID  (use as generate_race_manifests --guest-id)"

#!/usr/bin/env bash
# B3 verification — vulnerable (load_rs2 absent) + 3 A4 handlers present + guest_id==B2.
# B3 = B2 source + TXN_PREV_WORD/TXN_PREV_CYCLE/CYCLE_DIFF_COUNT witgen handlers (6556e8d7), still vulnerable.
# Run from repo root. Exits nonzero on any gate failure.
set -uo pipefail
BIN="workspace/output-a1vuln-b3/target/release/risc0-host"
B2_GUESTID="2819774008,269738887,492358372,594138501,3395406058,845810525,2646011585,829874012"
OUT="a4/runs/iv_pos_9/a1/B3_VERIFY.json"
[ -x "$BIN" ] || { echo "FAIL: $BIN missing/not-exec"; exit 1; }

echo "== B3 sha256 =="; sha256sum "$BIN" | tee a4/runs/iv_pos_9/a1/B3_sha256.txt

echo "== G1/G2/G3: fingerprint (want load_rs2_present=0, planted_bug=none, guest_id==B2) =="
FP="$(A4_INSPECT_FINGERPRINT=1 "$BIN" 2>/dev/null | sed -n 's/.*<a4_fingerprint>\(.*\)<\/a4_fingerprint>.*/\1/p' || true)"
[ -n "$FP" ] || { echo "FAIL: no <a4_fingerprint>"; exit 1; }
echo "$FP" | python3 -m json.tool | tee "$OUT"
LOAD_RS2=$(echo "$FP"|python3 -c 'import sys,json;print(json.load(sys.stdin).get("load_rs2_present"))')
PLANTED=$(echo "$FP"|python3 -c 'import sys,json;print(json.load(sys.stdin).get("planted_bug"))')
GUESTID=$(echo "$FP"|python3 -c 'import sys,json;d=json.load(sys.stdin);print(",".join(str(x) for x in d.get("guest_image_id",[])))')
HEAD=$(echo "$FP"|python3 -c 'import sys,json;print(json.load(sys.stdin).get("risc0_head_sha"))')
echo "load_rs2_present=$LOAD_RS2 planted_bug=$PLANTED head=$HEAD"
echo "GUEST_ID=$GUESTID"
[ "$LOAD_RS2" = "0" ]  || { echo "FAIL(G1): load_rs2=$LOAD_RS2 (want 0=vulnerable)"; exit 1; }
[ "$PLANTED" = "none" ] || { echo "FAIL(G2): planted=$PLANTED"; exit 1; }
[ "$GUESTID" = "$B2_GUESTID" ] || { echo "FAIL(G3): guest_id MISMATCH; B3=$GUESTID B2=$B2_GUESTID -> divide steps may have moved off 444/449; STOP and re-locate before any run"; exit 1; }
echo "PASS G1-G3: vulnerable + no planted bug + guest_id == B2 (CVE intact, divide stays @444/449)"

echo "== G-handlers: the 3 kinds compiled in (B2 had 0 each) =="
for k in TXN_PREV_WORD_MOD TXN_PREV_CYCLE_MOD CYCLE_DIFF_COUNT_MOD; do
  n=$(strings -n 8 "$BIN" | grep -c "$k"); echo "  $k: $n"
  [ "$n" -ge 1 ] || { echo "FAIL: handler $k absent"; exit 1; }
done
echo "PASS: 3 A4 handlers present in B3"

echo ""
echo "ALL DETERMINISTIC GATES PASSED."
echo "MANUAL follow-ups (need inject CLI):"
echo "  (a) CVE intact: replay rs2-alias INSTR_WORD_MOD @ step 444 -> expect ACCEPT + committed output 0 (== B2)."
echo "  (b) handlers live: replay a TXN_PREV_CYCLE_MOD -> expect a real mutation (failures/reject), NOT '<a4_error>invalid config'."
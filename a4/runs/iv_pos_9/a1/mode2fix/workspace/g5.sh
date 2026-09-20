#!/bin/bash
set -e
echo "=== install fix 67f2d81 (applies rv32im_rs_67f2d81 with load_rs2 + hooks) ==="
risc0-fuzzer install /root/risc0 --commit-or-branch 67f2d81c638bff5f4fcfe11a084ebb34799b7a89 --zkvm-modification --verbosity 1 --log-file /root/workspace/logs/g5_install.log
RV=/root/risc0/risc0/circuit/rv32im/src/execute/rv32im.rs
echo "load_rs2 in fix clone: $(grep -c 'fn load_rs2' $RV)"
echo "=== re-apply A1_ALIAS_RS2 patch to the fix random_word ==="
python3 - "$RV" <<'PY'
import sys,re
p=sys.argv[1]; s=open(p).read()
patch='''    pub fn random_word(&mut self, word: u32) -> u32 {
        if std::env::var("A1_ALIAS_RS2").is_ok() {
            let rs1 = (word >> 15) & 0x1f;
            return (word & !(0x1f << 20)) | (rs1 << 20);
        }'''
s2=re.sub(r'    pub fn random_word\(&mut self, word: u32\) -> u32 \{', patch, s, count=1)
assert s2!=s, "random_word not found"
open(p,'w').write(s2)
print("patched random_word")
PY
echo "=== build fix + run honest + alias ==="
cd /root/workspace
cargo build --release > logs/g5_build.log 2>&1; echo "BUILD=$?"; tail -1 logs/g5_build.log
H=./target/release/risc0-host; A="--in0 7 --in1 5 --in4 0"
$H $A --trace > logs/g5_honest.log 2>&1
STEP=$(grep '"instruction":"RemU"' logs/g5_honest.log | head -1 | grep -oE '"step":[0-9]+' | grep -oE '[0-9]+')
echo "REMU_STEP=$STEP  honest_remu=$(grep '"instruction":"RemU"' logs/g5_honest.log | head -1)"
echo "=== INJECT same rs2:=rs1 alias on the FIX build (expect REJECT) ==="
A1_ALIAS_RS2=1 CONSTRAINT_CONTINUE=1 $H $A --inject --inject-step "$STEP" --inject-kind INSTR_WORD_MOD --seed 1 > logs/g5_inject.log 2>&1
echo "inject_exit=$? (nonzero/panic = REJECT = fix works)"
grep -iE '<fault>|<constraint_fail>|"output"|context.:.Prover., .status|context.:.Verifier., .status' logs/g5_inject.log | head -12

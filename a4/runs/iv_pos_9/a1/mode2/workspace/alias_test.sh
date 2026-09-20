#!/bin/bash
cd /root/workspace
echo "=== rebuild (clone executor + guest changed) ==="
cargo build --release > logs/alias_build.log 2>&1; echo "BUILD=$?"
grep -iE "error" logs/alias_build.log | head -5
tail -1 logs/alias_build.log
echo "=== honest trace (in0=7,in1=5 -> expect output 2; find remu step; confirm rs1!=rs2) ==="
./target/release/risc0-host --in0 7 --in1 5 --trace > logs/alias_honest.log 2>&1
grep -iE '"instruction":"RemU"' logs/alias_honest.log | head -1
grep -iE '"output"|context.:.Verifier., .status' logs/alias_honest.log | tail -2
STEP=$(grep -oE '"step":[0-9]+, "pc":[0-9]+, "instruction":"RemU"' logs/alias_honest.log | head -1 | grep -oE '"step":[0-9]+' | grep -oE '[0-9]+')
echo "REMU_STEP=$STEP"
echo "=== INJECT targeted rs2:=rs1 alias (A1_ALIAS_RS2=1) via INSTR_WORD_MOD @ remu ==="
A1_ALIAS_RS2=1 CONSTRAINT_CONTINUE=1 ./target/release/risc0-host --in0 7 --in1 5 \
   --inject --inject-step "$STEP" --inject-kind INSTR_WORD_MOD --seed 1 > logs/alias_inject.log 2>&1
echo "INJECT_EXIT=$?"
grep -iE '<fault>|<constraint_fail>|"output"|context.:.Prover., .status|context.:.Verifier., .status' logs/alias_inject.log | head -12

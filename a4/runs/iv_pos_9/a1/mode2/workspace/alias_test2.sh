#!/bin/bash
cd /root/workspace
H=./target/release/risc0-host
A="--in0 7 --in1 5 --in4 0"
echo "=== honest (in0=7,in1=5 -> expect output 2) + trace ==="
$H $A --trace > logs/alias_honest.log 2>&1; echo "honest_exit=$?"
grep -iE '"output"|context.:.Verifier., .status' logs/alias_honest.log | tail -2
echo "--- the remu op ---"; grep '"instruction":"RemU"' logs/alias_honest.log | head -1
STEP=$(grep '"instruction":"RemU"' logs/alias_honest.log | head -1 | grep -oE '"step":[0-9]+' | grep -oE '[0-9]+')
echo "REMU_STEP=$STEP"
if [ -n "$STEP" ]; then
  echo "=== INJECT rs2:=rs1 alias (A1_ALIAS_RS2=1) via INSTR_WORD_MOD @ step $STEP ==="
  A1_ALIAS_RS2=1 CONSTRAINT_CONTINUE=1 $H $A --inject --inject-step "$STEP" --inject-kind INSTR_WORD_MOD --seed 1 > logs/alias_inject.log 2>&1
  echo "inject_exit=$? (0 = verify OK = ACCEPT; nonzero = reject)"
  echo "--- fault + verdict ---"
  grep -iE '<fault>|<constraint_fail>|"output"|context.:.Prover., .status|context.:.Verifier., .status' logs/alias_inject.log | head -12
fi

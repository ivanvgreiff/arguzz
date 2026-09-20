#!/bin/bash
cd /root/workspace
H=./target/release/risc0-host
ARGS="--in0 7 --in1 0 --in4 0"   # x=7; honest remu s0,a0,a0 = 0
echo "kind|seed|prover|verifier|output|fault"
for K in COMP_OUT_MOD POST_EXEC_REG_MOD PRE_EXEC_REG_MOD PRE_EXEC_MEM_MOD; do
  for S in 3 11; do
    o=$($H $ARGS --inject --inject-step 290 --inject-kind $K --seed $S 2>&1)
    pv=$(echo "$o" | grep -oE '"context":"Prover", "status":"[a-z]+"' | tail -1 | grep -oE '[a-z]+"$' | tr -d '"')
    vf=$(echo "$o" | grep -oE '"context":"Verifier", "status":"[a-z]+"' | tail -1 | grep -oE '[a-z]+"$' | tr -d '"')
    op=$(echo "$o" | grep -oE '"output":"[^"]*"' | tail -1)
    ft=$(echo "$o" | grep -oE '<fault>[^<]*</fault>' | tail -1 | cut -c1-70)
    echo "$K|$S|${pv:-PANIC}|${vf:-none}|${op:-none}|$ft"
  done
done

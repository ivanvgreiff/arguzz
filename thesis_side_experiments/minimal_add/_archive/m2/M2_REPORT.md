# M2 Report — A4 Witness Mutation (a1 READ 4→9)

**Status:** PASS

## Mutation
- Config: `artifacts/m2/a4_mutation.json`
- step=185, txn_idx=15057, word 4→9, strategy=next_read

## Isolation (witness-effective add-cycle state)

Preflight `A4_DUMP_STEP` txns are **pre-witness**; effective mutation from `<a4_pre_exec_reg_mod>`.

| reg | op | preflight word | witness word | prev_word | expected |
|-----|-----|----------------|--------------|-----------|----------|
| a0 | READ | 3 | 3 | 3 | 3 / 3 |
| a1 | READ | 4 | **9** | 4 | 4→**9** / 4 |
| s0 | WRITE | 7 | 7 | 0 | 7 / 7 |

A4_DUMP_STEP reflects preflight trace (a1 word still 4); witgen rewrites txn 15057 word to 9 per <a4_pre_exec_reg_mod>. s0 WRITE stays 7 in both preflight and witness.

**Isolation confirmed.**

## Failures (deduped)

### phase=local
- `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)` value=2013265916
- `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:22) at  MemoryRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :90:10)))` value=2013265916

### phase=accum
- *(none)*

## GLOBAL (Hook 3 + final residue)

- **memory**: nonzero=True
- **u16**: nonzero=False
- **u8**: nonzero=False
- **cycle**: nonzero=False
- **A4_GLOBAL_RESIDUE**: nonzero=True

## Constraint provenance

### `MemoryWrite(zirgen/circuit/rv32im/v2/dsl/mem.zir:99)`
- ZIR `/root/arguzz/zirgen/zirgen/circuit/rv32im/v2/dsl/mem.zir:99` verbatim: `io.newTxn.dataLow = data.low;`
- Form: `io.newTxn.dataLow = data.low  (MemoryWrite / AddU32 rs1+rs2=rd)`
- lhs=7, rhs=12; Predicted `(lhs-rhs) mod p` = **2013265916**; observed **2013265916**; match=True
- Witness isolation: recorded s0 write stays 7 while circuit recomputes AddU32(rs1=3, rs2=9)=12. Residue equals IsRead@79 (p-5) because +5 read corruption propagates linearly through addition (12=7+5); residue alone is ambiguous under linear propagation.

### `loc(callsite( IsRead ( zirgen/circuit/rv32im/v2/dsl/mem.zir :79:22) at  MemoryRe...`
- ZIR `/root/arguzz/zirgen/zirgen/circuit/rv32im/v2/dsl/mem.zir:79` verbatim: `io.oldTxn.dataLow = io.newTxn.dataLow;`
- Form: `io.oldTxn.dataLow = io.newTxn.dataLow`
- lhs=4, rhs=9; Predicted `(lhs-rhs) mod p` = **2013265916**; observed **2013265916**; match=True

## Add-universe subset check
- All failing locs in 37-member Add universe: **True**

exit_code: **101**

**Opus gate:** M2 acceptance met. Await greenlight for **M3**.

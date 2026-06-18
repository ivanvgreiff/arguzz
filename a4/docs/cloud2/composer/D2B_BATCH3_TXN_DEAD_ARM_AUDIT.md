# B.4/B.5 Txn-Field Dead-Arm Audit — Composer Independent Verification

**Date:** 2026-06-18  
**Subject:** Mechanistic proof for `TXN_ADDR_MOD` (B.4) and `TXN_CYCLE_PHASE_MOD` (B.5) dead arms  
**Kickoff:** [`D2B_BATCH3_TXN_DEAD_ARM_AUDIT_KICKOFF.md`](./D2B_BATCH3_TXN_DEAD_ARM_AUDIT_KICKOFF.md)  
**Predecessor bar:** [`D2B_BATCH2_DEAD_ARM_AUDIT.md`](./D2B_BATCH2_DEAD_ARM_AUDIT.md)  
**Verdict:** **TRUE DEAD ARM (mechanism-proven)** for both B.4 and B.5 on sha2-host user-instruction memory txns. **NOT W-16.**

---

## Pre-kickoff sanity (executed)

```bash
cd /root/arguzz
git rev-parse --abbrev-ref HEAD   # → cloud2
git log --oneline -3
# f81523c d2.b batch 2
# 78d036c Batch 1.5e D2.B
# 3a8487c Check d1.c

git status   # Batch 3 work in working tree, uncommitted
```

Empirical baseline unchanged: B.4 and B.5 attestation xfails with guard firing + verifier accept (see [`D2B_BATCH3_COMPOSER_REPORT.md`](./D2B_BATCH3_COMPOSER_REPORT.md)).

---

## 1. Terminology (precision required)

| Term | Meaning for B.4 | Meaning for B.5 |
|------|-----------------|-----------------|
| **Trace mutation** | `trace.txns[i].addr` changed in RAM before witgen — **TRUE** (Layer 3 dump) | `trace.txns[i].cycle` LSB flipped — **TRUE** (Layer 3 dump) |
| **Witness mutation** | Committed witness columns for **address** derived from mutated trace `addr` — **FALSE** | Committed witness columns for **read/write phase** derived from mutated trace LSB — **FALSE** |
| **No-op** | Nothing changed — **WRONG** (trace changed) | Same |
| **Dead arm** | Trace field mutated but no witness column ever reflects the mutated value; constraints unchanged | Same |
| **Soundness bug (W-16)** | Witness column reflects mutated value, constraints accept corrupted witness — **RULED OUT** | **RULED OUT** |

**Composer label correction:** This is **not** the W-17 `set_cycle`/`exec_Reg` overwrite class. It is a distinct **W-18 execution-derived witness key** class: the circuit passes execution-derived `addr` and `memCycle` into `MemoryIO`; `extern_getMemoryTxn` returns only `prevCycle`, `prevWord`, and `word` from trace — not `addr` or phase.

---

## 2. Hypothesis statements (from Batch 3 report) — verdict

| Hypothesis | Verdict |
|------------|---------|
| B.4: "`txn.addr` is execution-derived in witness columns; trace `addr` is only a lookup key re-checked against execution-side addr" | **CONFIRMED** — see §3 |
| B.5: "`txn.cycle` LSB encodes phase but witness uses execution-derived `memCycle` (2×cycle or 2×cycle+1), not trace LSB" | **CONFIRMED** — see §4 |

---

## 3. Source-level trace for B.4 (`txn.addr`)

### 3a. Preflight population

`preflight.rs:592-598` (load) and `618-624` (store) record txns from **execution** address and cycle:

```592:598:workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/preflight.rs
            let txn = RawMemoryTransaction {
                addr: addr.0,
                cycle,
                word,
                prev_cycle,
                prev_word: word,
            };
```

`cycle` is `(2 * trace.cycles.len())` for reads or `(2 * len + 1)` for writes — execution-derived at record time.

### 3b. Extern reads of `txn.addr`

Grep of `ffi.cpp` for `preflight.txns` / `txn.addr`:

| Extern | Reads `txn.addr`? | Returns `addr`? | Role |
|--------|-------------------|-----------------|------|
| `extern_getMemoryTxn` | **Yes** — compares to argument | **No** | Sanity check only; returns prevCycle/prevWord/word |
| `extern_hostReadPrepare` | via txnIdx | No (returns word) | Host I/O |
| `extern_hostWrite` | via txnIdx | No (returns word) | Host I/O |

**No `extern_getAddr` or similar** returns `txn.addr` into witness columns.

### 3c. `extern_getMemoryTxn` — the critical path

```171:223:workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp
std::array<Val, 5> extern_getMemoryTxn(ExecContext& ctx, Val addrElem) {
  uint32_t addr = addrElem.asUInt32();
  size_t txnIdx = ctx.preflight.cycles[ctx.cycle].txnIdx++;
  const MemoryTransaction& txn = ctx.preflight.txns[txnIdx];
  // ...
  if (txn.addr != addr) {
    // FAULT_INJECTION_ENABLED → skip throw; else throw
  }
  return {
      txn.prevCycle,
      txn.prevWord & 0xffff,
      txn.prevWord >> 16,
      txn.word & 0xffff,
      txn.word >> 16,
  };
}
```

**Key facts:**

1. **`addrElem` is a circuit argument** — execution-derived address passed from DSL, not read from mutated trace into witness.
2. **`txn.addr` is compared but never returned** — mutation creates mismatch; witness addr columns come from `addrElem`.
3. **Returned fields** (`prevCycle`, `prevWord`, `word`) are exactly the B.1/B.2 live path — mutating only `addr` leaves these unchanged in trace.

### 3d. DSL constraints — address is execution-supplied

`mem.zir:65-75`:

```
component MemoryIO(memCycle: Val, addr: Val) {
  ret := GetMemoryTxn(addr);
  public oldTxn := MemoryArg(-1, addr, ret.prevCycle, ret.prevData);
  public newTxn := MemoryArg(1, addr, memCycle, ret.data);
  // ...
  newTxn.addr = addr;
}
```

Generated `steps.cpp:745-769`:

```745:769:workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp
auto [x3, x4, x5, x6, x7] = INVOKE_EXTERN(ctx,getMemoryTxn, arg1_0);
MemoryArgStruct x8 = exec_MemoryArg(ctx,Val(2013265920), arg1_0, x3, ...);
MemoryArgStruct x9 = exec_MemoryArg(ctx,Val(1), arg1_0, arg0, ...);
// ...
Val x14 = (x9.addr._super - arg1_0);
EQZ(x14, "MemoryIO(...)");
```

- `arg1_0` = execution address from instruction semantics  
- `arg0` = execution `memCycle`  
- Witness `oldTxn.addr` / `newTxn.addr` are constrained to **`arg1_0`**, not `txn.addr` from trace  
- `MemoryArg` calls `extern_memoryDelta(addr, cycle, ...)` with these execution-derived values (`mem.zir:30`)

**B.4 mutation effect:** trace `txn.addr` ≠ execution `addrElem` → sanity check fails → with FIE, throw suppressed → returned prevCycle/prevWord/word unchanged → **no witness column carries mutated addr** → Hook 3 `memory` family balanced → verifier accepts proof of original execution.

### 3e. FAULT_INJECTION_ENABLED disambiguation

**Dispatcher set site:**

```275:281:workspace/risc0-modified/risc0/circuit/rv32im/src/prove/witgen/mod.rs
        if let Ok(config_path) = std::env::var("A4_MUTATION_CONFIG") {
            if std::env::var("A4_NO_FAULT_INJECTION").is_err() {
                unsafe { std::env::set_var("FAULT_INJECTION_ENABLED", "1"); }
```

**What FIE suppresses (static — Option α):**

| Site | Effect |
|------|--------|
| `ffi.cpp:199-213` | Skip throw on `txn.addr != addrElem` |
| `ffi.cpp:186-195` | Skip throw on `txn.cycle/2 != ctx.cycle` |
| `steps.cpp` (~40 sites) | Skip throw on unreachable mux arms during bad execution paths |

**What FIE does NOT suppress:**

| Channel | Evidence |
|---------|----------|
| Hook 3 family residue (`A4_FAMILY_RESIDUE`) | `extern_memoryDelta` / `extern_lookupDelta` have no FIE branches |
| `verify segment` panic | Host verifier path; unrelated to FIE |
| EQZ constraint failures | Normal constraint path; FIE only bypasses **throws**, not EQZ |

**Empirical — Option β:** Re-ran B.4 with `A4_NO_FAULT_INJECTION=1`:

```
exit 101
<a4_fault_injection_enabled/> absent
[16574]: txn.addr: 0x30000001, addr: 0x3fffc003
thread 'main' panicked at host/src/main.rs:150:13
```

Without FIE: witgen **panics** on addr mismatch (runtime throw), not C1/C2/C3 rejection. With FIE (default attestation): witgen completes, all channels silent, verifier accepts.

**Root-cause ruling for B.4 silence:**

| Candidate | Ruled? | Reason |
|-----------|--------|--------|
| **(a) True dead arm** | **YES** | Witness addr never bound to mutated trace field |
| **(b) Soundness bug** | **NO** | Witness uncorrupted; proof attests original execution |
| **(c) FIE silencing rejection channels** | **NO** | FIE suppresses **throws** only; Hook 3 / verify segment unaffected. Silence is structural dead arm, not masked C1/C2/C3 |

**Spec correction:** Spec §3.4 claimed FIE "produce constraint failures instead" of panic. Empirically FIE allows witgen to **continue past the mismatch** without producing constraint failures — because witness columns never incorporated the mutated addr. FIE is a **witgen survival hook**, not a rejection-channel substitute.

---

## 4. Source-level trace for B.5 (`txn.cycle` LSB / phase)

### 4a. Preflight population

Same as §3a — `cycle` set at record time from execution: even = read `(2*len)`, odd = write `(2*len+1)`.

### 4b. Python/Rust phase logging vs witness

`mod.rs:818-821` flips LSB: `new_cycle = old_cycle ^ 1`. Logging uses `txn.cycle % 2` for READ/WRITE labels — **diagnostic only**, not witness path.

### 4c. Extern use of `txn.cycle`

| Extern | Uses `txn.cycle`? | Returns phase? |
|--------|-------------------|----------------|
| `extern_getMemoryTxn` | **Yes** — `txn.cycle/2 != ctx.cycle` sanity check | **No** — returns prevCycle (prior chain link), not current txn.cycle LSB |
| Others | No direct txn.cycle reads in ffi.cpp | — |

LSB XOR preserves `cycle/2` (e.g. 33148→33149 both map to cycle index 16574), so the sanity check in `getMemoryTxn` **still passes** even after mutation.

### 4d. DSL phase classification — execution-derived

`mem.zir:88-101`:

```
component MemoryRead(cycle: Reg, addr: Val) {
  io := MemoryIO(2*cycle, addr);    // memCycle = even → READ
  IsRead(io);
}
component MemoryWrite(cycle: Reg, addr: Val, data: ValU32) {
  public io := MemoryIO(2*cycle + 1, addr);  // memCycle = odd → WRITE
}
```

Phase is encoded in **`memCycle` argument** (`2*cycle` or `2*cycle+1`) from the **execution register `cycle`**, not from `trace.txns[i].cycle` LSB.

`IsRead` (`mem.zir:78-80`) constrains `oldTxn.data == newTxn.data` — does not read trace phase bit.

**B.5 mutation effect:** trace LSB flipped; `getMemoryTxn` sanity check still passes (same `cycle/2`); returned prevCycle/prevWord/word unchanged; witness `newTxn.cycle = memCycle` from execution → **no witness column reflects mutated LSB** → all channels silent → verifier accepts.

### 4e. FIE for B.5

Same analysis as §3e. Cycle mismatch throw at `ffi.cpp:186-195` is FIE-suppressible, but LSB-only flip does not trigger it. B.5 silence is **not** FIE masking — it is execution-derived `memCycle`.

---

## 5. Disambiguation tests — summary

**Method:** Option α (static FIE enumeration) **plus** Option β (empirical `A4_NO_FAULT_INJECTION=1` on B.4).

**Conclusion:** FIE is necessary for B.4 witgen to complete (otherwise panic), but FIE does **not** explain silent C1/C2/C3 on default attestation runs. The dead arm is structural: mutated fields never enter witness columns that constraints bind.

---

## 6. Comparison table — txn 15415 step 1 (sha2-host)

| Mutation | Field mutated | Witness path (audit) | Constraint that would fire if witness saw mutation | Actual channel |
|----------|---------------|----------------------|---------------------------------------------------|----------------|
| B.1 `TXN_PREV_WORD_MOD` | `prev_word` | `getMemoryTxn` → returns prevWord → `oldTxn` → `memoryDelta` | Memory permutation / IsRead imbalance | **`memory` Hook 3** |
| B.2 `TXN_PREV_CYCLE_MOD` | `prev_cycle` | `getMemoryTxn` → returns prevCycle → `oldTxn.cycle` → `memoryDelta` | Chain ordering / delta imbalance | **`memory` + `cycle`** |
| B.4 `TXN_ADDR_MOD` | `addr` | `getMemoryTxn(addrElem)` compares trace addr; returns **only** prevCycle/prevWord/word; witness addr = **execution `addrElem`** | Would fire if witness addr bound to mutated trace — **it is not** | **Silent; verifier accept** |
| B.5 `TXN_CYCLE_PHASE_MOD` | `cycle` LSB | Phase from `MemoryIO(2*cycle±1, addr)` execution arg; trace LSB unused in witness | Would fire if IsRead/IsForward used trace LSB — **they use execution memCycle** | **Silent; verifier accept** |

**Hypothesis stress test:** `extern_getMemoryTxn` does **not** return the entire txn structure. It returns 5 values: prevCycle, prevWord_low, prevWord_high, word_low, word_high. B.1/B.2 mutate fields in the **return tuple**; B.4/B.5 mutate fields used only for **sanity checks** (and not returned). Same extern, different fields → different live/dead outcomes. **Mechanism proven.**

---

## 7. Certainty table

| Statement | Certainty | Source |
|-----------|-----------|--------|
| B.4 trace `addr` mutated | 100% | Layer 3 dump + attestation |
| B.4 witness column for addr is execution-derived (`addrElem`), not trace | 100% | `mem.zir:65-75`, `steps.cpp:748-769`, `ffi.cpp:171-223` |
| B.4 dead arm on sha2-host user memory txns | 95% | Composition of above + attestation |
| B.4 dead arm on ALL guests / cycle types | 70% | Paging/host paths may differ; not exhaustively traced |
| B.4 NOT a soundness bug | 100% | Witness uncorrupted |
| FIE ruled out as masking C1/C2/C3 for B.4 | 100% | §3e static + Option β |
| B.5 trace `cycle` LSB mutated | 100% | Layer 3 dump + attestation |
| B.5 witness phase is execution-derived `memCycle` | 100% | `mem.zir:88-101`, `steps.cpp:762` |
| B.5 dead arm on sha2-host user memory txns | 95% | Composition + attestation |
| B.5 dead arm on ALL guests / cycle types | 70% | Same qualification as B.4 |
| B.5 NOT a soundness bug | 100% | Witness uncorrupted |
| FIE ruled out as masking C1/C2/C3 for B.5 | 100% | §4e; LSB flip doesn't even trigger cycle mismatch throw |

---

## 8. Verdict

| Kind | Verdict |
|------|---------|
| **B.4 `TXN_ADDR_MOD`** | **TRUE DEAD ARM (mechanism-proven)** — promote to **W-18** |
| **B.5 `TXN_CYCLE_PHASE_MOD`** | **TRUE DEAD ARM (mechanism-proven)** — promote to **W-18** |

**Not SOUNDNESS BUG SUSPECTED.** Safe to proceed with Batch 3 commit (pending Ivan/Opus review of this doc).

---

## 9. Reconciliation rule

N/A — verdict is TRUE DEAD ARM for both kinds.

---

## Appendix A1 — B.6/B.7 extern read path enumeration

Grep performed on `workspace/risc0-modified/risc0/circuit/rv32im-sys/kernels/cxx/`:

```bash
grep -r 'extern_getPc\|extern_getState' ...   # → no matches
grep -r 'cycles\[.*\]\.pc' ...               # → witgen.h:189 only (debug helper)
grep -r 'cycles\[.*\]\.state' ...            # → no matches
grep 'preflight.cycles' ffi.cpp               # → getMajorMinor, nextPagingIdx, getDiffCount context
```

| Field | Direct trace read in ffi.cpp? | Witness path |
|-------|------------------------------|--------------|
| `cycle.pc` | **No extern** | `set_cycle` preset → `step_Top` `exec_Reg(newPc)` overwrite (W-17) |
| `cycle.state` | **No extern** | `set_cycle` preset → `step_Top` `exec_Reg(newState)` overwrite (W-17) |
| `cycle.machine_mode` | `extern_nextPagingIdx` (paging only) | W-17 with paging caveat (Batch 2 audit) |
| `cycle.diff_count[]` | `extern_getDiffCount` | **LIVE** (B.8 confirmed) |

B.6/B.7 dead-arm classification on sha2-host user-instruction cycles remains **high-confidence**; global "never live on any cycle type" claim still qualified per W-17 paging caveat.

---

## Appendix A2 — Broader manual scan (not in pytest)

Attestation tests use **first valid target only**. Manual scan parameters and outcomes:

### B.4 `TXN_ADDR_MOD`

| Step | txn_idx (sample) | addr region | Outcome |
|------|------------------|-------------|---------|
| 1 | 15415 | register-adjacent heap | Dead — all channels silent, verifier accept |
| 16 | first valid per module | memory | Dead |
| 24 | first valid | memory | Dead |
| 26 | first valid | memory | Dead |
| 28 | first valid | memory | Dead |
| 100 | first valid | memory | Dead |
| 500 | first valid | memory | Dead |
| 1000 | first valid | memory | Dead |
| 1 | 15474 | heap `0x4000` | Dead |

**Consistency:** 100% dead across scanned targets on sha2-host.

### B.5 `TXN_CYCLE_PHASE_MOD`

| Step | Scope | Outcome |
|------|-------|---------|
| 1 | all non-fetch txns at step | Dead |
| 100 | first valid txn | Dead |
| 500 | first valid txn | Dead |
| 1000 | first valid txn | Dead |

**Consistency:** 100% dead across scanned targets.

**Recommendation accepted (Opus Issue 4):** Document here rather than parametrize attestation (runtime cost). Future regression sentinel optional post-D2.G.

---

## Composer pushback on Opus review

| Opus issue | Composer response |
|------------|-------------------|
| Issue 1 — mechanism unproven | **Agree** — this doc closes the gap; verdict TRUE DEAD ARM |
| Issue 2 — inverted AUDIT NOTE | **Agree** — patched in attestation tests |
| Issue 3 — B.4 cascade too permissive | **Agree** — tightened to `[]`; Rust handler only touches `addr` |
| Issue 4 — broader scan not in suite | **Agree** — §A2 documents scan; parametrization deferred |
| Issue 5 — B.6/B.7 non-user cycles | **Agree** — already qualified; §A1 adds grep evidence |
| Minor §9c scope | **Agree** — postscript may remove B.3+B.4+B.5+B.6+B.7 (5 dead kinds) |

**Nuanced pushback:** Root cause (c) "FIE silencing" is **partially mislabeled** in the kickoff trichotomy. FIE enables witgen survival on addr mismatch but does **not** suppress Hook 3 or verify segment. The observable silence on default runs is **(a) true dead arm**, not masked rejection. FIE matters for **methodology** (without it, B.4 crashes rather than producing a proof) but not for explaining silent C1/C2/C3.

**Nuanced pushback on spec §3.4:** Original spec claimed FIE converts addr violations into constraint failures. Audit shows FIE skips the throw and witgen proceeds with execution-derived witness — **no constraint failure either**. Spec updated accordingly.

# Test plan — non-alias `rs2` substitution, and resolving the decode / memory-argument model

**STATUS: EXECUTED & RESOLVED (existing hooks only, no rebuild).** The plan's questions are answered below;
the full plan (phases/hypotheses) follows for the record.

## RESULTS (measured)
Diagnostics used: `A4_TRACE_TXN` (requested-vs-consumed addr per access), `A4_FAMILY_RESIDUE`+`A4_COVERAGE_TOUCH`
(per-argument balance), `A4_GLOBAL_RESIDUE`, `CONSTRAINT_CONTINUE`. Logs: `b2_tracetxn.log`, `g5_tracetxn.log`,
`b2_nonalias_x9.log`, `g5_nonalias_x9.log`.

| mutation | B2 (vuln) | G5 (patched) | catch |
|---|---|---|---|
| `a1→a0` (alias, rs1==rs2) | **ACCEPT** (wrong output 0) | **REJECT** | G5: `load_rs2` reads once → writeback desync. B2: none. |
| `a1→x9` (`remu x14,x10,x9`, non-alias) | **REJECT** (memory residue ≠0) | **REJECT** (memory residue ≠0) | global **memory permutation argument**, both binaries |

- **Q1 (decode source): the circuit decodes the ORIGINAL word** — `A4_TRACE_TXN` shows the fetch consuming word
  `0x02b57733` (original `remu a4,a0,a1`) and the rs2 read **requesting a1 (`0x3fffc02b`)**. H1 refuted, H2
  confirmed.
- **Q2 (B2 balance): self-cancellation.** The rs2 read requests a1 but consumes the second-a0 txn
  (`0x3fffc02a`, value 9), which is a **same-cycle re-read** (`prev_cycle == cycle == 21126`). Its two
  memory-argument records `(a1, C, 9, +1)` and `(a1, C, 9, −1)` are identical → cancel → invisible → B2's
  memory residue is 0. **This is H2b with the precise mechanism (self-cancel via same-cycle), not "value
  coincidence."**
- **Q3 (non-alias): REJECTED on both binaries.** `a1→x9` makes the rs2 read consume the x9 txn (value 12345),
  whose `prev_cycle` is an earlier cycle, so the records `(a1, C, 12345)` and `(a1, x9_prev, …)` do **not**
  cancel → memory residue ≠ 0 → reject. (0 local `constraint_fail`s; the catch is the global permutation.)
  **H3 (broad operand-substitution hole) is REFUTED.** Note x9=12345 so output was unchanged, yet B2 still
  rejected — the catch is independent of output divergence.
- **Q4 (reconciliation):** the bug is **same-register / same-cycle**. The global memory permutation already
  catches every non-same-register substitution; the alias escapes only because the same-cycle re-read makes
  its spurious records self-cancel. The patch then closes the alias via `load_rs2` (read once → writeback
  desync). Full write-up in `CVE_CONSTRAINT_AUDIT_PLAN.md` PART −1 + STEP 6d.

---

**(Original plan for the record — status: PLAN for review; now executed above.)**

## 0. The gap, stated honestly
The current "STEP 6d" model says: the circuit decodes the **original** fetched word (`remu a4,a0,a1`), the
patched `load_rs2` records one fewer read for the `rs1==rs2` execution, and under fault injection
`extern_getMemoryTxn` **suppresses its address/cycle-mismatch throws** and returns the indexed transaction's
data regardless of address — so the circuit consumes transactions shifted by one.

That model has **two unresolved problems**:
1. **B2 memory balance.** If B2's circuit decodes the original and issues a read **for a1**, that read consumes
   the executor's *second a0* transaction (value 9). Recorded at addr `a1` with value 9, it should break a1's
   memory-permutation chain (a1's real value is 12602) → non-zero memory residue. **But B2's measured memory
   residue is 0.** So either the circuit does *not* read a1 (it reads a0 → it decoded the *mutated* word), or
   the record uses a0's address/value, or the memory argument works differently than assumed.
2. **The `a1→a3` question (the user's).** If address mismatches are suppressed and the transaction count stays
   aligned, a *non-alias* substitution (rs2 a1→a3, still two reads) should be **transaction-compatible** and
   accepted on both B2 and G5 — in which case the bug is a broader operand-substitution issue, not the
   same-cycle/same-register bug. If instead it is *caught*, we must identify the exact constraint that catches
   a1→a3 but not a1→a0.

These two are linked: both turn on **which register address the circuit actually requests for the rs2 read,
and what the memory argument does when the consumed transaction's address differs.**

## 1. Questions to resolve (each must end with a measured answer)
- **Q1 — Decode source:** for the `remu` cycle, what register address does the circuit *request* for rs1 and
  for rs2? (a1 ⇒ decodes original; a0 ⇒ decodes mutated.) On both B2 and G5.
- **Q2 — Memory balance:** given Q1, how does B2's memory residue come out 0? (What addr/value/cycle do the
  bogus read's records carry, and what do they cancel against?)
- **Q3 — Non-alias substitution:** for `rs2: a1→r` with `r ∉ {a0,a1}` (still two distinct source regs), does
  B2 accept or reject? Does G5? If reject, the exact failing constraint; if accept, does the committed output
  change?
- **Q4 — Reconciliation:** a single model that explains (alias accepted on B2 / rejected on G5) **and**
  (whatever non-alias does) **and** B2's zero residue — with the patch's role made precise.

## 2. ARGUZZ capability notes (what we can and cannot force)
- **Executor-path** (`--inject --inject-kind INSTR_WORD_MOD --seed S`): the mutation is **random**
  (`random_word`), seeded by `S`. We cannot dictate the resulting word; we **cycle seeds** and decode the
  emitted `<fault>` word to find one we want. This is the path the CVE race actually used, so it is the
  authoritative one for the soundness claim.
  - The `remu` word is `45446963` = `remu x14,x10,x11` (rd=a4, rs1=a0=x10, rs2=a1=x11). The rs2 field is bits
    24:20. A **single-bit flip** (strategy-0) of an rs2 bit moves rs2 from `01011` to: bit20→`01010`=x10 (a0,
    the alias), bit21→`01001`=x9 (s1), bit22→`01111`=x15 (a5), bit23→`00011`=x3 (gp), bit24→`11011`=x27 (s11).
    So **a1→{s1,a5,gp,s11} are single-bit-reachable non-alias substitutions** — findable by cycling seeds
    (≈4 of the ~30 strategy-0 single-bit targets land in the rs2 field as non-alias). a1→a3 specifically needs
    a 2-bit flip (strategy-1), rarer; any non-alias r works for Q3, so we take the first we find.
  - The substituted register `r`'s **value** is a runtime value (the guest sets only a0=9, a1=12602, a2=9,
    a3=12602). We measure r's value from the trace; pick a found mutation where `9 % r_value ≠ 9` so the
    committed output diverges (cleaner oracle), but we record the verifier result regardless.
- **Witgen-path** (`A4_MUTATION_CONFIG={...,"mutation_type":"INSTR_WORD_MOD","step":S,"word":W}`): lets us
  **force the exact word** W (e.g. compute the word for `remu a4,a0,a3`). **Caveat:** this mutates the *fetch
  transaction* during witness generation, **not** the execution — so the executor ran the *original* (recorded
  reads of a0 and a1), while the circuit decodes the forced word. This is a *different* injection point from
  the CVE; it is useful as a **controlled probe of the decode-vs-trace binding**, but its result must not be
  conflated with the executor-path (CVE) result.

## 3. Phase 0 — read the remaining code to close the gap analytically (no runs)
Targets (risc0-modified, the patched tree; B2 = risc0-a1-vuln has the analogous code):
- `extern_memoryDelta` and the global memory-argument computation (the grand-product / diff-count check): what
  exactly is summed; is the record's addr the circuit's computed addr or the consumed txn's addr; does
  `wrap_memory_txns` rewrite addresses/values before the argument is formed.
- `MemoryArg` / `MemoryIO` witness-fill (the generated "back"): confirm `newTxn.addr` = circuit's computed addr
  and `newTxn.data` = consumed txn's `word`.
- `wrap_memory_txns` (preflight.rs:216-234) in full, including the `prev_cycle`/`orig_words` reset and the
  `diff = cycle - 1 - prev_cycle` (the patched `IsForward`) and how `diff_count` feeds the cycle argument.
- The order of phases: when `wrap_memory_txns` runs relative to the witgen step that consumes txns (decode).
Deliverable: a precise statement of what the circuit's rs2-read record contains and how it can (or cannot)
balance — which should either resolve Q2 or sharpen exactly what to measure.

## 4. Phase 1 — the decisive diagnostic: `A4_TRACE_TXN` (fast; likely resolves Q1 + Q2)
`extern_getMemoryTxn` prints under `A4_TRACE_TXN=1`:
`getMemoryTxn(<cycle>, <requested_addr>): txn(txnId, cycle, addr, word)` — i.e. **the address the circuit
requested vs the transaction's actual address and word**, for every memory access. Run on **both** binaries at
the `remu` cycle and read off, in order, the four accesses (fetch, read#1, read#2-or-write, write):

```
# B2 (vuln), step 444:
A4_TRACE_TXN=1 A4_INSPECT=1 CONSTRAINT_CONTINUE=1 risc0-host \
  --ctrl 7 --gseed 12345 --rounds 5 --inject --inject-step 444 --inject-kind INSTR_WORD_MOD --seed 1238004099
# G5 (patched), step 478: same with the G5 binary and --inject-step 478
```
Read the `getMemoryTxn(...)` lines for the remu cycle. **This directly answers Q1:** the requested addr of the
2nd source read is `a1` (⇒ circuit decoded original) or `a0` (⇒ decoded mutated). And it shows, for each, the
consumed txn's addr+word — answering whether the bogus read consumes a0's transaction and at what value
(Q2 input). (Output is large; filter to the remu cycle index — 10563 on B2, 16784 on G5.)
**Expected discriminator:**
- If B2's reads request `a0` then `a0` → the circuit decoded the **mutated** word; the "decode original"
  claim in STEP 6d is wrong and must be corrected (and B2's balance is explained: both reads are real a0).
- If B2's reads request `a0` then `a1` (consuming an a0 txn) → the circuit decoded the **original**; then Q2
  (why memory still balances) must be answered from Phase-0 code reading + the family-record dump.

## 5. Phase 2 — the non-alias substitution experiment (executor-path; authoritative for Q3)
**Step 2a — find a seed.** Script: for `S` in a range, run the binary with `--trace`, capture the `<fault>`
word, decode it, and keep the first `S` whose mutated word is `remu x14,x10,r` with `r ∉ {10,11}` (opcode
0x33, f3 7, f7 1, rd 14, rs1 10, rs2 = r). (Decode helper already used in the audit.) Record `r` and, from a
trace/txn dump, `r`'s register value.

**Step 2b — run the found mutation on B2 and G5** with the full diagnostic set, capturing exactly:
1. committed output (vs honest 9000027) and verifier status;
2. `<constraint_fail>` count + locations (and the failing pc);
3. `A4_DUMP_ALL_TXNS` + `A4_INSPECT` — the remu-cycle transactions (fetch / reads / write, addrs+words);
4. `A4_TRACE_TXN` — requested vs consumed addr for each access (does the circuit's "a1" read consume the
   r-read transaction? does the r-read's address bind?);
5. `A4_FAMILY_RESIDUE` + `A4_COVERAGE_TOUCH` + `A4_GLOBAL_RESIDUE` — memory/cycle/u8/u16 + global residue;
6. whether the residual (if any) tracks `r`'s value, a0's value, or a downstream instruction word (as the
   alias case's `17975 − a0` tracked the next `lui` word).

**Also run** the same with a benign mutation (e.g. an rd-only change like the earlier seed 11) as a control,
and the alias mutation (seed 1238004099) re-run in the same session, so all three sit side by side.

## 6. Phase 3 — controlled forced substitution (witgen-path; probe only, with caveat)
Compute `W = remu a4,a0,a3` (and/or `remu a4,a0,a5`). Run with
`A4_MUTATION_CONFIG=<file with {"mutation_type":"INSTR_WORD_MOD","step":S,"word":W}>` on B2 and G5, same
diagnostics. **Interpretation caveat (must be stated in any conclusion):** this mutates the *fetch transaction*
(circuit decode input), while the executor ran the original (reads a0,a1). So it isolates "circuit decodes a
substituted word while the recorded reads are the original" — a clean test of the decode-vs-trace binding, but
**not** the executor-path CVE scenario. Use it to cross-check Phase 1's Q1 answer, not as the CVE result.

## 7. Decision tree (what each outcome means)
| Phase-2 outcome (executor-path, non-alias a1→r) | Interpretation |
|---|---|
| **B2 rejects** | A constraint catches distinct-register substitution. Identify it (from the constraint_fail/residue) and explain why it does **not** fire for a1→a0. (Most likely: the r-read's address/value can't balance the memory argument, whereas the a0 re-read can.) |
| **B2 accepts, G5 rejects** | The patch's effect is broader than `load_rs2`'s read-count; identify which patched constraint (e.g. tightened `IsForward`, or a decode binding) rejects non-alias on G5. |
| **B2 accepts, G5 accepts, output unchanged** | Not an oracle-visible bug (e.g. `9 % r = 9`); says nothing about soundness — re-pick `r` so the output changes. |
| **B2 accepts, G5 accepts, output changes** | **Serious:** the harness accepts a general operand substitution, i.e. the proof is not bound to the committed program's `rs2` field at all. This would mean INSTR_WORD_MOD-style tampering is broadly accepted and the "rs1==rs2" framing is too narrow — to be reconciled before any thesis claim. |

Phase-1 (`A4_TRACE_TXN`) cross-checks all of these by showing the requested-vs-consumed addresses directly.

## 8. Working hypotheses to confirm or kill (stated so the experiment can falsify them)
- **H1 (decode-mutated):** the circuit actually decodes the *mutated* word (requests a0,a0 on B2), so B2's
  reads are real (balance = 0). Then G5 must reject for a different reason than "decode original ⇒ 2 reads" —
  re-derive the G5 residual (`17975 − a0`, next-insn `lui` word) under H1. *If A4_TRACE_TXN shows B2 requesting
  a0,a0, STEP 6d's "decode original" is wrong and the whole writeback-shift derivation must be redone.*
- **H2 (decode-original + a value-coincidence balance):** the circuit decodes original (requests a1), but the
  a0-re-read it consumes carries value 9 and the memory argument balances for a reason Phase-0/the family
  records will reveal (e.g. the record is keyed by the consumed txn's addr a0, not a1). Then non-alias a1→r
  consumes the r-read (value `r`), which *does* bind/chain at addr r — so the question becomes whether the
  circuit's "a1" record (addr a1, value r) breaks a1's chain → B2 rejects non-alias. *This is the model under
  which a1→a0 is special (a0's value coincides) and a1→a3 is caught.*
- **H3 (broad substitution):** address binding is genuinely absent for source reads under fault injection, so
  any rs2→r is accepted as long as the transaction count matches; a1→a0 was merely the first ARGUZZ found
  because `9 % 9 = 0` reliably changes the output. *Phase 2 "B2 accepts non-alias with changed output" confirms
  this; it would substantially change the thesis framing.*

The experiment is designed so the `A4_TRACE_TXN` requested-vs-consumed addresses (Phase 1) plus the non-alias
accept/reject + residue (Phase 2) jointly select exactly one of H1/H2/H3 and identify the binding constraint.

# AUDIT PLAN — Are the 37 `ACCEPTED` Arguzz outcomes real? (prove it, 100%)

## 0. The claim under audit

In the N=250 E5 sweep, **37 fired+tested Arguzz runs verified successfully** (`outcome_class = ACCEPTED`,
0 constraint failures, verifier `status:"success"`): **30 `POST_EXEC_PC_MOD`** and **7 `INSTR_WORD_MOD`**.
A4 had **zero** accepted. The user is (correctly) skeptical that a mutation that *fired* can be accepted,
since Arguzz mutations are recorded into the execution trace and should therefore be caught by some
constraint. This audit must determine, **with proof**, whether each acceptance is:

- **H1 — true no-op:** the mutation produced a witness *bit-identical* to the unmutated run → trivially
  valid (nothing to catch).
- **H2 — valid alternative:** the mutation *changed* the witness, but the changed witness still satisfies
  every constraint (a genuine fuzzer *evasion* / possible soundness-relevant finding).
- **BUG — false accept:** our pipeline mislabeled a run as ACCEPTED (parsing miss, wrong classifier,
  dump incompleteness, nondeterminism). **This is what we must rule out with certainty.**

## 1. Why a witness-level diff is necessary AND sufficient (the soundness backbone)

The rv32im-v2 prover reduces to a **witness** consumed by the constraint system:

- `trace.cycles[]` — per executed cycle: `(user_cycle/step, pc, major, minor, txn_idx)`
- `trace.txns[]` — per memory/register access: `(addr, cycle, word, prev_cycle, prev_word)`

**Every** constraint we classify (intrastep `MemoryWrite`, interstep `IsRead`/`IsCycle`, decode
`DecodeInst`/`VerifyOpcode*`, and the global memory/cycle/register permutation residues) is a pure
function of `cycles[] ⊕ txns[]`. Therefore:

> If the full `(cycles, txns)` witness of a mutated run is **identical** to the unmutated run, then **no
> constraint can possibly differ** → acceptance is provably valid (H1). If it differs, the diff localizes
> the exact changed rows, and each must be shown to keep every binding constraint satisfied (H2), or it
> contradicts the ACCEPTED label (BUG).

`A4_INSPECT` dumps all `cycles[]` (`<a4_cycle_info>`) and `A4_DUMP_ALL_TXNS` dumps all `txns[]`
(`<a4_all_txn>`). These dumps are the audit's ground truth — **not** our log parser. We additionally keep
the cryptographic verifier verdict as an independent oracle.

## 2. Injection mechanics already established (from `execute/rv32im.rs`)

- **`POST_EXEC_PC_MOD`** (`step()` line ~681): runs *after* `exec_rv32im` already advanced the PC.
  `new_pc = random_pc(pc)` uses the **original instruction pc** (local var), then `ctx.set_pc(new_pc)`.
  `random_pc` returns `pc ± steps`, `steps=4` with prob 1/6. So `new_pc = pc+4` happens ~1/6 of the time;
  for a **sequential / not-taken** instruction the natural next pc is *already* `pc+4`, so `set_pc(pc+4)` is
  a no-op overwrite. **Prediction (H1):** every accepted `POST_EXEC_PC` has `new_pc == pc+4` AND the
  site instruction is non-control-flow (or a not-taken branch); the witness is identical.
  Resolves the "+8" worry: it is `original_pc + 4`, never `post_exec_pc + 4`.
- **`INSTR_WORD_MOD`** (`step()` line ~656): word is loaded from memory (original), then replaced by
  `random_word(word)` (always a *different valid* instruction) and fed to `exec_rv32im(new_word)`.
  **Open question:** is the executed word bound to committed program memory, and which of the 32 bits does
  the decode constrain? **H1 prediction** for `ecall rs1`-flip: ECALL ignores `rs1`, so the produced txns
  are identical. The store `imm[0]`-flip is the prime **H2 suspect** (different store address) and must be
  resolved by the diff, not by argument.

## 3. Investigation 1 — static code + constraint analysis (with proof)

**Goal:** for each mutated variable, enumerate the exact rv32im.rs code path, the trace events it can
produce, and the constraints that bind those events; predict H1/H2 per accepted case.

Tasks:
1. **Map mutation → trace events.** For `POST_EXEC_PC_MOD` and `INSTR_WORD_MOD`, document every write into
   `ctx` (set_pc / store_* / exec effects) and how witgen turns it into `cycles[]`/`txns[]` rows.
2. **Map trace events → constraints.** Read the circuit `.zir` (mem.zir `MemoryWrite`/`IsRead`/`IsCycle`,
   inst.zir `DecodeInst`/`VerifyOpcode*`). For each field of `cycles`/`txns`, list which constraints read it.
   Critically determine: **(a)** does the circuit decode the program-memory (committed) word or the executed
   word? **(b)** which instruction-word bits are constrained per opcode (e.g. does ECALL bind `rs1`)?
   **(c)** is there any constraint that distinguishes *who/when* set the next pc (so a value-equal `set_pc`
   cannot be caught)?
3. **Predict** H1/H2 for every accepted case from the static analysis, to be confirmed dynamically in Inv. 2.

Proof artifacts: `audit/INV1_CODE_TRACE.md` — annotated code excerpts (rv32im.rs + .zir line refs), the
event→constraint table, and the per-case prediction. Every claim cites a file:line.

## 4. Investigation 2 — dynamic trace-diff with A4 instrumentation (with proof)

**Goal:** empirically prove each acceptance by diffing the full witness clean-vs-mutated, with controls that
guarantee the diff tool itself is correct.

Runner (frozen host, env: `CONSTRAINT_CONTINUE=1 A4_COVERAGE_TOUCH=1 A4_FAMILY_RESIDUE=1
A4_GLOBAL_RESIDUE=1 A4_INSPECT=1 A4_DUMP_ALL_TXNS=1`):
- **Baseline (clean):** `HOST` (no `--inject`) → dump `B = (cycles, txns)`.
- **Mutated:** `HOST --inject --inject-step S --inject-kind K --seed N` (the exact accepted sample) → dump `M`.
- Parser extracts `<a4_cycle_info>` + `<a4_all_txn>` into canonical ordered records; compute `diff(B, M)`.

Controls (these make the audit trustworthy, not the headline runs):
- **C1 Determinism (negative control):** run baseline **twice** → `diff == ∅`. If not, the witness is
  nondeterministic and all diffs are void — stop and fix.
- **C2 Completeness:** assert dumped `txns` count == `<a4_inspect_meta>.txns` and dumped cycles ==
  `.cycles`. A subset dump could hide a change. Must be exact.
- **C3 Positive control (catch a real change):** run a **known-breaking** mutation (e.g. `COMP_OUT_MOD` at a
  compute step that is a `CONSTRAINT_REJECT` in the dataset). Confirm (i) `diff(B,M) ≠ ∅`, (ii) the changed
  txn rows correspond to the constraint that fired (e.g. the `MemoryWrite` cell), and (iii) our diff tool
  flags them. This proves the tool does **not** silently miss changes — directly answering "ensure we can
  catch arguzz mutations that do change the trace."
- **C4 Independent failure-signal sweep:** grep the raw mutated log for *any* failure token
  (`<constraint_fail>`, `residue nonzero`, reject, prover `status:error`) — confirm none — so the ACCEPTED
  label does not rely solely on our parser.

Per accepted sample, classify:
- **H1** if `diff(B,M) == ∅` (witness identical) → acceptance proven trivially valid.
- **H2** if `diff ≠ ∅` but verifier still `success` and all residues zero → for each changed row, show the
  binding constraints remain satisfied; flag as a genuine evasion and analyze why (un-constrained field vs
  valid alternative execution). H2 cases get individual write-ups.
- **BUG** if `diff ≠ ∅` AND any constraint should fire → escalate; the ACCEPTED label is wrong.

Coverage: **all 37** accepted samples (1 shared baseline per distinct guest entry-point + 37 mutated dumps).
Must include every distinct mechanism: `POST_EXEC_PC +4`, `INSTR_WORD ecall-rs1`, `INSTR_WORD store-imm0`,
and any branch/format flips.

Proof artifacts: `audit/INV2_TRACE_DIFF/` — `baseline.txns.json`, `<sample>.txns.json`, `<sample>.diff.json`
per case, plus `INV2_REPORT.md` with the H1/H2/BUG verdict table and the control results.

## 5. Acceptance gates (audit is conclusive only if ALL hold)

1. C1 determinism: baseline≡baseline (∅ diff).
2. C2 completeness: dumped counts == inspect-meta counts for every run.
3. C3 positive control: a known reject shows a non-empty diff that maps to its constraint.
4. C4: zero independent failure signals in every ACCEPTED raw log.
5. Every one of the 37 classified H1 or H2 (zero BUG). Any BUG ⇒ audit fails, fix pipeline, re-run.
6. Inv1 static predictions match Inv2 empirical classifications for every case (no unexplained acceptances).
7. Cryptographic verifier `status:success` reproduced for every audited ACCEPTED sample on the frozen host.

## 6. What could still make us wrong — and how we close it (toward 100%)

- *Dump omits a constrained quantity.* → C2 + Inv1's field→constraint table proves the dump covers the full
  witness; if any constrained quantity is not in the dump, extend the dump before trusting results.
- *Parser drops a row/field.* → canonical re-serialize + count asserts; C3 proves the parser surfaces real
  changes.
- *Nondeterminism.* → C1.
- *Classifier mislabel.* → C4 (independent grep) + verifier verdict as third oracle.
- *"It verified but is actually unsound."* → that is precisely the H2 bucket; we keep it, write it up, and do
  NOT dismiss it. (Distinguishing "expected evasion" from "circuit soundness bug" may warrant escalation, but
  is out of scope for proving the *label* correct.)

## 7. Deliverables & retention (all local, NO re-proving needed beyond the audit runs)

- `audit/INV1_CODE_TRACE.md`, `audit/INV2_TRACE_DIFF/` (raw dumps + diffs + report), `audit/AUDIT_SUMMARY.md`.
- Audit runs are ≤ ~40 reproductions (37 mutated + 1 baseline + controls) on the **frozen host** — small
  enough to run locally (≤10 at a time) or one POS shard; all raw dumps gzipped and retained.
- Update `TRIPLES_N250.md` / write-ups to relabel `(0,0,0)` as **"verified / evaded (none broken)"** with a
  footnote pointing to this audit, once H1/H2 verdicts are in.

## 8. Order of work

1. C1+C2+C3 controls (prove the tool) → 2. Inv1 static analysis (predict) → 3. Inv2 all-37 diff (confirm)
→ 4. gates + summary → 5. relabel docs.

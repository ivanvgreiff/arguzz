# E2-FULL — complete A4 characterization (FULL mirrors + SUR), on polynize

> **Greenlit.** The POS path is certified (P1+P2: POS≡WSL on `polynize`, 12/12 identical,
> fingerprint determinism ✔). This increment scales the SAME validated path and now also
> **subsumes the former E3** (A4 `INSTR_WORD_MOD_SUR`). Reuse everything from
> `E2_POS_PREP_SPEC.md` (frozen host sha `5337f944…`, flag contract, on-node runner, local
> `analyze_logs.py`, `--allocation-duration 0` claim of `polynize`).
>
> **Internal staging (important):** complete + gate **Part A** (low-risk, validated path)
> first, then **Part B** (new SUR code), then **Part C** (new MEM_VAL code). Each part has its
> own gate; if a later part hits trouble, earlier parts still land. Ship in one polynize
> dispatch when ready.

## Required fixes (do first)
1. **Determinism runner fix:** `pos/thesis_run_pos.sh` must strip volatile fields
   (`"time":"…"`, wall clocks) before the raw-line diff, so on-node `determinism_summary.txt`
   is meaningful. The **constraint fingerprint** remains the real determinism gate.
2. Carry E1 `field_class`/`fields_changed` labels onto each A4 word-row for direct comparison.

---

## Part A — A4 FULL semantic mirror of every E1 layer-row
Extend `a4_config.py::build_a4_config` with the `forced_value` bypass (from E2-PREP P1.1).
For **every E1 constraint-layer run** (value-kind seeds 0–4 + all non-crash `INSTR_WORD_MOD`
words; **exclude the 7 PROVE_ERROR control-flow seeds** — A4 can't mirror a crash), build a
config applying the **exact same** Arguzz value/word at the **same instruction step**:
- `COMP_OUT_MOD`@add → force add rd WRITE = Arguzz value.
- `LOAD_VAL_MOD`@load_x → force load rd value = Arguzz value.
- `STORE_OUT_MOD`@store → force store mem data = Arguzz value.
- `INSTR_WORD_MOD_FULL`@add → force fetch word = exact Arguzz word.
Run each twice on polynize; analyze locally.

**Expected (confirm or flag):**
- Value kinds: Arguzz `1/0/0` vs **A4 `1/0/1`** (same intrastep `MemoryWrite` + a `memory`
  **global** break — witness edit leaves downstream reads stale; Arguzz propagates
  consistently). The global hit is the bias.
- INSTR_WORD operation (funct3/funct7): both intrastep decode; note if A4 adds global.
- INSTR_WORD dest_reg / src_reg: both expected `0/0/1` (global only) for the FULL mirror.
- **Interstep bucket stays ~empty for both** — this circuit enforces cross-row register
  consistency via the GLOBAL permutation. State this; the discriminating axis is
  **local-only (Arguzz) vs local+global (A4)**.

**Part A gate:** configs use the exact Arguzz value/word (assert per row); A4 column filled
for every non-crash E1 row; 2× fingerprint determinism; value-kind `+global` delta confirmed.

---

## Part B — A4 surgical (`INSTR_WORD_MOD_SUR`), single-field
Add a SUR builder to `a4_config.py` using `a4.standalone.mutations.instr_word_mod_sur`
(`get_targets_at_step`, `RiscVInstruction.encode_with_mutation`, `create_config`). At the
**add's** fetch step, mutate **one field at a time** (separate configs):
- `FUNCT3`: ADD→XOR (and one more, e.g. SLT).
- `FUNCT7`: ADD→SUB (`0x00`→`0x20`).
- **`RD` only**, **`RS1` only**, **`RS2` only**: change exactly one register, all else fixed.
- `OPCODE`/`IMM`: only if they yield a VALID decode; if a variant produces an invalid
  instruction that crashes preflight, record it as `PROVE_ERROR` (don't fight it).
Run each twice on polynize; analyze locally.

**Hypothesis to settle (user):** Arguzz register changes are `0/0/1` (global only) for BOTH
dest and source regs, because the executor stays self-consistent. A4 SUR edits the witness
**after** the executor ran the original, so a **source-register** SUR change is expected to
break **a local consistency check (decoded operand vs the recorded read txn) AND global** —
i.e. >1 broken constraint, of a different nature than Arguzz. **Confirm/deny the rd-vs-src
asymmetry explicitly**, with per-field footprints + provenance.

**Part B gate:** per-field footprint table (rd/rs1/rs2/funct3/funct7 each its own
single-field config); the rd-vs-src asymmetry confirmed or denied with evidence; each broken
constraint's nature documented (ZIR loc + meaning); 2× fingerprint determinism.

---

---

## Part C — A4 `MEM_VAL_MOD` (A4-only; targets the interstep layer)
**Purpose:** populate the so-far-empty **interstep-local** layer and demonstrate a constraint
class **Arguzz structurally cannot reach**. `MEM_VAL_MOD` mutates **memory READ** values,
which break **`MemoryRead`/`IsRead@mem.zir`** (a *local* cross-row consistency check on RAM
reads — unlike registers, whose consistency is global).

Use `a4.standalone.mutations.mem_val_mod` (`get_targets_at_step`, `create_config`). In our
guest, target each memory-read txn type that exists:
- **`load_mem_read`** — the `lw` loads at `load_x`/`load_y` (mutate the value read FROM memory;
  distinct from `LOAD_VAL_MOD`, which edits the register-write side).
- **`store_rmw_read`** — the `sw`'s read-modify-write read at `store`.
- **`load_mem_read`** at the **read-back** `lw` (the store→readback interstep oracle).
For each target, force a mutated value (a couple of seeds is plenty); run twice on polynize;
analyze locally. Record txn_type, addr, original→mutated, and the broken constraint + layer.

**No Arguzz mirror:** Arguzz has no in-place memory-read mutation (its `LOAD_VAL_MOD` edits the
register side; propagating kinds keep reads self-consistent). Its nominal alignment
`PRE_EXEC_MEM_MOD` is a Family-1 inject kind expected to OOB-crash (like `PRE_EXEC_REG_MOD`).
**State this explicitly** — Part C is the "A4 reaches a layer Arguzz can't" result.

**Expected (confirm or flag):** mutating a memory READ breaks **`MemoryRead`/`IsRead`** →
**interstep-local ≥ 1** (the first non-empty interstep result), possibly + global. Document
each constraint's ZIR meaning.

**Part C gate:** ≥1 memory-read target per available txn_type mutated; interstep-local layer
populated with the `IsRead`/`MemoryRead` loc + meaning; 2× fingerprint determinism; the
"no Arguzz mirror" point stated.

---

## Deliverables
- `run_e2.py` (bakes Part A + B + C configs, one polynize dispatch, pull + analyze).
- `artifacts/e2/`: per-run JSON (A4 FULL + SUR + MEM_VAL) + `E2_REPORT.{md,json}` + a combined
  **A4(FULL) vs A4(SUR) vs A4(MEM_VAL) vs Arguzz matrix** keyed by `(role, kind/field, seed)`
  with intrastep/interstep/global per variant + a per-`field_class` aggregate. MEM_VAL rows are
  A4-only (mark Arguzz column "n/a — no in-place memory-read mutation").

## Node / POS
`polynize` (entry 1744), `--allocation-duration 0`, re-image `debian-trixie` if needed.
**Never run on flare/meld/octorand/opulous** (A/B agents). If polynize allocate fails, STOP
and report. tmux on coinbase. Frozen host only — no rebuild.

---

## After E2-FULL (do NOT do now)
1. `A4_CONSTRAINTS_EXPLAINED.md` — the A4 analogue of `CONSTRAINTS_EXPLAINED.md`: each A4
   mutation (FULL value, FULL word, SUR field, MEM_VAL memory-read) → constraint(s) broken →
   ZIR meaning → layer, **with the Arguzz mirror contrast** (why A4 adds the global break;
   what SUR isolates; how MEM_VAL reaches the interstep layer Arguzz can't).
2. **E4** — the side-by-side Arguzz vs A4-FULL vs A4-SUR comparison + thesis write-up.

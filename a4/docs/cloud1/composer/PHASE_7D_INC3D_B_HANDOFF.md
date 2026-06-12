# Phase 7d Inc 3d Phase B — Composer handoff

**Status:** Opus has applied B1+B2+B3 instrumentation to `workspace/risc0-modified/`, rebuilt the host, and verified determinism locally. Ready for POS deployment.
**Owner shifts here:** Composer prepares bundle and dispatches the POS runs.
**Branch:** `arguzz/b7-race-instrumentation` in `/root/arguzz/workspace/risc0-modified/`

---

## What changed

Three diagnostic patches added (full spec in `PHASE_7D_INC3D_B_PATCH_SPEC.md`; results in `PHASE_7D_INC3D_REPORT.md` §B):

| ID | What it does | When active |
|----|--------------|-------------|
| B1 | Adds `mut="…"`, `pid="…"`, `seq="…"` attributes to `<a4_touch_verbose>` and `<a4_accum_touch_verbose>` opening tags | Whenever `A4_COVERAGE_TOUCH_VERBOSE=1` (always for our campaigns) |
| B2 | Emits `<a4_ftw cycle="…" userCycle="…" pc="0x…" major="…" minor="…" arg0="…" low="…" high="…" lowIsZero="…"/>` **to stderr** per `exec_FieldToWord` call | Gated behind `A4_FTW291_TRACE=1` (off by default — verbose, only enable on diagnostic pass) |
| B3 | Emits `<a4_ftw291_95_count phase="witgen|accum" value="N"/>` once per phase, counting EQZ touches that match `(major=9, minor=5, loc⊃"inst_p2.zir:291")` | Always when `A4_COVERAGE_TOUCH=1` |

## New host artifact

- **Path:** `/root/arguzz/workspace/output/target/release/risc0-host`
- **SHA-256:** `632094efdcf713387b3f9cfb69b3a6e25e89cf48a29413e0f7ae0e1e89dadee1`
- **Previous (Inc 3c) SHA:** `c2e77443275372846a73a9d1d13d340e8068ff70961d8e8b97fff479bb63b332`

Coverage/verbose body content is byte-identical to the previous host — only the new attributes and `<a4_ftw…>` / `<a4_ftw291_95_count…>` tags appear. **Existing parsers continue to work** unless they require zero extra tags (none of ours do).

---

## What you need to do

### 1. Prepare bundle

Re-bundle exactly as for Inc 3c, but with the new host SHA. Name it `INC3D_B_BUNDLE` (or your convention). All other files (guest, dispatcher, mutation configs) are unchanged from Inc 3c.

Verify on POS-side: `sha256sum risc0-host` must show `632094ef…`.

### 2. Dispatch — Pass 1 (with B2 trace, with verbose)

Re-run **the same SPREAD plan from Inc 3c phase δ** (3 SPREAD pairs + flare control + octorand controls, n=50 each). Use the existing `run_inc3c_phase_delta.sh` (or a copy), but **add these env vars** to the host invocation:

```
A4_FTW291_TRACE=1
A4_MUTATION_SHA256=<sha256 of the mutation config sent to this host>
```

The `A4_MUTATION_SHA256` is optional — if you don't set it, B1 will fall back to FNV-1a of the config file (still useful, but harder to correlate with your dispatcher logs). Strongly recommend you compute and pass it.

**Keep everything else identical** to Inc 3c:
- `--allocation-duration 0` for pre-reserved calendar slots.
- Same nodes (`octoa`, `octob`, `meld`, `flare`, etc.).
- Same A4 env vars (`A4_COVERAGE_TOUCH=1`, `A4_COVERAGE_TOUCH_VERBOSE=1`, `A4_FAMILY_RESIDUE=1`, `CONSTRAINT_CONTINUE=1`).
- Same seed (`999`).

**Warning:** `A4_FTW291_TRACE=1` produces a LOT of stderr output (one line per FieldToWord call, which is multiple per Poseidon2 cycle). Plan for ~100 MB of stderr per host log; ensure your log collection has capacity.

### 3. Dispatch — Pass 2 (no verbose, B3 counter only)

This pass tests whether the race exists **without** the `std::set<std::string>` perturbation that ChatGPT flagged as a potential trigger.

Same SPREAD plan, same nodes. Difference from Pass 1:
- **Drop** `A4_COVERAGE_TOUCH_VERBOSE=1` (do NOT set it).
- **Drop** `A4_FTW291_TRACE=1` (we only need the B3 counter here).
- **Keep** `A4_COVERAGE_TOUCH=1` and `A4_MUTATION_SHA256=<sha>`.

Logs will be MUCH smaller (no verbose blocks, no per-call FTW traces), but `<a4_ftw291_95_count>` will still be emitted for both phases.

### 4. Hand back to Opus

Post both passes back into this conversation (or the next Composer↔Opus turn) with:
- Bundle SHA confirmation.
- Per-pair (A vs B) log paths.
- Any anomalies in dispatch (e.g. SIGSEGVs, calendar misses).

Opus will then update `B7_verbose_touch.py` to read the new attributes and run the analysis.

---

## Key questions the runs will answer

1. **Is the race real, or a parser artifact?** B1's `mut="…"` attribute lets us prove paired blocks belong to the same mutation (currently the parser is doing fuzzy matching). If `mut_A == mut_B` for every paired block and the race signature persists → real race.
2. **Does the race depend on `std::set<std::string>` verbose tracking?** Pass 2 vs Pass 1 comparison of B3 counter divergence rates.
3. **What is the racy Poseidon2 input?** B2's `<a4_ftw>` trace shows the exact `(cycle, pc, arg0, low)` tuple for the diverging touch. If A and B see the same arg0 but compute different `low` (the lower 16 bits) → the Poseidon2 permutation itself is nondeterministic. If they see different `arg0` → executor divergence upstream.
4. **Can we now eliminate the "49 blocks for 50 mutations" off-by-one?** Pass 1 B1 attrs combined with `seq=` numbering will tell us deterministically whether the host emitted 49 or 50 verbose blocks, and which mutations were dropped (if any) — versus the parser's current best-guess alignment.

---

## What NOT to do

- **Don't** run on different node sets — we need direct comparison with Inc 3c.
- **Don't** change mutation seeds or counts — same plan or comparison is meaningless.
- **Don't** combine Pass 1 and Pass 2 into a single dispatch — keep them separate so we can isolate the verbose-perturbation hypothesis.
- **Don't** modify the host binary or rebuild it on POS — use the exact `632094ef…` artifact Opus built locally.

---

## Local verification recap (so Composer trusts the bundle)

Opus ran 4 sequential instances of mut27 on this WSL2 host with the new binary. Results:

```
verbose body SHA      : ac56a7278b17faa7 (4/4) -- matches pre-B1 gold
accum_verbose body SHA: bf4891cb80a0d2b1 (4/4) -- matches pre-B1 gold
coverage SHA          : b99b53555d06c752 (4/4) -- matches pre-B1 gold (no change)
ftw291_95_count SHA   : 90d5519e4804db45 (4/4) -- new, deterministic
```

B1 attributes appear correctly: `mut="fnv1a64=99ec79d08877a7a7" pid="<varies>" seq="0"`. Without `A4_FTW291_TRACE=1`, zero `<a4_ftw>` tags appear in stderr (B2 correctly gated off).

On this WSL2 machine, `value="0"` for both witgen and accum phases of mut27 — consistent with Phase A finding that this environment doesn't race-reproduce (we're always the A-mate side locally).

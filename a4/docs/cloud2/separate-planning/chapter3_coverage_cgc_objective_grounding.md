# Chapter-3 grounding: coverage spaces, CGC keys, novelty, and the campaign objective

**Purpose.** This is a source-grounded definitional reference for the next stretch of `chapter-3.md` (the empty *Constraint Coverage* subsection, and the *Multi-Armed Bandit* material that follows). It gives precise definitions and expressions for (1) the three coverage spaces, (2) every coordinate of the CGC key, (3) the novelty signals, and (4) the campaign objective — each tied to the exact source. It deliberately **reuses the notation you have already defined in `chapter-3.md`** and flags every *new* symbol it introduces, so the writing stays a clean build-up: *blocks → a problem to solve → new expressions assembled from the blocks*. Every fact is cited; nothing is guessed. You parse this and decide what to lift.

> **Style note.** I kept your LaTeX-in-markdown conventions (`\textbf`, `\texttt`, `$…$`, `$$\begin{align}…\end{align}$$`) so paragraphs can drop straight in.

---

## 0. Notation you have already established (recap)

From the *Mutation Feedback* section, the reader already has:

| Symbol | Meaning | where |
|---|---|---|
| $\gamma=(\texttt{Name@file:line},\mathrm{major},\mathrm{minor})$ | a **local failure context** | ch3 §Local |
| $\Gamma$ | the multiset of $\gamma$ a single run emits | ch3 §Local |
| $\mathrm{set}(\Gamma)$ | its distinct elements | ch3 §Local |
| $n_{\text{fail}}=|\Gamma|,\ \ d_{\text{loc}}=|\mathrm{set}(\Gamma)|,\ \ r_{\text{rep}}=n_{\text{fail}}-d_{\text{loc}}$ | total / distinct / **within-run** cascade mass | ch3 §Local |
| $z_{\text{mem}}=(\text{addr},\text{step},\text{data})$, $z_{\text{look}}=(\text{index},\text{table})$ | global event tuples | ch3 §Global |
| $m\in\{+1,-1\}$ | signed multiplicity ($-1\equiv p-1$) | ch3 §Global |
| $h_r(z)$ | random affine hash | ch3 §Global |
| $\mathcal{F}\in\{\text{memory},\text{u8},\text{u16},\text{cycle}\}$ | the four global **families** | ch3 §Global |
| $\operatorname{res}_{\mathcal{F}}=\sum_{i\in\mathcal{F}}m_i\,h_r(z_i)^{-1}$ | the per-family **residue** | ch3 §Global |

**New symbols introduced below** (each defined at first use): the per-pull index $t$ and budget $N$; the **CGC key** $\kappa$; the **structural cell** $\sigma$; the three accumulated **coverage sets** $\mathcal{L}_t,\mathcal{G}_t,\mathcal{S}_t$; the per-run global-key set $\mathsf{G}_t$; the **novelty** counts $\ell_{\text{new}},g_{\text{new}},s_{\text{new}},f_{\text{new}}$; and, for the objective, the **history** $\mathcal{H}_{t-1}$ and **policy** $\pi$. That is the *complete* list of new letters — I kept it minimal on purpose (your stated concern).

A campaign is a finite sequence of mutations indexed $t=1,2,\dots,N$; we call each one a **pull** (the bandit term, motivated later). "After pull $t$" means *having processed the outcomes of pulls $1\dots t$.*

---

## 1. From per-run feedback to campaign coverage: the three coverage spaces

**The problem to motivate.** The feedback of the previous section — the contexts $\mathrm{set}(\Gamma)$ a run breaks, and the broken global tuples behind a nonzero $\operatorname{res}_{\mathcal{F}}$ — describes a *single* run. To steer a *campaign*, the fuzzer must remember what it has *already exercised*, so it can tell whether a new mutation reaches somewhere new or merely re-treads old ground. We therefore accumulate the per-run feedback into **coverage sets** that grow monotonically over the campaign. Three distinct notions of "where we have been" arise, and they are not interchangeable: two record *the environment's response* (which constraints broke, where in the global algebra), and one records *what the fuzzer tried*.

### 1.1 Local failure coverage $\mathcal{L}$

A single run at pull $t$ contributes the distinct local contexts $\mathrm{set}(\Gamma_t)$ it broke — which is exactly your per-run object, and $|\mathrm{set}(\Gamma_t)|=d_{\text{loc}}(t)$. **Local failure coverage** is the union of these across the campaign:
$$
\mathcal{L}_t \;=\; \mathcal{L}_{t-1}\,\cup\,\mathrm{set}(\Gamma_t), \qquad \mathcal{L}_0=\varnothing,
\qquad\text{so}\qquad
\mathcal{L}_t=\bigcup_{s\le t}\mathrm{set}(\Gamma_s).
$$
An element of $\mathcal{L}_t$ is a distinct failure context $\gamma=(\texttt{Name@file:line},\mathrm{major},\mathrm{minor})$. *Source:* the accumulator is the in-memory set `_seen_local_v2`, a `Set[Tuple[str,int,int]]`; it is read for novelty and then unioned with the run's contexts (`reward_v2.py:151,177`). Persisted first-hits live in table `local_coverage_v2`, whose identity key is the string `f"{constraint_loc}|{major}|{minor}"` per campaign (`coverage_db.py:449–463,688`). (This is the *fine* triple; a legacy `coverage` table keyed only on `constraint_loc` is coarser and not what $\mathcal{L}$ denotes.)

### 1.2 Global failure coverage $\mathcal{G}$

**A problem first.** A nonzero residue hands us *raw* broken tuples — concretely, broken memory addresses and lookup indices. The address space is $2^{32}$; using a raw address as a coverage coordinate would make every break "new" forever, which is useless. We therefore compress each broken tuple into a recurring, semantically meaningful key — the **Compressed Global Context (CGC)** key $\kappa$ (fully enumerated in §2). Write $\kappa(z)$ for the key a broken tuple $z$ maps to. The run's contributed keys are
$$
\mathsf{G}_t \;=\; \big\{\,\kappa(z)\;:\; z \text{ is a broken tuple in any family with }\operatorname{res}_{\mathcal{F}}\neq 0 \text{ at pull } t\,\big\},
$$
(a set, capped at $64$ keys per run — `compressed_global_extractor.py:86,344–349`), and **global failure coverage** accumulates them:
$$
\mathcal{G}_t \;=\; \mathcal{G}_{t-1}\,\cup\,\mathsf{G}_t, \qquad \mathcal{G}_0=\varnothing.
$$
An element of $\mathcal{G}_t$ is a CGC key $\kappa$. *Source:* `_seen_compressed_global`, a `Set[str]` of the keys' canonical JSON serialization `to_json_str()` (`reward_v2.py:158–169,178–179`); persisted in `compressed_global_coverage`, keyed on that JSON string per campaign (`coverage_db.py:424–437`; `extractor.py:360–374`). (A separate legacy `global_failures` table stores *raw* `(mutation_id, family, address)` — that is the uncompressed store, **not** $\mathcal{G}$.)

### 1.3 Structural coverage $\mathcal{S}$

$\mathcal{L}$ and $\mathcal{G}$ measure the *environment's* response. **Structural coverage** measures *what the fuzzer tried* — the semantic signature of the mutation itself, independent of any failure. The per-run object is a single **structural cell** $\sigma_t$, a 6-tuple:
$$
\sigma_t \;=\; \big(\,k,\; z,\; \mathrm{oc}(\mathrm{major}),\; \mathrm{mode},\; \tau(k),\; \mathrm{sub}\,\big),
$$
where $k$ is the mutation kind, $z$ its semantic zone, $\mathrm{oc}(\cdot)$ the opcode class (§2.6), $\mathrm{mode}\in\{\texttt{user},\texttt{machine}\}$, $\tau(k)$ the transaction role (§2.4), and $\mathrm{sub}$ a finer sub-strategy descriptor (the first present of the instance's $\texttt{funct3}$, $\texttt{byte\_lane}$, or $\texttt{value\_class}$, else none). Structural coverage is
$$
\mathcal{S}_t \;=\; \mathcal{S}_{t-1}\,\cup\,\{\sigma_t\}, \qquad \mathcal{S}_0=\varnothing.
$$
*Source:* `StructuralCell` is a frozen 6-field dataclass with `to_tuple = (kind, semantic_zone, opcode_class, mode, txn_role, sub_strategy)` (`structural_cells.py:32–53`); built per run by `_build_structural_cell` (`reward_v2.py:111–130`) with `opcode_class=major_to_opcode_class(major)` and `txn_role=txn_role_for_kind(kind)` — i.e. it **reuses the very maps defined for the CGC key in §2.4 and §2.6.** The accumulator is `_seen_structural` (`reward_v2.py:171–180`). **Note for the write-up:** unlike $\mathcal{L},\mathcal{G}$, structural coverage is **not** persisted as a first-hit table; it lives only in memory.

> **Ordering caveat (worth a decision).** $\sigma$ is built from the mutation's *kind*, *zone*, and *opcode class* — objects you formalize later, in *Semantic Decomposition of a Mutation*. So $\mathcal{S}$ reads most naturally **after** that subsection, or with a forward reference. A clean framing: introduce $\mathcal{L}$ and $\mathcal{G}$ in *Constraint Coverage* (they are genuinely "constraint" coverage, built from feedback), and introduce $\mathcal{S}$ alongside the semantic decomposition as *mutation-space* coverage — since $\mathcal{S}$ is not about the constraint system at all, but about the action space.

### 1.4 The three spaces at a glance

| set | element | per-run contribution | what it captures | persisted? |
|---|---|---|---|---|
| $\mathcal{L}_t$ | $\gamma=(\texttt{loc},\mathrm{major},\mathrm{minor})$ | $\mathrm{set}(\Gamma_t)$ | which local rules broke, where | yes (`local_coverage_v2`) |
| $\mathcal{G}_t$ | CGC key $\kappa$ | $\mathsf{G}_t$ (≤64) | which corner of the global algebra broke | yes (`compressed_global_coverage`) |
| $\mathcal{S}_t$ | structural cell $\sigma$ | $\{\sigma_t\}$ (exactly one) | what kind of mutation we tried | no (in-memory only) |

The three element-types are disjoint, so $|\mathcal{L}_t\cup\mathcal{G}_t\cup\mathcal{S}_t| = |\mathcal{L}_t|+|\mathcal{G}_t|+|\mathcal{S}_t|$ — a fact §4 uses.

---

## 2. The CGC key $\kappa$ in full (the Appendix-A material)

**The compression, precisely.** A broken tuple $z$ is rich — for memory, $z_{\text{mem}}=(\text{addr},\text{step},\text{data})$ — but the CGC key keeps only what is *semantically reusable* and discards the rest. It retains the address's **region** and **order of magnitude**, *forgets* the exact step and data, and tags the key with the *mutation's* role and phase. (Why the mutation's, not the transaction's? Because the residue mechanism does not expose per-transaction role/phase metadata; attributing them from the mutation context is an explicit, documented approximation — decision **D16**, `compressed_global_extractor.py:47–50,151–159`.) The two key forms are:
$$
\begin{align}
\kappa_{\text{mem}} &= \big(\,\texttt{memory},\; \rho(\text{addr}),\; \beta(\text{addr}),\; \tau(k),\; \psi(z)\,\big),\\[2pt]
\kappa_{\text{look}} &= \big(\,\mathcal{F},\; \beta(\text{index}),\; k,\; \mathrm{oc}(\mathrm{major})\,\big),\qquad \mathcal{F}\in\{\texttt{u8},\texttt{u16},\texttt{cycle}\}.
\end{align}
$$
*Source:* the frozen dataclasses `GlobalMemoryCtx` / `GlobalLookupCtx` (`compressed_global.py:67–106`), assembled in `extract_compressed_global_contexts` (`compressed_global_extractor.py:267–351`). The five component maps follow.

### 2.1 Families $\mathcal{F}$

These are the four global arguments of your §Global; $\kappa_{\text{mem}}$ covers the first, $\kappa_{\text{look}}$ the other three.

| family | meaning |
|---|---|
| $\texttt{memory}$ | the memory-consistency (permutation) argument over memory transaction records |
| $\texttt{u8}$ | the 8-bit lookup table — byte-range checks (table id 8) |
| $\texttt{u16}$ | the 16-bit lookup table — 16-bit-range checks (table id 16) |
| $\texttt{cycle}$ | the cycle/control lookup table — per-cycle table lookups (table id 0) |

*Source:* `LOOKUP_FAMILIES=("u8","u16","cycle")` (`compressed_global.py:60`); table-id → name at `ffi.cpp:540–541`.

### 2.2 Address region $\rho(\text{addr})$ (memory keys)

$\rho$ partitions the $2^{32}$-byte address space into **nine functional regions**, plus an $\texttt{invalid}$ fallback. The label says *what part of the machine* the broken address lives in — this is the "memory-level exploration diagnostic" your §Global already promises the reader. *Source:* `_ADDRESS_REGION_MAP` (`compressed_global_extractor.py:96–122`); ranges verbatim from `platform.rs`; meanings from the D8 audit (`CLOUD1_DECISIONS_FOR_PRO_R2.md:159–203`).

| byte-address range $[\,\text{lo},\text{hi})$ | label | what lives there |
|---|---|---|
| $[\texttt{0x0000\_0000},\,\texttt{0x0001\_0000})$ | $\texttt{zero\_page}$ | reserved low 64 KB; should never carry a real transaction |
| $[\texttt{0x0001\_0000},\,\texttt{0xBFFF\_0000})$ | $\texttt{user}$ | the bulk user space — code, data, heap, stack (~3 GB, one label) |
| $[\texttt{0xBFFF\_0000},\,\texttt{0xC000\_0000})$ | $\texttt{user\_bigint}$ | BigInt operand scratch region |
| $[\texttt{0xC000\_0000},\,\texttt{0xFF00\_0000})$ | $\texttt{kernel}$ | machine-mode kernel code/data |
| $[\texttt{0xFFFF\_0000},\,\texttt{0xFFFF\_0080})$ | $\texttt{machine\_regs}$ | machine-mode register file |
| $[\texttt{0xFFFF\_0080},\,\texttt{0xFFFF\_0100})$ | $\texttt{user\_regs}$ | user-mode register file ($\texttt{x0}$–$\texttt{x31}$) |
| $[\texttt{0xFFFF\_0100},\,\texttt{0xFFFF\_1000})$ | $\texttt{machine\_special}$ | machine special registers (MEPC, suspend PC/mode/cycle, global I/O) |
| $[\texttt{0xFFFF\_1000},\,\texttt{0xFFFF\_2000})$ | $\texttt{ecall\_dispatch}$ | ECALL trampoline dispatch table |
| $[\texttt{0xFFFF\_2000},\,\texttt{0x1\_0000\_0000})$ | $\texttt{trap\_dispatch\_and\_beyond}$ | trap dispatch table and everything above to the 4 GB ceiling |
| any in-range address in no row (e.g. the gap $[\texttt{0xFF00\_0000},\texttt{0xFFFF\_0000})$), or out of range | $\texttt{invalid}$ | fallback for valid-but-unmapped or out-of-range addresses |

Two clarifications for the prose: (i) the enum also lists $\texttt{unknown}$, but that is only a dataclass default and is *never emitted* — the extractor always returns one of the ten above; (ii) $\texttt{user}$ deliberately swallows code/heap/stack into one label, delegating fine discrimination *inside* user space to the magnitude band $\beta$ (next).

### 2.3 Magnitude band $\beta$ (memory addresses and lookup indices)

$\beta$ is a logarithmic bucket, applied to a memory address or a lookup index:
$$
\beta(x) \;=\; \big\lfloor \log_2 \max(x,1)\big\rfloor .
$$
Ranges: $\beta(\text{addr})\in\{0,\dots,31\}$ for 32-bit addresses; $\beta(\text{index})$ is small ($\texttt{u8}$: $0$–$7$, $\texttt{u16}$: up to $15$, $\texttt{cycle}$: $\sim$$12$–$13$). *Meaning of "same band":* two addresses/indices that differ only in low-order bits within one power-of-two window collapse to the same band — i.e. they touch the same $\sim$$2^\beta$-aligned chunk. This is the actual source of compression: "a new $\sim$$64$ KB chunk" rather than "a new byte." *Source:* `address_bucket`, `lookup_index_bucket` (`extractor.py:125–148`). **Byte vs word:** $\beta$ is taken on the **byte** address; the extractor prefers the `byte_addr` field over the circuit word address (`_coerce_broken_addr` key order `("byte_addr","addr","address")`, `extractor.py:237`). This is the NFP-10 fix — before it, word addresses shifted every band by $-2$ and mis-labeled $\sim$$55$–$59\%$ of memory keys (`IV_POS_8_NOTES_FOR_PRO.md:277–298`). Note $\beta$ is reused for both addresses and indices (one symbol, two uses).

### 2.4 Transaction role $\tau(k)$ (memory keys)

The role names *what kind of transaction* the break is attributed to. It is read off the **mutation kind** $k$ (not the transaction — D16). Six values:

| role | meaning |
|---|---|
| $\texttt{read}$ | a memory-read (loaded data) |
| $\texttt{write}$ | a memory-store (stored data) |
| $\texttt{ifetch}$ | an instruction fetch / decode |
| $\texttt{register}$ | a register-file access or computation output |
| $\texttt{prev\_word}$ | the previous-word field of a transaction record |
| $\texttt{prev\_cycle}$ | the previous-cycle field of a transaction record |

The map $\tau(k)$ (`_TXN_ROLE_BY_KIND`, `extractor.py:161–201`; unknown kinds default to $\texttt{read}$): $\texttt{ifetch}\leftarrow\{\texttt{INSTR\_WORD\_MOD},\texttt{INSTR\_WORD\_MOD\_FULL},\texttt{INSTR\_WORD\_MOD\_SUR},\texttt{INSTR\_TYPE\_MOD},\texttt{PRE\_EXEC\_PC\_MOD},\texttt{POST\_EXEC\_PC\_MOD},\texttt{BR\_NEG\_COND}\}$; $\texttt{read}\leftarrow\{\texttt{LOAD\_VAL\_MOD},\texttt{MEM\_VAL\_MOD},\texttt{PRE\_EXEC\_MEM\_MOD},\texttt{CYCLE\_MODE\_MOD},\texttt{TXN\_ADDR\_MOD},\texttt{TXN\_CYCLE\_PHASE\_MOD},\texttt{CYCLE\_DIFF\_COUNT\_MOD}\}$; $\texttt{write}\leftarrow\{\texttt{STORE\_OUT\_MOD},\texttt{POST\_EXEC\_MEM\_MOD}\}$; $\texttt{register}\leftarrow\{\texttt{PRE\_EXEC\_REG\_MOD},\texttt{COMP\_OUT\_MOD},\texttt{POST\_EXEC\_REG\_MOD}\}$; $\texttt{prev\_word}\leftarrow\{\texttt{TXN\_PREV\_WORD\_MOD}\}$; $\texttt{prev\_cycle}\leftarrow\{\texttt{TXN\_PREV\_CYCLE\_MOD}\}$.

### 2.5 Cycle phase $\psi(z)$ (memory keys)

The phase names *where in the machine's control flow* the mutation sat. It is read off the mutation's semantic **zone** $z$. Five values:

| phase | meaning | zones mapped to it |
|---|---|---|
| $\texttt{normal}$ | ordinary core execution | any $\texttt{core\_*}$ zone, or unrecognized |
| $\texttt{ecall}$ | around an environment-call boundary | $\texttt{pre\_ecall},\texttt{post\_ecall}$ |
| $\texttt{mret}$ | around a machine-mode (trap) return | $\texttt{pre\_mret},\texttt{post\_mret}$ |
| $\texttt{halt}$ | around program halt | $\texttt{pre\_halt},\texttt{post\_halt}$ |
| $\texttt{boundary}$ | the first or last step of the trace | $\texttt{step0},\texttt{last\_step}$ |

*Source:* `cycle_phase_for_zone` (`extractor.py:204–222`).

### 2.6 Opcode class $\mathrm{oc}(\mathrm{major})$ (lookup keys and structural cells)

The opcode class names *what instruction family* the cycle belonged to, read off the cycle's **major** index. Eight values, via `OPCODE_CLASS_BY_MAJOR` (`semantic_zones.py:86–102`; unknown major → $\texttt{other}$). This is the **major-based 8-class scheme** — distinct from the 7-class scheme used for the Arguzz arm opcode coordinate; the CGC and the structural cell both use *this* one.

| major | class | instruction family |
|---|---|---|
| 0,1,2 | $\texttt{alu}$ | integer arithmetic / logic / compare / immediates (with branch & jump encodings folded into majors 1–2) |
| 3 | $\texttt{mul}$ | multiply group (and the `Sll` shift sharing the major) |
| 4 | $\texttt{div}$ | divide/remainder group (and shift-right) |
| 5 | $\texttt{mem}$ | loads |
| 6 | $\texttt{mem}$ | stores |
| 7 | $\texttt{branch\_or\_ctrl}$ | control: `Eany`/`Mret` |
| 8 | $\texttt{branch\_or\_ctrl}$ | ECALL handling |
| 9,10 | $\texttt{poseidon}$ | Poseidon2 hash accelerator |
| 11 | $\texttt{sha}$ | SHA-256 accelerator |
| 12 | $\texttt{other}$ | BigInt |

(Subtlety to flag: the CGC/structural opcode class is major-only — it does *not* split major 4 into shift-vs-divide the way the *zone* layer does.)

### 2.7 Producer kind (lookup keys)

For lookup keys, the fourth coordinate is simply the **mutation kind** $k$ itself (free-form kind string, default $\texttt{UNKNOWN}$; `extractor.py:339`). It records *which mutation produced* the lookup break.

---

## 3. Novelty: the per-pull discovery signal

**The problem.** The coverage *sets* say what has been exercised; the fuzzer's per-pull learning signal is whether a pull added anything **new**. Novelty is the first-hit delta of each coverage set — defined by reading the accumulated set *before* the pull is folded in. All three are computed in one pass (`reward_v2.py:133–189`), which reads $\mathcal{L}_{t-1},\mathcal{G}_{t-1},\mathcal{S}_{t-1}$ and then updates them.

$$
\begin{align}
\ell_{\text{new}}(t) &= \big|\,\mathrm{set}(\Gamma_t)\setminus\mathcal{L}_{t-1}\,\big| && \text{(count of newly-seen local contexts)}\\
g_{\text{new}}(t) &= \big|\,\mathsf{G}_t\setminus\mathcal{G}_{t-1}\,\big| && \text{(count of newly-seen CGC keys)}\\
s_{\text{new}}(t) &= \mathbb{1}\big[\,\sigma_t\notin\mathcal{S}_{t-1}\,\big] && \text{(indicator: is this structural cell new?)}
\end{align}
$$

Note the asymmetry, which is exact to the code: $\ell_{\text{new}}$ and $g_{\text{new}}$ are **cardinalities** (a run breaks a *set* of local contexts and a *set* of global keys), while $s_{\text{new}}$ is a **0/1 indicator** (a run has exactly one structural cell). *Source:* `l_new = sum(1 for ctx in local_contexts if ctx not in seen_local_v2)`, `g_new` analogously, `s_new = 0 if cell in seen_structural else 1` (`reward_v2.py:151,165–169,174`).

**A clean identity that builds on your $d_{\text{loc}}$.** The distinct local contexts of a run split into the genuinely new and the already-seen:
$$
d_{\text{loc}}(t) \;=\; \underbrace{\ell_{\text{new}}(t)}_{\text{new this campaign}} \;+\; \underbrace{r_{\text{seen}}(t)}_{\text{already in }\mathcal{L}_{t-1}}, \qquad r_{\text{seen}}(t)=\big|\,\mathrm{set}(\Gamma_t)\cap\mathcal{L}_{t-1}\,\big|.
$$

> **⚠ Two different "repeats" — do not conflate.** Your $r_{\text{rep}}=n_{\text{fail}}-d_{\text{loc}}$ is a **within-run** quantity (the same context firing several times *in one run* — cascade mass). The $r_{\text{seen}}$ above is a **cross-run** quantity (distinct contexts this run that were *already discovered in earlier runs*). They answer different questions and are computed from different things. This matters when you write the reward section: the additive reward's repeat *penalty* term, $-0.05\,\operatorname{sat}(\cdot,5)$, is driven by the **cross-run** $r_{\text{seen}}$ (`reward_v2.py:152` `repeat = sum(... if ctx in seen_local_v2)`), **not** by your within-run $r_{\text{rep}}$. (Your within-run $r_{\text{rep}}$ instead drives the *quality* factor $Q_{\text{rep}}$ in the separate coverage-quality reward.) Suggest naming them distinctly in the thesis — e.g. keep $r_{\text{rep}}$ for within-run and introduce $r_{\text{seen}}$ for cross-run — so the reader is never confused.

**A diagnostic fourth signal.** There is also a coarse family novelty, used only as a diagnostic (it does **not** feed the bandit's learning signal):
$$
f_{\text{new}}(t) = \big|\,\Phi(\mathrm{set}(\Gamma_t))\setminus\Phi(\mathcal{L}_{t-1})\,\big|, \qquad \Phi(\cdot)=\{\text{the }\texttt{.zir}\text{ source file of each }\gamma\},
$$
where the **constraint family** $\Phi(\gamma)$ is the substring of $\texttt{Name@file:line}$ between `@` and `.zir` — i.e. the Zirgen source module the constraint comes from, a coarsening of $\gamma$ (`reward_v2.py:65–78,154–156`). A second diagnostic, the **touch new-bits** $\delta_T$, counts newly-lit reachability-bitmap buckets but belongs to a separate (legacy) reward path and likewise does not feed the bandit (`touch_coverage.py:84–95`).

**Which novelty the learner consumes.** Of the signals above, the bandit's binary success indicator is built from exactly the three primary ones (`reward_v2.py:60–62`):
$$
b(t) \;=\; \mathbb{1}\big[\,\ell_{\text{new}}(t)+g_{\text{new}}(t)+s_{\text{new}}(t)\;>\;0\,\big].
$$
$f_{\text{new}}$ and $\delta_T$ are deliberately excluded from $b(t)$. (You will motivate $b$ in the *Bayesian Learning* subsection; it is listed here only so the novelty definitions are complete.)

---

## 4. The campaign objective — stated rigorously and honestly

Your draft objective ("maximize $|\mathcal{L}_N|+|\mathcal{G}_N|+|\mathcal{S}_N|$ subject to $N$ pulls") needs two corrections: **"policy"** must be defined, and **"subject to $N$ pulls" overstates what the system does** — $N$ is a fixed input parameter, not a constraint in an optimization the code solves. Here is the precise picture.

**Budget.** $N$ is a fixed campaign parameter — the number of mutations, set by the `--num` flag (default $100$; the reference V5 run used $N=6000$). The campaign is literally a `for` loop of $N$ iterations; there is **no** objective function, `argmax` over coverage, or solver anywhere in the campaign code (verified by search across the fuzzer, reward, and scheduler modules). *Source:* `run_campaign(num_mutations)` and the fixed loop `for i in range(main_budget)` (`fuzzer.py:1702,1763`); `--num` (`cli.py:199`).

**Policy.** Let the **history** after pull $t-1$ be everything the scheduler has observed,
$$
\mathcal{H}_{t-1} \;=\; \big(\,a_s,\ \text{outcome}_s\,\big)_{s<t} \quad\text{(the arms pulled and their feedback so far)},
$$
and let $\mathcal{A}$ be the set of arms (the semantic mutation classes, formalized in *Semantic Decomposition*). A **policy** $\pi$ is a — generally randomized, history-dependent — rule selecting the next arm,
$$
\pi:\ \mathcal{H}_{t-1}\ \longmapsto\ a_t\in\mathcal{A}.
$$
V5's $\pi$ is the constrained-Thompson-sampling waterfall (cold-start → singleton → floor → adaptive). Running $\pi$ for $N$ pulls produces a (random) trajectory and hence random terminal coverage sets $\mathcal{L}_N,\mathcal{G}_N,\mathcal{S}_N$.

**Objective (conceptual target, not a solved program).** Because the three element-types are disjoint (§1.4), terminal coverage is
$$
C_N \;=\; |\mathcal{L}_N| + |\mathcal{G}_N| + |\mathcal{S}_N|,
$$
and the *design goal* is a policy that makes $\mathbb{E}_\pi[\,C_N\,]$ large for the fixed budget $N$:
$$
\text{design goal:}\qquad \text{choose } \pi \text{ to make } \mathbb{E}_\pi\big[\,C_N\,\big]\ \text{large}, \qquad N \text{ fixed.}
$$
**Be explicit in the prose that this is an interpretive target, not an optimization the code performs.** The implemented policy does not optimize $C_N$ directly; it greedily maximizes a *per-pull* discovery signal — choosing, each pull, an arm whose posterior discovery probability $\theta_a=\Pr[\,b(t)=1\mid a_t=a\,]$ looks high — and $C_N$ is the cumulative consequence. Two honest qualifications strengthen the thesis:

1. **Greedy-per-pull $\neq$ optimal-for-$C_N$.** Because coverage is submodular (each newly-discovered context lowers the marginal value of related future pulls), the per-pull greedy heuristic is a tractable surrogate for the intractable budgeted-coverage objective, not its exact solution.
2. **The budget is a parameter, not a constraint.** "Subject to $N$ pulls" reads as a hard optimization constraint; it is really just "the campaign runs for a fixed, pre-set number of pulls $N$." Prefer wording like *"with a fixed budget of $N$ pulls"* over *"subject to $N$ pulls."*

A faithful one-sentence statement for the chapter: *"For a fixed budget of $N$ mutations, the scheduler is a policy $\pi$ mapping history to the next arm; its design goal is to make the discovered coverage $C_N=|\mathcal{L}_N|+|\mathcal{G}_N|+|\mathcal{S}_N|$ large, which it pursues not by solving a global optimization but by greedily favoring, at each pull, arms whose estimated probability of yielding new coverage is highest."*

---

## 5. Variable ledger (everything, with status)

| symbol | definition | expression / value | source | status |
|---|---|---|---|---|
| $t,\ N$ | pull index; fixed budget | $t=1..N$; $N$ = `--num` (def. 100; V5 run 6000) | `fuzzer.py:1702,1763`; `cli.py:199` | new |
| $\mathcal{L}_t$ | local failure coverage | $\mathcal{L}_{t-1}\cup\mathrm{set}(\Gamma_t)$ | `_seen_local_v2`, `reward_v2.py:177` | new |
| $\mathcal{G}_t$ | global failure coverage | $\mathcal{G}_{t-1}\cup\mathsf{G}_t$ | `_seen_compressed_global`, `reward_v2.py:179` | new |
| $\mathcal{S}_t$ | structural coverage | $\mathcal{S}_{t-1}\cup\{\sigma_t\}$ | `_seen_structural`, `reward_v2.py:180` | new |
| $\mathsf{G}_t$ | CGC keys a run emits | $\{\kappa(z):z\text{ broken at }t\}$, $\le 64$ | `extractor.py:267–351` | new |
| $\kappa$ | CGC key | $\kappa_{\text{mem}}$ or $\kappa_{\text{look}}$ (§2) | `compressed_global.py:67–106` | new |
| $\sigma$ | structural cell | $(k,z,\mathrm{oc},\mathrm{mode},\tau,\mathrm{sub})$ | `structural_cells.py:32–53` | new |
| $\rho,\beta,\tau,\psi,\mathrm{oc}$ | CGC coordinate maps | §2.2–2.6 | `extractor.py`, `semantic_zones.py` | new |
| $\ell_{\text{new}},g_{\text{new}},s_{\text{new}}$ | primary novelty | §3 | `reward_v2.py:151,165,174` | new |
| $r_{\text{seen}}$ | cross-run already-seen count | $|\mathrm{set}(\Gamma_t)\cap\mathcal{L}_{t-1}|$ | `reward_v2.py:152` | new (≠ $r_{\text{rep}}$) |
| $f_{\text{new}},\delta_T$ | diagnostic novelty (not in $b$) | §3 | `reward_v2.py:154–156`; `touch_coverage.py:84` | new |
| $b(t)$ | bandit success bit | $\mathbb{1}[\ell_{\text{new}}+g_{\text{new}}+s_{\text{new}}>0]$ | `reward_v2.py:60–62` | new (define w/ bandit) |
| $\mathcal{H}_{t-1},\ \pi,\ \mathcal{A}$ | history; policy; arms | §4 | conceptual + scheduler | new |
| $C_N$ | terminal coverage | $|\mathcal{L}_N|+|\mathcal{G}_N|+|\mathcal{S}_N|$ | — (interpretive) | new |

---

## 6. Recommendations for the write-up

1. **Split the three spaces by *what they measure*.** Put $\mathcal{L},\mathcal{G}$ in *Constraint Coverage* (they are responses of the constraint system). Defer $\mathcal{S}$ to the semantic-decomposition material — it is *action* coverage and depends on kind/zone/opcode-class you formalize there. This keeps each definition resting only on blocks already introduced.
2. **Introduce $\kappa$ exactly where you need it** — i.e. when defining $\mathcal{G}$ — and push the full coordinate enumeration (§2.2–§2.7) to Appendix A, which your §Global already forward-references for the region definitions.
3. **Anchor novelty on $d_{\text{loc}}$.** The split $d_{\text{loc}}=\ell_{\text{new}}+r_{\text{seen}}$ lets you introduce $\ell_{\text{new}}$ as "the part of $d_{\text{loc}}$ that is new this campaign" — no fresh machinery, a direct build on the block the reader already has.
4. **Resolve the two-repeats clash now** (§3 warning) so the later reward section is clean.
5. **Fix the objective framing** per §4: define $\pi$, call $N$ a budget (parameter) not a constraint, and state plainly that the policy greedily approximates the coverage goal rather than solving it.
6. **Minor accuracy notes you may choose to footnote:** the memory data field is two field limbs ($\text{dataLow},\text{dataHigh}$) in the implementation, which your $z_{\text{mem}}=(\text{addr},\text{step},\text{data})$ abstracts as one "data" — fine to keep as a deliberate simplification, but the affine hash then carries one extra coefficient; and "cycle" and "step" are used loosely as synonyms for the instruction sub-step (you already note this).

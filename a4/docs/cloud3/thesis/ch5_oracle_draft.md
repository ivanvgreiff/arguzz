% =====================================================================
% DRAFT — Chapter 5, Section 5.2 "Oracle"
% Drop-in LaTeX-markdown, written to follow 5.1 (Post-Execution Trace Mutations).
% =====================================================================

% ---------------------------------------------------------------------
% NOTES FOR YOU (not part of the prose — delete before compiling)
%
% 1. NAMING: I kept "A4" for the post-execution surface, consistent with the
%    5.1 draft (you may be globally swapping A4->A3; the prose here only says
%    "our mutations", so it's naming-agnostic except one parenthetical).
%
% 2. SCOPE: this section defines the oracle MECHANISM (the chapter-5 promise:
%    "define our oracle implementation helping us classify soundness-bug
%    candidates"). I keep the quantitative campaign results light and defer the
%    full numbers to Chapter 6 (Evaluation) — only the headline ("0 confirmed")
%    appears, framed as a verified negative. Move/expand as you see fit.
%
% 3. The internal name for this oracle is the D2.G "fault-propagation triage";
%    none of that jargon is in the prose. Exact code anchors are in CITATIONS.
%
% 4. Forward-ref placeholders "(Section ?)" / "(Chapter ?)" left for your
%    cross-refs (future-work adjudication; Chapter 6 evaluation).
% ---------------------------------------------------------------------


\section{Oracle}
\label{sec:oracle}

A fuzzer is only as useful as its \textit{oracle} — the mechanism that decides whether a given test actually exposed a bug. For ordinary software the oracle is usually self-evident: a crash, a failed assertion, a wrong answer. For zkVM \textit{soundness} the oracle is far more delicate, for the reason we gave in Chapter \ref{chap:analysis}: a soundness bug is an \textit{accepted proof of an execution that should have been rejected}, and crucially the program's public output is still correct (otherwise the verifier would reject on the public values alone, and we would learn nothing about the constraint system). There is therefore nothing in the output to flag. The only outward signal is the verifier's verdict itself. Our mutations deliberately make the trace semantically invalid, so the verifier \textit{ought} to reject; an \textbf{acceptance} is the event that something may have gone wrong.

This suggests a tempting one-line oracle: \textit{a mutation whose proof the verifier accepts is a soundness bug.} It does not work, and understanding precisely why is the substance of this section — it is what forces our oracle to be a multi-stage triage rather than a single check.


\subsection{Why Acceptance Alone Is Not a Soundness Bug}
\label{subsec:oracle-why}

Two facts defeat the naive oracle.

\textbf{First, acceptances are overwhelmingly no-ops.} A mutation can only matter if its altered value (a) reaches a witness column that some constraint actually reads, and (b) that constraint then fails to reject it. Most accepted mutations fail condition (a): the edited value is never bound to a constraint, so the proof the prover commits to is \textit{identical} to the one it would have produced without the mutation, and the acceptance is both correct and uninformative. We already met one face of this in Section \ref{subsec:a4-dead} (the inert trace cells); the same phenomenon recurs across the whole mutation catalog. The cleanest example is a mutation of the fetched instruction word: the circuit re-decodes the \textit{original} instruction from the committed instruction-fetch record (Section \ref{subsec:risc0-pipeline}), so it proves the original program no matter what the executor's local copy was changed to — it accepts whenever the perturbed run still produced a consistent witness. Empirically, the great majority of accepted proofs are exactly these inert cases, and the few mutation kinds that \textit{do} commit a corrupted value into the witness are almost always \textit{rejected} by the constraint system, exactly as soundness intends. A raw count of "accepted" mutations is therefore dominated by noise.

\textbf{Second, there is no output to compare against.} As noted above, the guest's only emitted value is a fixed sentinel, not a meaningful result. So unlike the completeness oracle of Chapter \ref{chap:analysis} — where Arguzz's product programs encode the expected answer inside the guest and compare outputs — we have no answer to check. To decide whether a mutation mattered, we must look at the \textit{execution} it produced, not at what it returned.

The real oracle therefore cannot ask "did the verifier accept?" It must ask, for every accepted proof, the sharper question:
\begin{center}
\textit{Did the fault actually propagate into the proven computation, or was it inert?}
\end{center}
Only a fault that genuinely changed the committed execution and was \textit{nonetheless} accepted is a soundness candidate. Separating those from the inert majority is the entire job of our oracle, which we therefore build as a \textbf{fault-propagation triage}.


\subsection{The Fault-Propagation Triage}
\label{subsec:oracle-triage}

The oracle classifies every accepted proof into one of three outcomes:

\begin{center}
\begin{tabular}{l l}
\textbf{Outcome} & \textbf{Meaning} \\
\hline
\textbf{no-op} & the mutation was \textit{provably} inert; the proof attests the original computation — not a bug. \\
\textbf{propagated candidate} & the mutation genuinely changed the execution, yet the verifier accepted — a soundness candidate. \\
\textbf{hidden global reject} & the verifier accepted, but the global-argument residue (Chapter \ref{chap:design}) flagged an imbalance — the strongest signal. \\
\end{tabular}
\end{center}

It reaches this verdict in two tiers, cheapest first, so that the expensive work is spent only where it is needed.

\paragraph{Tier 1 — the global-residue check (free).} Recall from Chapter \ref{chap:design} that for every run we extract the per-family residue of the global memory and lookup arguments ($\operatorname{res}_{\mathcal{F}}$). If an accepted proof has a \textit{nonzero} residue for any family, then the whole-trace permutation argument was violated even though the prover accepted the proof: the global constraint and the verifier disagree. That is the most direct soundness signal we can get, and detecting it costs nothing — the residue was already recorded during the campaign, so this tier is a pure lookup with no re-execution. Such an accept is classified a \textbf{hidden global reject}.

\paragraph{Tier 2 — trace-propagation comparison.} For every accept that Tier 1 did not already flag, we re-run the guest with the \textit{exact} recorded mutation (its kind, its target location, and its seed), capture the resulting execution trace, and compare it against the unmutated \textbf{baseline} trace. If the execution \textit{downstream} of the mutation diverges — a different control-flow path, a different sequence of program counters or events — then the fault demonstrably propagated, and the accept is a \textbf{propagated candidate}. If the downstream trace is identical, the mutation \textit{may} have been inert — but "the trace looks identical" is not the same as "the mutation was inert," and this gap is where the oracle must be most careful.

The difficulty is that the trace we can capture is \textit{coarse}: it records the instruction stream and program counters, but not every intermediate register and memory value, and (as established above) the output is a sentinel. So a naive "are the two traces identical?" test is wrong in both directions:
\begin{itemize}
  \item \textbf{Comparing too much over-reports.} Changing the \textit{target} of a branch that is \textit{not taken} alters the disassembled text of one instruction but changes nothing that executes — the program counters are unchanged. That is not propagation.
  \item \textbf{Comparing too little under-reports.} A store whose address changes can corrupt a \textit{different} memory word while the control flow — and hence the program-counter sequence — is byte-for-byte identical. Reducing the comparison to "did the PC stream change?" would silently miss exactly this data-corruption-with-intact-control-flow case, which is precisely where the subtlest soundness bugs would hide.
\end{itemize}

Our comparison is therefore aware of \textit{which kind} of mutation was applied and \textit{what that kind can affect}. The cleanest illustration is a store-offset change. RISC Zero is word-addressed, so a store whose offset moves \textit{within} the same 32-bit word — for example \texttt{sw} at offset \texttt{4} mutated to offset \texttt{6} — writes the \textit{identical} word and is a \textbf{provable} no-op; whereas one that crosses into a neighbouring word writes different memory and must be surfaced. A change that moves a \textit{byte} or \textit{half-word} lane, by contrast, always touches a different sub-word and is surfaced even when it stays in the same word. The oracle encodes a small, closed set of such \textit{provable-inertness} patterns — an unused instruction field, a within-word full-word access, a control-flow mutation that leaves the program-counter sequence unchanged, or a fault that genuinely produced no value change at all — and classifies a mutation as a no-op \textit{only} when it matches one of them.

\paragraph{The cardinal rule.} Everything that does \textit{not} match a provable-inertness pattern is surfaced as a candidate. This asymmetry is deliberate and is the single most important design principle of the oracle: \textit{we call a mutation a no-op only when its inertness is proven, and we surface everything else.} A spurious candidate is cheap to discard during later adjudication; a \textit{missed} candidate could bury the rare soundness bug we are hunting. When the coarse trace cannot prove a change was inert, the oracle surfaces it rather than risk silence.


\subsection{Trusting the Verdict}
\label{subsec:oracle-trust}

An oracle that reports "no candidates" is only meaningful if we can be sure it \textit{would} have reported a real one. We establish that two ways.

First, a \textbf{contract test on a known set}: we hand the oracle a small batch of accepted mutations whose correct classification we had already established by hand — including the subtle within-word store case above — and require it to reproduce that classification exactly. This guards against the classifier drifting as its rules grow.

Second, and more important, a \textbf{positive control}: we feed the oracle mutations we \textit{know} diverged — faults that the verifier had \textit{rejected}, so their downstream divergence is certain — and confirm that its propagation detector fires on every one of them. This rules out the one failure mode that would invalidate a null result: a detector silently stuck at "no divergence." With the positive control passing, a campaign outcome of \textit{zero} candidates becomes a \textbf{verified negative} — the oracle looked, with a detector demonstrated to work, and genuinely found none — rather than a broken instrument reporting silence.


\subsection{From Candidates to Confirmed Bugs}
\label{subsec:oracle-boundary}

It is important to state precisely what the oracle does and does not establish. It \textit{identifies} candidates; it does not \textit{confirm} bugs. A propagated candidate is a mutation that changed the execution and was still accepted — but that change may have produced a \textit{different yet equally valid} computation rather than a genuine soundness violation. Deciding which requires deeper adjudication: minimizing the mutation to its essential effect and checking whether the accepted witness truly violates the machine's intended semantics. That adjudication is expensive and is left to future work (Section \ref{?}); the oracle's role is precisely to compress the flood of raw acceptances down to the small, ranked set of genuine candidates that merit it.

On our single-guest campaign, the oracle's verdict was clean: of all the accepted proofs, none were hidden global rejects, and none exhibited a confirmed downstream divergence that survived as a candidate — \textbf{zero confirmed soundness bugs} on this guest within our mutation budget. We report this honestly and with its caveats: it is a \textit{verified} negative (the detector was validated against a positive control), it concerns a single guest program, and — as the exploration analysis of Chapter \ref{?} argues — broad constraint-space \textit{coverage} is evidence of \textit{potential}, not a substitute for a confirmed bug. With the oracle defined, we can now assemble the full fuzzing architecture in which it, the mutation surface of Section \ref{sec:post-execution}, and the learning scheduler of Chapter \ref{chap:design} operate together.


% ---------------------------------------------------------------------
% CITATIONS (for your appendix / footnotes — not prose)
%
% The oracle = the D2.G fault-propagation triage. Spec: a4/docs/cloud2/
%   IV_POS_8_D2_G_SPEC.md §3 (NOT D2.H — D2.H is the exploration notebook,
%   which explicitly disclaims being the triage, IV_POS_8_D2_H_SPEC.md:16).
%
% Three classes / six evidence labels:
%   a4/runs/iv_pos_8/d2g/propagation_triage.py:25-34
%   (accepted_noop / accepted_propagated_candidate / accepted_hidden_global_reject;
%    evidence strong/weak/identity/cosmetic/word_truncated/cf_inert).
%
% "Acceptance is no-op-dominated; output is a sentinel" — F19; D2_G_SPEC.md:40,70.
% Commit dichotomy (instruction-word = proof-invisible; only 2 of 11 kinds ever
%   accept; the 9 committed kinds = 0 accepts) — F26, D2_G_SPEC.md:83;
%   rv32im.rs:643 (committed fetch) vs :662 (local word).
%
% Accept set = outcome='applied' AND config_json.soundness_signal=1:
%   propagation_triage.py:132-140. soundness_signal definition:
%   arguzz_invoke.py:97-98.
%
% Tier 1 (global residue → hidden reject): propagation_triage.py:384-387;
%   global_failures table fed by Hook-3 residue (ffi.cpp <a4_family_residue>
%   -> touch_coverage.py:179-228 -> coverage_db.py:1084).
% Tier 2 (--trace rerun + classify_semantics): propagation_triage.py:269-381,
%   390-413. Coarse trace {step,pc,instruction,assembly}, sentinel output.
% Why not full-hash (over) / PC-only (under): D2_G_SPEC.md:80-81.
% Word-addressed within-word store no-op (step 3939 sw 4->6) + sub-word lane
%   rule: D2_G_SPEC.md:93-96; propagation_triage.py:355-376. Word-truncation:
%   risc0 ByteAddr.waddr()=addr/4 (addr.rs:35), misalign trap injection-gated.
% Cardinal fail-safe ("only noop when proven; else surface"):
%   propagation_triage.py:290-291; D2_G_SPEC.md:98.
%
% Scaling: kind-aware dedup 2795 raw accepts -> 1423 reruns
%   (INSTR_WORD_MOD on (variant,kind,step); POST_EXEC_PC_MOD keeps iter_seed):
%   propagation_triage.py:519-545; POS chain dispatch triage_at_scale.py.
%
% Validation:
%   Smoke contract test (8 accepts -> 8 noop/0/0, step 3939=word_truncated):
%     validate_smoke_oracle, propagation_triage.py:548-566.
%   Positive control (3 divergent REJECTED POST_EXEC_PC_MOD reruns -> all
%     evidence=strong, post_inject_pc_changed=True): central-planning-1.md:77;
%     D2G_F29_COMPOSER_REPORT.md:16.
%
% Result (full 4-variant x 3-seed x N=10000, sha2-host):
%   2795 raw accepts -> 1423 deduped -> 1313 noop / 110 propagated (all weak)
%   / 0 hidden / 0 strong -> 0 confirmed soundness bugs.
%   d2g_soundness_reread.{md,json}; D2_G_SPEC.md:172 ("0 strong / 0 hidden,
%   F29 verified-negative against a positive control"). 733 POST_EXEC_PC_MOD
%   accepts -> 731 cf_inert + 2 weak + 0 strong.
%
% Boundary: oracle identifies candidates; deep adjudication (witness
%   repair/minimization, "Mode-B") is D3, deferred/not implemented —
%   D2_G_SPEC.md:19, DG-5:197. propagated_candidate != confirmed bug.
% ---------------------------------------------------------------------

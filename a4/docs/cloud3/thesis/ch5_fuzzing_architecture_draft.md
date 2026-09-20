% =====================================================================
% DRAFT — Chapter 5, Section 5.3 "Fuzzing Architecture"
% High-level repo/architecture overview. Drop-in LaTeX-markdown; follows 5.1/5.2.
% =====================================================================

% ---------------------------------------------------------------------
% NOTES FOR YOU (not part of the prose — delete before compiling)
%
% 1. NAMING (folded to your thesis convention). Prose uses your Chapter-4
%    variant names — Arguzz / Arguzz Bandit / A3 Bandit / A3+Arguzz Bandit —
%    and "A3" for the post-execution surface throughout. The codebase
%    identifiers (V5_control / V6_uniform / V6_cTS / Hybrid_cTS, the surface
%    string "a4", env var A4_MUTATION_CONFIG, selectors cTS_semantic_v2 etc.)
%    appear ONLY in the variant table's last column and in CITATIONS, framed
%    as literal implementation identifiers.
%    ⚠ The 5.1 draft still uses "A4" for the surface in prose — for
%    whole-chapter consistency, flip 5.1's prose A4->A3 (keep literal code
%    tokens like A4_MUTATION_CONFIG / A4_INSPECT as-is). I can do that on ask.
%
% 2. "POS" is the internal name for your GPU prover cluster; prose says
%    "the prover cluster". Phase tags (IV.POS.8/9, D2.F, Track-B) + SHAs are
%    in CITATIONS only.
%
% 3. SCOPE: deliberately high-level and not long; synthesizes 5.1 (mutations),
%    Ch.4 (scheduler), 5.2 (oracle). Quantitative results stay in Chapter 6.
%
% 4. FIGURES: two TikZ figures (Fig.~\ref{fig:fuzzing-architecture} the system,
%    Fig.~\ref{fig:per-mutation-loop} the loop). Each has a commented ASCII
%    preview of the intended layout — swap in your own vector art if preferred.
%    They compile as-is given:  \usepackage{tikz}
%    \usetikzlibrary{arrows.meta, positioning}  (in your preamble).
% ---------------------------------------------------------------------


\section{Fuzzing Architecture}
\label{sec:fuzzing-architecture}

Having defined our mutation surface (Section \ref{sec:post-execution}), the learning scheduler (Chapter \ref{chap:design}), and the oracle (Section \ref{sec:oracle}) in isolation, we now step back and describe how they fit together into one system, and how that system is laid out as a repository. The guiding idea is simple: our architecture is two halves that meet at a single seam.

\begin{itemize}
  \item A \textbf{fuzzer engine}, written in Python, that \textit{decides} — it chooses which mutation to apply next, learns from the feedback, and records everything.
  \item A \textbf{forked, instrumented zkVM}, written in Rust/C++, that is simultaneously the \textit{target} of the mutations and the \textit{source} of the feedback.
\end{itemize}

The two communicate in the most decoupled way possible: the engine launches the zkVM as an ordinary subprocess (a single \texttt{risc0-host} binary), hands it a mutation through environment variables and command-line flags, and reads the constraint-system's response back by parsing tagged lines from the binary's output. Nothing about the proving internals leaks into the Python; nothing about the search strategy leaks into the circuit. This seam is what let us build the entire scheduler, reward, and oracle as plain Python on top of an unmodified-by-us proving algorithm.

\begin{figure}[h]
\centering
% --- ASCII preview of the intended layout (the TikZ below renders this) ---
%  +---------------------------- FUZZER ENGINE (Python) ----------------------------+
%  |  A4Fuzzer:  cTS scheduler  ->  mutation catalog  ->  reward / discovery bit     |--records--> [run.db]
%  +-------------------------------------------------------------------------------- +
%       |  mutation request                                ^  constraint feedback
%       |  (A4_MUTATION_CONFIG / --inject flags)            |  (<constraint_fail>, <a4_family_residue>)
%       v                                                   |
%  +---------------------------- risc0-host binary ---------------------------------+
%  |  forked, instrumented RISC Zero: guest ELF + inject hook + failure/residue emit |
%  +-------------------------------------------------------------------------------- +
%  grid of (variant x guest x seed) runs  ==>  prover cluster  ==>  many run.db
\begin{tikzpicture}[
  font=\small, >=Stealth,
  layer/.style={draw, rounded corners, align=center, inner sep=8pt, minimum width=11cm},
  store/.style={draw, rounded corners, align=center, inner sep=6pt, fill=black!4},
  seam/.style={font=\footnotesize\itshape, align=center},
]
  \node[layer, fill=blue!5] (engine)
    {\textbf{Fuzzer engine}\,---\,Python (\texttt{a4/})\\[3pt]
     cTS scheduler \;$\to$\; mutation catalog \;$\to$\; reward / discovery bit};
  \node[layer, fill=orange!5, below=2.6cm of engine] (vm)
    {\textbf{Target}\,---\,forked, instrumented RISC~Zero (\texttt{risc0-host})\\[3pt]
     guest ELF \;+\; mutation-injection hook \;+\; constraint-fail \& residue emitters};
  \node[store, right=1cm of engine] (db) {\texttt{run.db}\\(SQLite)};
  \draw[->] ([xshift=-2.6cm]engine.south) -- ++(0,-2.6)
     node[seam, midway, left=3pt]{mutation\\request};
  \draw[->] ([xshift=2.6cm]vm.north) -- ++(0,2.6)
     node[seam, midway, right=3pt]{constraint\\feedback};
  \draw[->] (engine.east) -- (db.west) node[seam, midway, above]{records};
  \node[seam, below=0.6cm of vm]
    {a grid of (variant $\times$ guest $\times$ seed) runs \;$\Rightarrow$\; prover cluster \;$\Rightarrow$\; many \texttt{run.db}};
\end{tikzpicture}
\caption{The two-layer architecture. A Python fuzzer engine drives a forked, instrumented RISC~Zero --- the single \texttt{risc0-host} binary --- across one seam: a \emph{mutation request} passes down as environment variables and command-line flags (\texttt{A4\_MUTATION\_CONFIG} for an A3 mutation, \texttt{--inject} flags for an Arguzz fault), and the constraint system's \emph{feedback} comes back up as tagged output the engine parses (local \texttt{<constraint\_fail>} records and the global \texttt{<a4\_family\_residue>}). Each mutation is recorded to a per-run SQLite database; a campaign fans a grid of runs across a prover cluster.}
\label{fig:fuzzing-architecture}
\end{figure}


\subsection{The Target: A Forked, Instrumented RISC Zero}
\label{subsec:arch-target}

Our framework is \textbf{RISC Zero}, the production zkVM whose pipeline we dissected in Section \ref{subsec:risc0-pipeline}. We do not reimplement it; we \textit{fork} it. The fork lives in the repository as a git submodule and carries exactly the instrumentation the previous two sections described: the post-execution trace-cell mutation hook in the witness-generation module, the local-constraint-failure reporting in the equality-to-zero routine, the global-residue extraction (Hook 3) in the accumulation phase, and Arguzz's execution-time fault injection in the emulator. These are the only changes; the proving algorithm itself is RISC Zero's.

The fork is exposed to the outside world as a single executable, the \texttt{risc0-host} binary, built from a small Rust workspace that links the forked crates directly (rather than the public releases). The binary's job is narrow: parse its flags, push the requested fault or mutation into the fork's global state, run the guest program, prove it, and verify the proof — emitting along the way the tagged records the engine consumes. The guest program is compiled to RISC-V and embedded into the same binary at build time, so a campaign against a given guest is just repeated invocations of one self-contained executable.

One implementation detail matters for the integrity of our experiments. Because we run several \textit{different} builds of the fork — a clean baseline, a build with a deliberately planted constraint hole, and a build reproducing a known real-world under-constraint — each lives in its own checkout with its own output directory, and each binary is stamped at build time with an un-spoofable fingerprint (which bug, if any, it contains, and the exact source commit). Before any run on the cluster, a guard asserts that the deployed binary's fingerprint matches the one the experiment expects. This prevents the single most insidious experimental error in this setting: silently fuzzing the wrong binary and misattributing the result.


\subsection{The Engine: One Fuzzer, Four Variants}
\label{subsec:arch-engine}

The Python side is a single engine, \texttt{A4Fuzzer}, parameterized into the four variants rather than four separate programs. A campaign is one call to its run loop, which repeats the cycle the earlier sections built up, once per mutation:

\begin{enumerate}
  \item \textbf{select} an arm (a mutation kind, in a trace zone) from the scheduler (Chapter \ref{chap:design});
  \item \textbf{instantiate} a concrete mutation within that arm and \textbf{run} it against the \texttt{risc0-host} binary;
  \item \textbf{parse} the constraint-system feedback (local failures, the global residue) from the binary's output;
  \item \textbf{reward} the arm with the binary discovery signal and \textbf{update} the posterior;
  \item \textbf{record} the mutation, its feedback, and the scheduler's decision to the results database.
\end{enumerate}

\begin{figure}[h]
\centering
% --- ASCII preview (the TikZ below renders this loop) ---
%   (1) Select arm  -->  (2) Instantiate & run  -->  (3) Parse feedback
%        ^  (scheduler)        (risc0-host)            (local gamma, global residue)
%        |                                                     |
%   (5) Update posterior  <-------------------------  (4) Reward: bit b = 1[l+g+s>0]
%        + record to run.db
\begin{tikzpicture}[
  font=\footnotesize, >=Stealth, node distance=1.1cm and 1.4cm,
  step/.style={draw, rounded corners, align=center, inner sep=5pt},
]
  \node[step] (sel) {1.~\textbf{Select arm}\\(cold / floor / adaptive)};
  \node[step, right=of sel] (run) {2.~\textbf{Instantiate \& run}\\(\texttt{risc0-host})};
  \node[step, right=of run] (parse) {3.~\textbf{Parse feedback}\\(local $\gamma$, global residue)};
  \node[step, below=of parse] (reward) {4.~\textbf{Reward}\\$b=\mathbb{1}[\ell{+}g{+}s>0]$};
  \node[step, below=of sel] (rec) {5.~\textbf{Update posterior}\\+ record to \texttt{run.db}};
  \draw[->] (sel) -- (run);
  \draw[->] (run) -- (parse);
  \draw[->] (parse) -- (reward);
  \draw[->] (reward) -- (rec);
  \draw[->] (rec) -- (sel);
\end{tikzpicture}
\caption{The per-mutation feedback loop, executed once per pull of a campaign: the scheduler selects an arm, the mutation is instantiated and run against the host binary, the constraint-system feedback is parsed, the arm is rewarded with the binary discovery signal and its posterior updated, and the outcome is recorded --- closing the loop. Only the mutation surface (Section~\ref{sec:post-execution}) and the scheduler (Chapter~\ref{chap:design}) differ across the four variants; this loop is shared by all of them.}
\label{fig:per-mutation-loop}
\end{figure}

Two things vary across the four variants, and \textit{only} two: the \textbf{mutation surface} (which kinds are in play) and the \textbf{scheduler} (how arms are chosen). Everything else — the host invocation, the feedback parsing, the reward, the database — is shared. This is the central implementation fact about our architecture: the variants are \textit{configurations}, not codebases. Concretely:

\begin{center}
\begin{tabular}{l l l l}
\textbf{Variant} & \textbf{Surface} & \textbf{Scheduler} & \textbf{Codebase identifier} \\
\hline
Arguzz            & Arguzz (during-exec) & round-robin (no learning) & \texttt{V6\_uniform} \\
Arguzz Bandit     & Arguzz (during-exec) & our cTS bandit            & \texttt{V6\_cTS} \\
A3 Bandit         & A3 (post-exec)       & our cTS bandit            & \texttt{V5\_control} \\
A3+Arguzz Bandit  & both                 & our cTS bandit            & \texttt{Hybrid\_cTS} \\
\end{tabular}
\end{center}

\noindent The rightmost column gives the name each variant carries in the codebase and in the run databases (the selector strings and the variant registry use these identifiers); the prose throughout uses the Chapter \ref{chap:design} names.

The mutation surface is selected at the host-invocation seam: an A3 (post-execution) mutation is delivered by writing a small JSON mutation request and pointing the binary at it through an environment variable (Section \ref{subsec:a4-hooks}), whereas an Arguzz mutation is delivered by passing \texttt{--inject} flags naming the fault kind, target step, and seed. The hybrid variant simply carries arms of both surfaces in one arm space and routes each pull to the appropriate seam. The scheduler is selected by a single \texttt{--selector} argument. Three of the four variants therefore launch with one command — \texttt{cli fuzz --host <binary> --db <run.db> --seed S --num N --selector <variant>} — and the round-robin Arguzz baseline launches through a thin sibling driver that reuses the same invocation primitive and writes the same database. A canonical variant registry is the single source of truth for these launch commands, so smoke tests, cluster manifests, and the analysis all agree on what each variant is.


\subsection{From a Single Run to a Campaign}
\label{subsec:arch-campaign}

A \textbf{single run} is one (variant, guest, seed, budget) tuple; it produces one self-contained SQLite database recording every mutation, every constraint failure, every global residue, and every scheduler decision. That database \textit{is} the run's output — all of our coverage curves, territory comparisons, and the soundness triage of Section \ref{sec:oracle} are computed offline from it, never live.

A \textbf{campaign} is a grid of such runs — the four variants $\times$ several seeds, and in our most recent campaign $\times$ several guest programs — fanned out across a cluster of GPU prover nodes (proving is the dominant cost, so the runs are embarrassingly parallel across nodes). A manifest generator enumerates the grid into per-node jobs, a batch dispatcher ships the code bundle and the correct binary to each node, launches the jobs, polls for completion, and pulls each finished database back; a collector then validates the set before analysis. Crucially, the recent multi-guest sweep — which runs all four variants across guests stressing different parts of the machine (a hashing baseline, a system-call-heavy guest, a memory-stress guest, and an accelerator guest) — \textit{reuses the exact same launch commands} from the variant registry, prefixed only by the binary-fingerprint guard. So scaling from one laptop run to a multi-hundred-job cluster campaign changes the orchestration around the engine, not the engine itself.


\subsection{The Load-Bearing Files}
\label{subsec:arch-files}

The repository is large, but a small set of files carries the architecture. They divide along the seam.

\textbf{The fuzzer engine (Python, \texttt{a4/}):}

\begin{center}
\begin{tabular}{l l}
\textbf{File} & \textbf{Role} \\
\hline
\texttt{standalone/fuzzer.py} & the engine — the campaign loop and per-mutation control flow for all variants \\
\texttt{standalone/cli.py} & the entry point (\texttt{fuzz} command) for the three bandit variants \\
\texttt{standalone/variants.py} & the variant registry — the canonical definition + launch command of each variant \\
\texttt{standalone/bandit\_ts.py} & the constrained Thompson-sampling scheduler (the learning) \\
\texttt{standalone/v6\_uniform\_driver.py} & the entry point for the round-robin Arguzz baseline \\
\texttt{core/executor.py} & runs an A3 (post-execution) mutation against the host binary \\
\texttt{standalone/arguzz\_invoke.py} & runs an Arguzz (during-execution) fault against the host binary \\
\texttt{standalone/mutations/} (+ \texttt{arguzz\_bridge.py}) & the mutation catalog and the bandit-arm $\rightarrow$ invocation bridge \\
\texttt{standalone/reward\_v2.py} & the reward function + the binary discovery signal the bandit learns from \\
\texttt{standalone/coverage\_db.py} & the SQLite results store (the campaign's entire output) \\
\end{tabular}
\end{center}

\textbf{The instrumented zkVM (Rust/C++, \texttt{workspace/}):}

\begin{center}
\begin{tabular}{l l}
\textbf{File} & \textbf{Role} \\
\hline
\texttt{output/host/src/main.rs} & the \texttt{risc0-host} binary — the one process the engine drives \\
\texttt{risc0-modified/} (submodule) & the forked, instrumented RISC Zero (all the circuit/witgen hooks) \\
\end{tabular}
\end{center}

\textbf{The cluster orchestration (\texttt{a4/pos/}, \texttt{a4/runs/.../sweep/}):} the manifest generators, the batch dispatcher, and the result collector that turn the four launch commands into a fanned-out, fingerprint-guarded campaign and gather the databases back for analysis.

In short: \textbf{one engine} (\texttt{fuzzer.py}) drives \textbf{one binary} (\texttt{risc0-host}, a forked RISC Zero) through \textbf{one seam} (subprocess + flags + parsed output), is specialized into \textbf{four variants} by a registry (\texttt{variants.py}) selecting a surface and a scheduler, writes every run into \textbf{one database schema} (\texttt{coverage\_db.py}), and is scaled to multi-guest campaigns by a generic dispatcher that reuses the very same launch commands. The mutation surface of Section \ref{sec:post-execution}, the learner of Chapter \ref{chap:design}, and the oracle of Section \ref{sec:oracle} are the three substantive components that plug into this skeleton.


% ---------------------------------------------------------------------
% CITATIONS / GROUNDING (for your appendix — not prose)
%
% Two-layer seam (subprocess + env/flags + parsed tagged output):
%   A4 surface: a4/core/executor.py:187-228 (run_a4_mutation; env A4_MUTATION_CONFIG,
%     CONSTRAINT_CONTINUE, A4_COVERAGE_TOUCH, A4_FAMILY_RESIDUE; parses failures/
%     touch/family residues).
%   Arguzz surface: a4/standalone/arguzz_invoke.py:116-154 (run; --inject
%     --inject-step --inject-kind --seed; parse_prover_status -> soundness_signal :97-98).
%
% Framework / fork:
%   .gitmodules — workspace/risc0-modified = fork of github.com/ivanvgreiff/risc0,
%     branch arguzz/b7-race-instrumentation (@ 6556e8d7, on 28e53771).
%   Host links the fork by path: workspace/output/host/Cargo.toml (risc0-zkvm + fuzzer_utils
%     path deps; feature prove=[...,"witgen_debug"]). Host CLI + injection wiring:
%     workspace/output/host/src/main.rs:9-44 (Args: --trace/--inject/--inject-step/-kind/
%     --seed/--in0..4), :81-90 (fuzzer_utils set_injection*/enable_assertions), :158-159
%     (prove_with_opts), :231 (receipt.verify). Guest ELF: workspace/output/methods/build.rs
%     (risc0_build::embed_methods) -> RISC0_GUEST_ELF/ID consumed in main.rs:1-3.
%   Sibling builds (own checkout + output dir each): risc0-modified -> output/ (main/AP);
%     risc0-clean-28e53771 @ 53c21894 (branch arguzz/track-b-multiguest) -> output-trackb/
%     (clean baseline); risc0-a1-vuln @ 088a0753 -> output-a1vuln/ (CVE under-constraint,
%     upstream 98387806); risc0-seamb @ 93bda33b -> output-seamb/ (planted VerifyOpcode hole).
%   Fingerprint stamp + guard: host/src/main.rs emit_build_fingerprint_if_requested
%     (A4_INSPECT_FINGERPRINT / A4_PLANTED_BUG); guard a4/pos/fingerprint_guard.py asserted
%     before each cluster job.
%
% Engine + per-mutation loop:
%   a4/standalone/fuzzer.py: A4Fuzzer (:244), run_campaign (:1702), setup branch (:1742-1759),
%     loop (:1763-1777); _run_v2_bandit_mutation (:1347) routes by arm surface to the A4 path
%     (run_a4_mutation, :1417) or _run_arguzz_cts_mutation (:1195 -> arguzz_invoke.run).
%   Surface selection per variant: _arguzz_strategy_config (:772-784).
%   Bandit: a4/standalone/bandit_ts.py (ConstrainedTSScheduler). Reward + bit:
%     a4/standalone/reward_v2.py (compute_reward_v2, compute_bandit_success).
%   Arm->invocation bridge: a4/standalone/mutations/arguzz_bridge.py (create_mutation_for_arm).
%
% Variants registry + launch commands:
%   a4/standalone/variants.py: CANONICAL_VARIANTS (:26-71) — V5_control (cli, cTS_semantic_v2,
%     a4), V6_uniform (driver, a4.standalone.v6_uniform_driver, arguzz, round-robin),
%     V6_cTS (cli, v6_cTS, arguzz, bernoulli+applied), Hybrid_cTS (cli, hybrid_cTS, hybrid).
%     variant_launch_command (:82-119) emits the exact argv. cli fuzz: a4/standalone/cli.py:33-68.
%   V6_uniform launcher: a4/standalone/v6_uniform_driver.py:80 (main; ArguzzScheduler round-robin;
%     reuses arguzz bridge + same CoverageDB).
%
% Results DB (the run output):
%   a4/standalone/coverage_db.py: CoverageDB (:66); tables campaigns(:84), mutations(:97),
%     failures(:128), coverage(:150), global_failures(:182), bandit_decisions(:293),
%     compressed_global_coverage(:425), local_coverage_v2(:450), etc.
%
% Campaign dispatch / cluster (POS):
%   a4/pos/chain_dispatcher.sh (batch|node|run_id|remote_cmd manifest runner, resume-safe);
%   a4/pos/dispatch_pos.py (poslib dispatcher); a4/pos/collect_results_pos.py (collector);
%   generate_*_manifests.py.
%   Multi-guest sweep: a4/runs/iv_pos_9/sweep/generate_sweep_manifests.py (imports
%     variants.CANONICAL_VARIANTS + variant_launch_command, :28; GUEST_SPECS g0..g3 :48-69;
%     fingerprint-guarded remote_cmd :121-131); run_sweep_pos.sh; build_sweep_curves.py.
%
% Recent campaigns: IV.POS.8 D2.F = 4 variants x 3 seeds x N=10000 (single guest sha2-host);
%   IV.POS.9 Track-B = multi-guest sweep, 4 guests x 4 variants. (git log, this session.)
% ---------------------------------------------------------------------

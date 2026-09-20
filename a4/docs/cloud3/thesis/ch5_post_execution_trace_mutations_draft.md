% =====================================================================
% DRAFT — Chapter 5, Section 5.1 "Post Execution Trace Mutations"
% Source-grounded prose for the four bullet points. Drop-in LaTeX-markdown.
% =====================================================================

% ---------------------------------------------------------------------
% NOTES FOR YOU (not part of the prose — delete before compiling)
%
% 1. NAMING (A3 vs A4): Your Design chapter names the post-execution trace
%    fuzzer "A3" (and the variants "A3 Bandit", "A3+Arguzz Bandit"). The
%    codebase — and this section, because the bullet says "a4 mutation
%    kinds" — uses "A4". Pick one and apply globally. I wrote A4 below to
%    match the source and your bullet; if you prefer A3 in prose, swap
%    every "A4" -> "A3" here (the *kind names* like A4_MUTATION_CONFIG stay
%    A4 since they are literal code identifiers).
%
% 2. "RawTrace" vs "PreflightTrace": Chapters 3-4 call the post-execution
%    object the \texttt{RawTrace}. In RISC Zero's rv32im (v2) circuit there
%    is no type literally named RawTrace; the concrete object our fuzzer
%    edits is the \texttt{PreflightTrace} produced by a dedicated preflight
%    pass. I introduce this correspondence explicitly in 5.1.1 — consider
%    aligning the earlier chapters to say "preflight trace" too, or add one
%    sentence there noting RawTrace = PreflightTrace.
%
% 3. Figures you may want: (a) the three-pass pipeline
%    Executor->Segment->Preflight->PreflightTrace->Witgen with the A4
%    injection arrow between Preflight and Witgen; (b) a small table of the
%    PreflightCycle / MemoryTransaction fields.
%
% 4. Every factual claim below is grounded in source; key file:line anchors
%    are listed in the "CITATIONS" comment at the end for your appendix.
%
% 5. PROPOSED MUTATIONS (5.1.6): these come from ProG_Report_4 §Q5 (the advisor's
%    "mechanism-selected next batch"), grounded field-by-field in the D2.B
%    mechanism report §11. ProG_Report_5 proposes NO new trace mutations — it only
%    proposes a bigint/paging *guest* that would activate them. I wrote 5.1.6 as
%    "we identified ..." (your thesis voice) rather than naming the internal
%    reports; cite/attribute however your thesis handles advisor input. I did NOT
%    invent any ProG_5 mutations.
% ---------------------------------------------------------------------


\section{Post Execution Trace Mutations}
\label{sec:post-execution}

In Chapter 4 we argued, at the level of design, that a fuzzer which edits the trace \textit{after} the guest program has finished executing should shift the constraint-targeting bias away from the within-step local constraints that Arguzz tends to exercise, and toward the interstep and global constraints that bind the trace together as one consistent object. That argument was deliberately abstract: it spoke of "the post-execution trace" without saying what that object concretely \textit{is} inside a real zkVM, nor where in the proving pipeline it can be intercepted. This section makes the argument concrete. We first walk through how RISC Zero actually turns a guest program into a witness, and why it is built in separate passes (\ref{subsec:risc0-pipeline}); this tells us exactly which object the post-execution mutation operates on and why that object exists at all. We then locate Arguzz's mutations inside that pipeline (\ref{subsec:arguzz-kinds}), show precisely what such execution-time injection structurally \textit{cannot} reach (\ref{subsec:arguzz-cannot}), and present our own catalog of post-execution mutations, which we call the A4 kinds (\ref{subsec:a4-kinds}). We then account for the cells that turned out to be \textit{inert} (\ref{subsec:a4-dead}) and the surfaces we have identified for future work (\ref{subsec:a4-proposed}), and close by pinpointing exactly where in RISC Zero these mutations are applied and where we read the constraint system's response (\ref{subsec:a4-hooks}).


\subsection{The RISC Zero Execution Pipeline}
\label{subsec:risc0-pipeline}

A natural first guess is that a zkVM executes the guest program and, as it goes, fills in the witness table row by row in a single pass. RISC Zero does not work this way, and the reasons it does not are exactly the reasons our post-execution mutation surface exists. RISC Zero turns a guest program into a proof in three distinct passes, each producing a concrete object that the next pass consumes:
$$
\underbrace{\texttt{Executor}}_{\text{pass 1}} \;\longrightarrow\; \texttt{Segment} \;\longrightarrow\; \underbrace{\texttt{Preflight}}_{\text{pass 2}} \;\longrightarrow\; \texttt{PreflightTrace} \;\longrightarrow\; \underbrace{\texttt{Witgen}}_{\text{pass 3}} \;\longrightarrow\; \text{witness}
$$
Understanding why these passes are separated is what tells us where, and why, a single cell of the trace can be meaningfully edited.

\paragraph{Why execution comes first, and alone.} A STARK proof is generated over a trace of a \textit{fixed} height, namely $2^{\,\text{po2}}$ rows. A long-running program will not fit in one such trace, so RISC Zero proves it in fixed-size chunks called \textit{segments} and chains them together (the continuations mechanism). The difficulty is that the right place to cut one segment from the next is \textit{data-dependent}: a single instruction can cost anywhere from one cycle to tens of thousands of cycles (a big-integer accelerator instruction can consume up to roughly twenty-five thousand cycles), so one cannot know in advance how many guest instructions will fit in a $2^{\,\text{po2}}$-row segment. The only way to discover the segment boundaries is to \textit{run the program first}. This is the job of the \textbf{executor} (\texttt{rv32im.rs}): it interprets the RISC-V guest at speed, tracking only what it must — the program counter, the registers, and a working set of memory — and it does \textit{not} build a detailed trace. Its output per segment is a lean \texttt{Segment} object containing just enough information to faithfully \textit{replay} that segment later: the initial memory image of the pages the segment touches, a record of the host inputs and outputs it consumed, and the claimed start and end states. The crucial intuition is that the executor's purpose is not to produce the witness, but to discover the shape of the computation so that a fixed-height trace can be built for each segment.

\paragraph{Why memory is recorded as transactions with back-pointers.} The most demanding thing a zkVM must prove about an execution is \textit{memory consistency}: that every read from an address returns the value most recently written to that address, even if that write happened thousands of rows earlier. RISC Zero does not, and cannot, check this row-by-row; it proves it globally, with the permutation argument introduced in Chapter 4. For that argument to work, every single memory access must be recorded not just as "address $a$ held value $v$ at this cycle," but together with a \textit{back-pointer} to the previous access of that same address. This is why, when the trace is finally materialized, each memory access becomes a \texttt{MemoryTransaction} carrying five fields:
$$
\texttt{MemoryTransaction} = (\,\texttt{addr},\; \texttt{cycle},\; \texttt{word},\; \texttt{prev\_cycle},\; \texttt{prev\_word}\,),
$$
where \texttt{word} is the value read or written, and the pair $(\texttt{prev\_cycle}, \texttt{prev\_word})$ points back to the value and time of the previous touch of \texttt{addr}. These back-pointers are precisely the wiring that the memory-consistency argument consumes; the chain they form, sorted per address, is what lets the circuit assert that reads and writes line up. A subtle but important consequence for us is that registers are not special: RISC Zero memory-maps the register file into the high address space, so reading or writing register \texttt{x5} \textit{is} a memory transaction like any other. Every value the machine touches — instruction words, register reads, register writes, loads, stores — flows through this same transaction record.

\paragraph{Why a separate preflight pass.} The back-pointers above do not exist while the program is naively executing; they can only be filled in once the \textit{complete, ordered} set of memory accesses is known. RISC Zero therefore introduces a second pass, \textbf{preflight}, whose sole job is to re-run a segment — deterministically, by replaying the host inputs the executor recorded — and this time \textit{materialize} the full trace. Because the replay is a pure function of the \texttt{Segment}, it is reproducible: the same instructions, the same memory, the same host I/O. The preflight pass walks the execution and emits, for every circuit row, a \texttt{PreflightCycle},
$$
\texttt{PreflightCycle} = (\,\texttt{state},\; \texttt{pc},\; \texttt{major},\; \texttt{minor},\; \texttt{machine\_mode},\; \texttt{user\_cycle},\; \texttt{txn\_idx},\; \texttt{diff\_count}[2],\; \dots\,),
$$
and, for every memory access, the \texttt{MemoryTransaction} described above. The \texttt{major} and \texttt{minor} fields are the integer encoding of \textit{which operation} the row performs — the very same $(\texttt{major},\texttt{minor})$ pair that appears in our local failure context $\gamma$ from Section~\ref{subsec:local-constraint-failure-retrieval}. RISC Zero groups the instruction set into thirteen major families (arithmetic and logic, multiply, divide, loads, stores, control, ecall, the Poseidon2 and SHA-256 accelerators, and big-integer), and \texttt{minor} selects the specific operation within a family. The \texttt{user\_cycle} field records which guest \textit{step} a row belongs to (so that a multi-cycle operation such as an ecall maps many rows back to one guest step), \texttt{txn\_idx} points a row to its first memory transaction, and \texttt{diff\_count} holds the small histogram the memory argument uses to range-check the gaps between successive accesses to an address.

\paragraph{Why the whole trace is materialized before the witness is filled.} The final pass, \textbf{witness generation} (witgen), consumes the \texttt{PreflightTrace} and fills the actual circuit columns. RISC Zero fills these columns \textit{in parallel} across rows. For a row to be computable independently of its neighbours, everything that row needs — its operation labels, its transaction indices, and its back-pointers into earlier rows — must \textit{already exist} in a finished, immutable trace. A single forward pass that built the witness while executing could neither be parallelized this way nor look "back in time" to a prior write without having first seen the entire access stream. This is the final reason the trace is fully materialized first.

\paragraph{The payoff: a clean interception point.} Stacking these four design decisions yields exactly the structure our fuzzer exploits. Because segmentation forces execution to run first, because the memory argument forces every access to be recorded with back-pointers, and because parallel witgen forces the trace to be fully materialized before it is consumed, RISC Zero necessarily produces a \textbf{complete, self-contained \texttt{PreflightTrace} that sits in memory between execution and witness generation}. This object is what Chapters 3 and 4 referred to abstractly as the post-execution \texttt{RawTrace}. It is a flat pair of arrays — one of \texttt{PreflightCycle}s, one of \texttt{MemoryTransaction}s — that witgen will read \textit{verbatim}. Editing a single field of a single element of those arrays therefore changes exactly the bytes the witness is built from, with no re-execution and no recompilation. That single-cell edit is the entire basis of our post-execution mutation surface, and the next subsections make precise why it reaches constraints that Arguzz's execution-time injection cannot.


\subsection{Arguzz Mutation Kinds in the Executor}
\label{subsec:arguzz-kinds}

Arguzz operates one pass earlier than the object we just described: it injects faults \textit{inside the executor}, while the emulator is stepping through the guest. Concretely, the RISC Zero emulator in \texttt{rv32im.rs} is augmented with a fault-injection context that is consulted at fixed points of every instruction step. A fuzzing run is parameterized by a triple $(\texttt{step}, \texttt{kind}, \texttt{seed})$: the context fires only when the emulator reaches the target step and the requested kind matches, at which point it perturbs the live machine state and lets execution \textit{continue as if the fault had always been there}. To ensure the corrupted execution is not simply rejected inside the emulator, Arguzz simultaneously disables the executor's own validity guards (the alignment, access, and illegal-instruction checks), so that the fault is carried forward into witness generation and proving rather than trapped early. The injected value itself is not supplied from outside; it is drawn from the seeded random generator, which is what makes a run reproducible from its $(\texttt{step},\texttt{kind},\texttt{seed})$.

The points at which the context can fire trace the natural anatomy of an instruction step: fetch the program counter, fetch the instruction word, decode and execute it, and write back its result. Arguzz exposes eleven mutation kinds across these points. They divide cleanly into perturbations applied \textit{before} an instruction's logic runs and perturbations applied \textit{at or after} its result is produced.

\begin{center}
\begin{tabular}{l l l l}
\textbf{Kind} & \textbf{What it perturbs} & \textbf{Phase} & \textbf{Effect} \\
\hline
\texttt{PRE\_EXEC\_PC\_MOD}   & program counter, pre-fetch        & pre  & fetch/execute from a wrong address \\
\texttt{INSTR\_WORD\_MOD}     & fetched instruction word          & pre  & decode/run a different instruction \\
\texttt{PRE\_EXEC\_MEM\_MOD}  & a memory word, pre-step           & pre  & corrupt memory before the step reads it \\
\texttt{PRE\_EXEC\_REG\_MOD}  & a register, pre-step              & pre  & corrupt a register before it is read \\
\texttt{BR\_NEG\_COND}        & branch-taken boolean              & pre  & invert a branch decision \\
\texttt{COMP\_OUT\_MOD}       & computed ALU result               & post & corrupt the value written to \texttt{rd} \\
\texttt{LOAD\_VAL\_MOD}       & loaded value                      & post & corrupt the value a load returns \\
\texttt{STORE\_OUT\_MOD}      & stored value                      & post & corrupt the value a store writes \\
\texttt{POST\_EXEC\_PC\_MOD}  & next program counter              & post & redirect the following fetch \\
\texttt{POST\_EXEC\_MEM\_MOD} & a memory word, post-step          & post & corrupt memory after the step commits \\
\texttt{POST\_EXEC\_REG\_MOD} & a register, post-step             & post & corrupt a register after write-back \\
\end{tabular}
\end{center}

This is the example we ran in Chapter 4 made literal: when Arguzz applies \texttt{PRE\_EXEC\_REG\_MOD} to the second source register of \texttt{add x3, x1, x2}, it is calling the emulator's own "store this value into this register" routine just before the instruction reads it, and the addition then proceeds on the corrupted operand.

The reason every one of these kinds is expressible is that, at the moment Arguzz injects, the emulator owns the full \textit{live} machine state and exposes it through a single narrow interface — the execution-context API used to get and set the program counter, to load and store registers, and to load and store memory, together with the in-flight instruction word and computed result. Everything in the table above is one of those quantities, or a value about to be passed into one of those calls. In short, Arguzz can perturb anything the machine is actively \textit{computing}. What it cannot perturb is anything the machine is not computing but the \textit{trace} is merely \textit{recording} — which is the subject of the next subsection. (Four of these eleven kinds — \texttt{INSTR\_WORD\_MOD}, \texttt{PRE\_EXEC\_MEM\_MOD}, \texttt{PRE\_EXEC\_PC\_MOD}, and \texttt{BR\_NEG\_COND} — are the subset we later combine with our own surface in the hybrid variant, for reasons of budget and non-overlap that we return to in Section~\ref{sec:fuzzing-architecture}.)


\subsection{What Arguzz Cannot Reach in the Preflight Trace}
\label{subsec:arguzz-cannot}

The limitation of execution-time injection is not a matter of Arguzz having simply chosen a small catalog; it is structural, and it follows directly from \textit{how} Arguzz writes. Arguzz perturbs state only through the emulator's execution-context interface — the same interface the preflight pass itself uses to \textit{build} the trace. When Arguzz forces a value into a register or memory, the preflight pass then records the \textit{consequence} of that fault by running its normal recording logic: it reads the genuine previous contents of the address to fill \texttt{prev\_word}, it advances the genuine per-address chain to fill \texttt{prev\_cycle}, it stamps the genuine read/write cycle, and it derives \texttt{major} and \texttt{minor} by decoding whatever instruction word is present. In other words, \textbf{every bookkeeping field of the recorded trace is recomputed to be consistent with the faulted value}. Arguzz can change \textit{what} the machine did, but the trace it produces is always an internally consistent record of \textit{some} execution.

This is the heart of the matter. The execution-context interface offers exactly three ways to mutate state — set the program counter, store a register, store a memory word — plus the in-flight word and result. It offers \textit{no} way to set a transaction's \texttt{prev\_word}, no way to set its \texttt{prev\_cycle}, no way to set a cycle's \texttt{major}/\texttt{minor} independently of the instruction word, no way to flip a transaction's read/write phase, and no way to set the \texttt{diff\_count} histogram. These fields simply do not exist as live variables during execution; they are synthesized by the preflight pass \textit{after} Arguzz has already written through the narrow interface. Consequently there are whole families of trace states that Arguzz can never construct, no matter how it is scheduled:

\begin{itemize}
  \item \textbf{A value decoupled from its memory history.} Arguzz cannot record a transaction whose \texttt{word} disagrees with the \texttt{prev\_word} the next access expects, because it never writes \texttt{prev\_word} — preflight always fills it consistently from the real prior contents. The temporal back-pointer \texttt{prev\_cycle} is likewise beyond reach.
  \item \textbf{An operation label decoupled from its instruction.} Arguzz can swap the instruction \textit{word} (\texttt{INSTR\_WORD\_MOD}), but the recorded \texttt{major}/\texttt{minor} are then decoded \textit{from that word} and will always agree with it. It cannot make a cycle claim to be an addition while its instruction word says it is a store.
  \item \textbf{Pure trace-encoding fields.} The read/write phase carried in \texttt{cycle}, the transaction index \texttt{txn\_idx}, the \texttt{diff\_count} histogram, the recorded privilege \texttt{machine\_mode}, and the cycle's \texttt{state} are all artifacts of how the trace is laid out, with no execution-context setter at all.
\end{itemize}

Why does this matter for finding soundness bugs? Recall the dichotomy from Chapter 4: local constraints check the internal consistency of a single step (does \texttt{rs1}+\texttt{rs2} equal \texttt{rd} for this Add?), whereas the interstep and global constraints relate a recorded value to \textit{other} recorded values — most importantly, the memory-consistency argument that ties each access to its predecessor through exactly the \texttt{prev\_word} and \texttt{prev\_cycle} back-pointers. Because Arguzz's faults are always recorded with self-consistent back-pointers, a faulted Arguzz value still satisfies "this write's value matches the next read's \texttt{prev\_word}"; the connective tissue between steps is left intact and therefore largely unexercised. This is the precise, implementation-level reason behind the bias we claimed in Chapter 4: by perturbing only what the machine computes, Arguzz concentrates its pressure on the within-step local constraints and tends to leave the interstep and global constraints — the ones a soundness bug in the memory argument would live behind — under-stressed. To reach those, a fuzzer must be able to edit the recorded bookkeeping itself.


\subsection{A4 Mutation Kinds}
\label{subsec:a4-kinds}

Our post-execution surface, which we call A4, is built to edit exactly the trace cells that Arguzz cannot. Because the \texttt{PreflightTrace} is a complete, materialized object sitting between preflight and witgen (\ref{subsec:risc0-pipeline}), a mutation reduces to overwriting one field of one element of its arrays. The mechanism is deliberately simple and runs end-to-end as follows. A mutation module first inspects a dump of the trace to choose a valid target — a particular guest step, the index of a particular transaction or cycle, and a new value — and writes this choice as a small JSON record:
$$
\texttt{A4\_MUTATION\_CONFIG} = \{\;\texttt{mutation\_type},\; \texttt{step},\; \langle\text{per-kind payload}\rangle\;\}.
$$
The path to this record is passed to the host through an environment variable. Inside the proving binary, \textit{after} the preflight pass has materialized the trace but \textit{before} witgen consumes it, RISC Zero reads the record, locates the target cycle by matching its \texttt{user\_cycle} against the requested step, and overwrites the single requested field in place — for example \texttt{trace.cycles[i].major} for an instruction-type mutation, or \texttt{trace.txns[j].word} for a value mutation. Witgen then proceeds over the edited trace exactly as if it were genuine. (Because the edited cell now disagrees with what execution actually did, the prover's internal sanity assertions would normally object; A4 suppresses these the same way Arguzz does, so the inconsistency is carried forward into the constraint system rather than trapped.) Crucially, this is a \textit{single-cell} edit: unlike a fault injected during execution, it does not propagate to neighbouring rows, which is exactly what lets it isolate one constraint relationship at a time.

A4 provides eleven live mutation kinds, which we group by the part of the trace they target.

\begin{center}
\begin{tabular}{l l l}
\textbf{Kind} & \textbf{Field overwritten} & \textbf{Constraint family stressed} \\
\hline
\texttt{INSTR\_WORD\_MOD\_FULL} & fetch txn \texttt{word} (+\texttt{prev\_word}) & instruction decode \\
\texttt{INSTR\_WORD\_MOD\_SUR}  & fetch txn \texttt{word}, one field re-encoded & instruction decode \\
\texttt{INSTR\_TYPE\_MOD}       & cycle \texttt{major}/\texttt{minor}          & opcode selection / decode \\
\hline
\texttt{COMP\_OUT\_MOD}         & register-write txn \texttt{word}             & compute-result local \\
\texttt{LOAD\_VAL\_MOD}         & register-write txn \texttt{word}             & load-result local \\
\texttt{PRE\_EXEC\_REG\_MOD}    & register read/write txn \texttt{word}        & register read-consistency \\
\hline
\texttt{STORE\_OUT\_MOD}        & memory-write txn \texttt{word}               & store-value / memory \\
\texttt{MEM\_VAL\_MOD}          & memory read/write txn \texttt{word}          & memory consistency \\
\hline
\texttt{TXN\_PREV\_WORD\_MOD}   & txn \texttt{prev\_word}                       & memory-consistency permutation \\
\texttt{TXN\_PREV\_CYCLE\_MOD}  & txn \texttt{prev\_cycle}                      & memory ordering / cycle table \\
\texttt{CYCLE\_DIFF\_COUNT\_MOD}& cycle \texttt{diff\_count}                    & cycle-table range check \\
\end{tabular}
\end{center}

The first two groups overlap conceptually with Arguzz — corrupting an instruction word or a computed value — but A4 reaches them by editing the recorded transaction rather than the live computation, so the edit is surgical and non-propagating. The genuinely new reach is the bottom group. \texttt{TXN\_PREV\_WORD\_MOD} and \texttt{TXN\_PREV\_CYCLE\_MOD} edit precisely the memory back-pointers that, as we argued in \ref{subsec:arguzz-cannot}, no execution-time fault can decouple; they let us record a transaction whose value or timing disagrees with its own memory history, which is the most direct possible probe of the memory-consistency permutation argument. \texttt{INSTR\_TYPE\_MOD} relabels a cycle's operation independently of its instruction word — making a row claim to be one instruction while its fetched word says another — which stresses the opcode-selection constraints. \texttt{CYCLE\_DIFF\_COUNT\_MOD} perturbs the histogram the memory argument range-checks. None of these states is reachable from the executor.

This raises a natural question: why is the live catalog exactly these eleven, and not more? The answer is that we initially implemented a broader set, and several of the additional kinds turned out to be \textit{inert}. That negative result is instructive in its own right, and it directly shapes which mutations we would add next; we treat both in turn before pinning down where, in the RISC Zero codebase, all of these mutations are actually applied.


\subsection{The Inert Cells: Non-Live Mutations}
\label{subsec:a4-dead}

When we first built the post-execution surface we did not yet know which recorded cells the constraint system actually \textit{depends on}, so we implemented five further metadata mutations beyond the eleven above. Each one successfully edits its target cell of the materialized trace, yet none of them changes the proof: the witness the constraints evaluate is identical with or without the edit, and the verifier's (correct) acceptance is unchanged. They are therefore \textit{not} soundness bugs — they perturb cells the circuit simply never reads. We exclude them from the campaign and keep them only as regression sentinels. Understanding precisely why each is inert is what tells us what makes a post-execution cell a \textit{meaningful} target in the first place.

The five fall into two failure modes, distinguished by the part of the trace they touch.

\begin{center}
\begin{tabular}{l l l l}
\textbf{Kind} & \textbf{Cell edited} & \textbf{What the cell records} & \textbf{Why inert} \\
\hline
\texttt{CYCLE\_MODE\_MOD}      & \texttt{cycle.machine\_mode} & the cycle's privilege bit (user vs.\ machine) & overwritten \\
\texttt{CYCLE\_PC\_MOD}        & \texttt{cycle.pc}            & the program counter recorded for the cycle    & overwritten \\
\texttt{CYCLE\_STATE\_MOD}     & \texttt{cycle.state}         & the cycle's state-machine label (\texttt{CycleState}) & overwritten \\
\texttt{TXN\_ADDR\_MOD}        & \texttt{txn.addr}            & the word address of the memory transaction    & execution-bound \\
\texttt{TXN\_CYCLE\_PHASE\_MOD}& \texttt{txn.cycle} (low bit) & the transaction's read/write phase (even read, odd write) & execution-bound \\
\end{tabular}
\end{center}

\textbf{Overwritten cells.} The three cycle-metadata fields — privilege mode, program counter, and state — are written into the witness twice. Witness generation first \textit{presets} the corresponding column from our (mutated) trace value, but then, while filling that same row, immediately \textit{overwrites} it with a value recomputed from the execution itself: the next program counter, mode, and state that the instruction actually produced. The constraints read this second, execution-derived value, so our edit is silently erased before any constraint can observe it. In effect these columns are determined by what the machine \textit{did}, not by what the trace \textit{says}, and our edited preset is merely an overwritten scratch value.

\textbf{Execution-bound cells.} The two transaction fields fail for a different reason. The bridge routine that hands a memory transaction to the circuit is \textit{called with} the address and phase the memory operation actually used during execution, and it binds the witness's address and phase columns to those execution arguments. Our edited \texttt{addr} and phase are read back only as an internal consistency check — which the prover skips when fault injection is enabled — and are never returned into the witness. (For the phase, our edit only flips the low bit of \texttt{cycle}; since the check compares the \textit{halved} value, which identifies the owning cycle, it passes regardless.) Either way the witness encodes the genuine execution and no constraint fires.

\textbf{The unifying principle.} A post-execution cell is a meaningful mutation target if and only if witness generation \textit{returns it into} the witness the constraints evaluate. The sharpest illustration is the memory transaction record itself: the single bridge that exposes a transaction returns its \texttt{word}, \texttt{prev\_word}, and \texttt{prev\_cycle}, but \textit{not} its \texttt{addr} or its phase. This is exactly why, of the five fields of one record, \texttt{TXN\_PREV\_WORD\_MOD} and \texttt{TXN\_PREV\_CYCLE\_MOD} are live (\ref{subsec:a4-kinds}) while \texttt{TXN\_ADDR\_MOD} and \texttt{TXN\_CYCLE\_PHASE\_MOD} are dead — the live/dead split is decided purely by whether the field flows into the witness, not by how important the field appears. This boundary between constraint-bearing and inert cells is the small but genuine contribution of the negative result, and it is what turns the next, unimplemented batch from a guess into a principled selection.


\subsection{Mutations Not Yet Implemented}
\label{subsec:a4-proposed}

The inert cells teach a concrete lesson: a post-execution surface should be expanded \textit{mechanism-first}, by confirming at the source level that a candidate field flows into the witness \textit{before} implementing a mutation for it. Applying that lesson, we identified four further mutations (plus two re-scopings of existing kinds) that target constraint surfaces no current kind reaches. They are not yet implemented; they are most productive on guest programs that heavily exercise big-integer arithmetic and memory paging — behaviours our current benchmark guests barely trigger — so they are deferred to a guest chosen for that purpose. We describe them because they map the natural frontier of the post-execution surface, organized by the three surfaces they open up.

\begin{center}
\begin{tabular}{l l l}
\textbf{Proposed kind} & \textbf{Cell / array targeted} & \textbf{Surface it opens} \\
\hline
\texttt{BIGINT\_BYTES\_MOD}     & \texttt{bigint\_bytes[k]} (an operand byte) & big-integer operands \\
\texttt{CYCLE\_BIGINT\_IDX\_MOD}& \texttt{cycle.bigint\_idx} (an index)        & big-integer operands (structural) \\
\texttt{CYCLE\_PAGING\_IDX\_MOD}& \texttt{cycle.paging\_idx} (an index)        & memory-paging cycles \\
\texttt{CYCLE\_TXN\_IDX\_MOD}   & \texttt{cycle.txn\_idx} (an index)           & structural index into transactions \\
\end{tabular}
\end{center}

\textbf{Big-integer operands.} RISC Zero accelerates 256-bit arithmetic with a dedicated big-integer instruction family whose operand bytes live in their own trace array, \texttt{bigint\_bytes}. \texttt{BIGINT\_BYTES\_MOD} would corrupt one of these operand bytes, which are handed directly to the big-integer witness, thereby stressing the big-integer constraint network — a family that neither the baseline nor any current kind exercises.

\textbf{Paging cycles.} The Merkle-tree memory image of Section~\ref{subsec:risc0-pipeline} is maintained on dedicated \textit{paging} cycles (page-in and page-out), which the current kinds leave almost entirely uncovered. \texttt{CYCLE\_PAGING\_IDX\_MOD} would mutate \texttt{cycle.paging\_idx}, the index a paging cycle uses to locate its paging record. This surface also revives one of the inert kinds: \texttt{CYCLE\_MODE\_MOD} is dead on ordinary instruction cycles (its privilege column is overwritten by execution, \ref{subsec:a4-dead}), but on paging cycles the privilege field \textit{is} returned to the circuit, so the very same edit becomes live there — a clean illustration that the live/dead boundary is itself cycle-class–specific. For the same reason, the live \texttt{INSTR\_TYPE\_MOD} could be re-scoped to fire on paging and ecall cycles, testing operation-dispatch on cycle classes it currently skips.

\textbf{Structural indices.} The last category is conceptually new. Rather than corrupting a \textit{value in} a trace array, \texttt{CYCLE\_TXN\_IDX\_MOD} and \texttt{CYCLE\_BIGINT\_IDX\_MOD} would corrupt an \textit{index into} a trace array — respectively which transaction a cycle is bound to (\texttt{txn\_idx}) and which slice of big-integer bytes it reads (\texttt{bigint\_idx}). The effect is qualitatively different from any value mutation: the witness would read a \textit{different but individually valid} transaction or operand for that cycle, desynchronizing the memory-permutation argument in a way that editing a single value cannot. This "mutate the pointer, not the pointee" idea is a distinct probe that only the post-execution surface makes possible, since these indices exist solely as recorded trace bookkeeping with no live-execution analogue.

Because each of these was selected by first confirming that its field flows into the witness through a named bridge routine, they are expected to be live — in contrast to the five inert kinds above — but verifying that, and pairing them with a big-integer/paging guest, is left to future work.


\subsection{Where the Mutations Are Applied}
\label{subsec:a4-hooks}

Every mutation discussed so far — live, inert, or proposed — enters the zkVM at a single point, and it is worth stating precisely where, because the choice of that point is what makes the whole surface possible.

\textbf{The execution hook.} The mutations are applied in \texttt{rv32im/src/prove/witgen/mod.rs}, the witness-generation module of the RISC Zero \texttt{rv32im} circuit. This module's job is to turn a finished execution segment into the witness columns the prover commits to; in particular it defines the routine that (i) invokes the preflight pass to materialize the \texttt{PreflightTrace} — the arrays of cycles and transactions from Section~\ref{subsec:risc0-pipeline} — and (ii) hands that trace to the column-filling witness generator. Our hook sits exactly between these two steps. Immediately after preflight returns the trace, and before any witness column is filled, the module reads the mutation request (the small JSON file named by the \texttt{A4\_MUTATION\_CONFIG} environment variable), locates the target cell by its guest step, overwrites that one field of the in-memory trace, and then lets witness generation proceed over the edited trace.

\textbf{Why this is the right point.} It is the only place in the pipeline where the trace exists as a \textit{complete, mutable} object that nothing downstream re-derives. Earlier — inside the executor — the detailed trace does not yet exist; later — once the columns are filled and the prover has committed — it is frozen into the witness. Operating here also means the mutation lives inside the prover's own process: the same binary that proves, when the environment variable is set, edits a single cell first and proves the result, with no external trace-rewriting tool. Because that edit makes the trace disagree with what execution actually did, the prover's internal consistency assertions would ordinarily abort the run; a fault-injection flag, set automatically alongside the mutation, suppresses exactly those aborts so that the inconsistency flows into the witness and on into the constraint system rather than being trapped early. This single-cell, single-pass, between-passes design is precisely what gives A4 its two defining properties from Sections~\ref{subsec:arguzz-cannot}--\ref{subsec:a4-kinds}: the edit does not propagate, and it can reach recorded bookkeeping fields that have no analogue in live execution.

\textbf{Reading the constraint system's response.} Applying mutations is only half of our instrumentation; the other half is observing how the constraint system reacts, which we extract by hooking two further files in the proving kernel (\texttt{rv32im-sys/kernels/cxx/}). \textit{Local} constraint failures are captured in \texttt{witgen.h}: every row-wise constraint is discharged through a single equality-to-zero routine, and we instrument that one chokepoint so that whenever a constraint evaluates non-zero it emits a \texttt{<constraint\_fail>} record tagging the violated constraint's location together with the cycle's $(\texttt{step}, \texttt{pc}, \texttt{major}, \texttt{minor})$ — exactly the failure context $\gamma$ of Chapter~4 — and, in a "continue" mode, keeps going so that one run reports \textit{all} of its failures rather than aborting at the first. \textit{Global} constraint failures are captured in \texttt{ffi.cpp}, the C++ entry point that drives witness generation and the accumulation phase; here we add the residue computation of Chapter~4, which, once the trace is assembled, evaluates the per-family logarithmic-derivative residue and, for any non-zero family, emits the offending broken addresses and indices. Both files sit in the same kernel directory as the prover's generated constraint code, so the values they report are exactly those the real verifier would compute.

With both the learning mechanism of Chapter 4 and this post-execution mutation surface now in place, we have the two ingredients our architecture combines. The next section defines the oracle that decides when a surviving, accepted proof of a mutated trace constitutes a genuine soundness-bug candidate.


% ---------------------------------------------------------------------
% CITATIONS (for your appendix / footnotes — not prose)
%
% Pipeline / preflight:
%   Executor pass + Segment: rv32im/src/execute/executor.rs (run @210; segments
%     @128-179; segment_threshold @217-219; MAX_INSN_CYCLES ~25k).
%   Segment struct: rv32im/src/execute/segment.rs:29-58.
%   Preflight pass: rv32im/src/prove/witgen/preflight.rs (Segment::preflight @95;
%     body @175-189; txn record @566-628; wrap/back-pointers @216-236;
%     table_split @211).
%   Structs: rv32im-sys/src/lib.rs:20-49 (RawMemoryTransaction, RawPreflightCycle);
%     C++ mirror kernels/cxx/preflight.h:21-41.
%   major/minor families: rv32im/src/execute/platform.rs:149-163; InsnKind table
%     rv32im.rs:397-455; major()/minor() preflight.rs:698-706.
%   Registers memory-mapped: platform.rs:34-35 (USER_REGS_ADDR 0xffff_0080,
%     MACHINE_REGS_ADDR 0xffff_0000); store_register -> store_u32 r0vm.rs:699-720.
%   Parallel witgen consumes trace: prove/hal/cpu.rs:76-86; ffi.cpp:380-447.
%
% Arguzz injection:
%   RV32IMFaultInjectionContext: rv32im.rs:28-35, embedded @348-355; trigger
%     predicate is_injection @152-156; (step,kind,seed) via fuzzer_utils + host
%     main.rs:15-90; value generators rv32im.rs:167-286.
%   Hooks: PRE_*  @598-640; INSTR_WORD_MOD @650-667; POST_* @675-718; BR_NEG_COND
%     @756-770; COMP_OUT_MOD @873-885; LOAD_VAL_MOD @942-954; STORE_OUT_MOD
%     @1005-1017. Guards disabled under injection @592,644,869,903,...
%   EmuContext trait (only set_pc/store_register/store_memory/...): rv32im.rs:304-346.
%   Kind catalog + 4 selected: a4/standalone/mutations/arguzz_bridge.py:48-81.
%
% A4 injection + catalog:
%   Config launch: a4/core/executor.py:187-215 (A4_MUTATION_CONFIG env var,
%     FAULT_INJECTION suppression, CONSTRAINT_CONTINUE).
%   Rust in-place edit: rv32im/src/prove/witgen/mod.rs:275-944 (INSTR_TYPE_MOD
%     @318-344 edits cycle.major/minor; INSTR_WORD_MOD @345+ edits txn.word &
%     prev_word; COMP/LOAD/STORE/MEM/PRE_EXEC_REG edit txn.word; TXN_PREV_WORD
%     @646-702; TXN_PREV_CYCLE @703-740; CYCLE_DIFF_COUNT @901-931).
%   Live set (11): a4/standalone/fuzzer.py:281-293.
%
% Non-live (dead) kinds — exact fields + death mechanism:
%   Registry/exclusion + rationale: fuzzer.py:259-293.
%   W-17 (overwrite) CYCLE_MODE/PC/STATE_MOD: handlers witgen/mod.rs:749-750,
%     857-858, 883-884; preset set_cycle @mod.rs:1235-1240; overwritten by
%     step_Top exec_Reg(inst_result.new_*) @steps.cpp:14751-14757; DSL bindings
%     top.zir:90-92. (CYCLE_MODE_MOD live on PAGING cycles via
%     extern_nextPagingIdx ffi.cpp:327-331 — campaign targets user cycles only.)
%   W-18 (execution-bound) TXN_ADDR_MOD / TXN_CYCLE_PHASE_MOD: handlers
%     witgen/mod.rs:782-783, 819-821; extern_getMemoryTxn returns
%     {prevCycle,prevWord,word} NOT addr/cycle @ffi.cpp:217-223; addr/cycle read
%     only as FIE-suppressible sanity checks @ffi.cpp:186,199-215; witness bound
%     to execution arg @mem.zir:70,73 (memCycle = 2*cycle[+1]).
%   Pro-facing summary + "same extern, 4 fields, 2 live 2 dead":
%     IV_POS_8_D2_B_MECHANISM_REPORT.md:360-371; audits D2B_BATCH2_DEAD_ARM_AUDIT.md
%     (W-17), D2B_BATCH3_TXN_DEAD_ARM_AUDIT.md (W-18).
%
% Proposed (not-yet-implemented) kinds — SOURCE: ProG_Report_4 §Q5
%   pro_checkin_attachments/ProG_Report_4.md:49,319-340,530-533 (the 6-item list:
%     BIGINT_BYTES_MOD, CYCLE_PAGING_IDX_MOD, CYCLE_TXN_IDX_MOD, CYCLE_BIGINT_IDX_MOD,
%     + CYCLE_MODE_MOD-on-paging, INSTR_TYPE_MOD-on-paging/ecall).
%   Per-field/extern/witness-path grounding: IV_POS_8_D2_B_MECHANISM_REPORT.md:505-537.
%   NOTE: ProG_Report_5.md proposes NO new trace mutations (guests/scheduler/reward
%     only); it reinforces by proposing a bigint/paging guest (cloud3/ProG_Report_5.md
%     :45,90-102) that would activate these kinds. New_Master.md:42,118 defers them
%     to IV.POS.9 (future IV_POS_9_A4_BATCH_SPEC.md, not yet on disk).
%
% Hook for executing mutations:
%   witgen/mod.rs PreflightResults::new @119-123 (segment.preflight materializes
%     trace), A4 block @128-944 edits trace in place before WitnessGenerator @989.
% Hooks for constraint info:
%   LOCAL: witgen.h eqz() @184-206 emits <constraint_fail>{step,pc,major,minor,loc,...};
%     CONSTRAINT_CONTINUE @198; a4_touch_mark (touch bitmap) @185; EQZ macro @217.
%   GLOBAL: ffi.cpp accum/Hook-3 family residue -> <a4_family_residue> (per-family
%     LogUp residue + broken addrs/indices); both files in rv32im-sys/kernels/cxx/.
% ---------------------------------------------------------------------

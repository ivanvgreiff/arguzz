\chapter{Introduction}
\label{chap:introduction}


The modern era requires systems to manage tradeoffs between processing increasingly larger amounts of data with increasingly faster speeds. As these two goals lie in direct opposition with each other, innovative approaches are required to find ways of improving both simultaneously, both in centralized and distributed systems. Zero Knowledge Virtual Machines (zkVMs) are a recent innovation which have unlocked the ability for interconnected distributed components to perform a computation once and provide the results together with a verifiable proof of computation to all other participating components in the system. This proof saves all other participants from having to re-execute the same computation while also providing assurance that the computation performed by the original party was done correctly. 

The efficiency which these proofs provide has been especially impactful in blockchain systems, where transaction blocks or smart contract executions can be validated without requiring every node to re-compute the same sequence of operations [1]. zkVMs have been the sole technology responsible for automating the generation of these proofs in realtime as these systems continuously receive new data that requires validation, thereby removing the need for manual translation of the underlying program logic into a proof (which takes the form of an arithmetic circuit). Rather than requiring a person to construct each unique arithmetic circuit by hand, these virtual machines can instead take any Rust/C++ program, execute it on the inputs provided, and generate a proof for this program's computations in a matter of seconds. The programmability of this translation process has not only made proving and verifying untrusted computations possible for blockchain systems, but also for identity, voting, authentication, and storage systems [1]. 

A second property which has made zkVMs invaluable to these different use-cases is the "zero knowledge" property. Zero Knowledge Proofs (ZKPs) are a type of proof which ensures that any sensitive data processed during the computation stays private. For example, if hospitals need to collaborate on machine learning (ML) model training without exposing patient-level data, ZKPs allow participants to prove that a computation (such as aggregation of locally trained model updates) was performed correctly without revealing the underlying updates which encode patient data [2]. From validating financial transactions to securing sensitive medical data, zkVMs are increasingly used to handle computations of critical importance for modern systems, where the consequences of failure can be disastrous.

\section{Classification of Failures}
\label{sec:classification-of-failures}

In 2018, Ariel Gabizon, a cryptographer at Zcash [3], discovered a vulnerability (CVE-2019-7167) that would have allowed a malicious prover to transform an honest proof for one statement into a proof that looked valid for another statement, thereby bypassing a consistency check and breaking the soundness of the proof system. Zcash uses ZKPs to establish the validity of transactions on their blockchain, and a forged proof using this vulnerability would have allowed counterfeit coins to be created without detection [4], were this vulnerability not first discovered by one of their employees. 

zkVMs can encounter two different classifications of bugs, namely soundness and completeness bugs. A soundness bug exists when an invalid proof is accepted by the verifier. Zcash's counterfeiting vulnerability demonstrates this issue exactly, where a cheating validator could have created a proof of fake transactions accepted by the verification system and thus accepted into the blockchain. This soundness error specifically comes from an underconstraint in the ZKP's arithmetic circuit, where can modify some intermediary computation or variable in a way that is not constrained by the circuit, leading to the ZKP attesting to a different computation/statement than the one originally intended. This would then be accepted by the verification process and incorrectly used by the overarching system. 

The second kind of bug which can exist is a completeness bug, which is when a valid proof is incorrectly rejected by the verifier. In 2024, Li et al. discovered an error in Polygon's zkRollup arithmetic circuit construction process where a perfectly valid operation remained unsatisfiable by the circuit [5]. This meant that the ZKP's constraint system accepted only a strict subset of valid executions, leading to valid transactions to be unprovable and unusable in Polygon's blockchain ledger. Rather than coming from an underconstraint in the ZKP's arithmetic circuit, a completeness bug instead comes from an overconstraint, where perfectly valid computations/statements become unusable by the overarching system.

These two classifications of bugs, soundness and completeness, demonstrate the most important responsibility zkVMs bear is that of perfectly constraining the underlying computation/statement during its translation into a unique and correct arithmetic circuit. Given that ZKP constructions are increasingly being automated by zkVMs, proof construction and security is increasingly becoming a question of zkVM implementation security. Thus, in order to reliably ensure the robustness and security of a wide variety of modern and future distributed systems, we must find ways of discovering and removing soundness and completeness bugs from current and future zkVM implementations.


\section{Motivation}
\label{sec:motivation}

With the goal of finding soundness and completeness bugs in ZKPs, Researchers have devised a different techniques ranging from static analysis, formal verification, algebraic constraint checking, and fuzzing. Static analysis involves inspecting a circuit language or constraint system before proof generation to look for patterns that indicate missing or inconsistent constraints (typically searching for unconstrained variables or missing checks). Formal verification is stronger but more expensive, where instead of just looking for suspicious patterns, one instead defines a formal specification of what the circuit should compute and then proves that the constraints enforce exactly that behavior. Algebraic constraint checkers work directly at the mathematical level, where instead of analyzing the source language, they treat the circuit as a system of polynomial equations over a finite field. Here, if the circuit constraints define a set of satisfying witnesses that do not match the set of valid witnesses defined by the intended computation, then an over/under-constraint must exist. Finally, fuzzing involves repeatedly executing the circuit over a wide variety of mutated inputs and mutations of the circuit itself to see if the underlying computation logic and constraint system ever incorrectly match. 

Although the above techniques have proven capable of discovering soundness and completeness bugs in ZK circuits, the majority suffer from issues preventing their adoption for bug discovery in zkVMs. Static analysis approximates behavior, often warning about code that is actually safe or missing bugs that only appear through tested executions, leading to a high false positive rate [6]. Formal tools already struggle with real-world circuit scale, and it is unclear whether it would be possible to formally verify an end-to-end ZKP creation process within a zkVM. Similarly, applying algebraic constraint checking would require exacting and solving a very large mathematical representation of the VM's semantics, as algebraic checkers are evaluated only within solver-tractable ranges. 

Fuzzing remains as the natural complementary direction for zkVM bug discovery, where instead of attempting to prove or solve an enormous system, fuzzing just searches for concrete counterexamples by repeatedly executing/mutating programs, inputs, or internal VM artifacts and searching for violations against the expected behavior. 


\section{Research Questions}
\label{sec:research-questions}

Most research in soundness/completeness bug discovery as been applied to ZK circuits and circuit processing pipelines [7]. However for zkVMs, bugs not only arise within constraint systems, but also in the VM's execution logic, leaving these machines with a larger surface area for failure. The most direct prior work attempting to stress-test this larger surface area for bugs is Arguzz [8] which uses mutated inputs and fault injections against zkVMs. However, this work only explores a portion of the total zkVM proving pipeline, and uses a mutation scheduler that randomly samples decisions without any feedback as to their impacts. 

As a result, our work expands upon these limitations by exploring different areas of attack within the zkVM proving pipeline and investigates if mutation-aware feedback can deliver a more efficient fuzzing strategy. In pursuit of this goal, our work focuses on answering these three research questions:

\begin{enumerate}
    \item \textbf{RQ 1 } What would be effective mutation strategies for fuzzing zkVMs?
    \item \textbf{RQ 2 } What zkVM internal information can we use, and how can we use it to increase coverage/effectiveness of our fuzzing approach
    \item \textbf{RQ 3 } How and to what level can we build a zkVM-agnostic framework that still provides zkVM-specific efficacy in fuzzing?
\end{enumerate}







\chapter{Background}
\label{chap:background}

Before defining ZKPs, we first formalize the notion of a mathematical statement and its truth. In cryptography, finite mathematical objects are often encoded as finite binary strings, so let us model a given public \textit{statement} as $x \in \{  0,1 \}^{*}$ where the star means all finite binary strings, and let us define a \textit{language} as a subset $L \subseteq \{  0,1 \}^{*}$ of all possible binary strings, where $L$ contains exactly those encoded statements that are considered true. The specific statement is therefore true exactly when $x \in L$. Let us further define a decision function $T_{L}(x)$ (also known as a predicate) whose purpose is to turn the set-membership statement $x \in L$ into a Boolean function $$
T_{L}(x)=\begin{cases}
1 & \text{if } x \in  L \\
0 & \text{if }x \not\in L
\end{cases}
$$A proof system formalizes how one party can convince another party that a statement belongs to such a language. In its simplest form, a proof system consists of a prover which produces a proof object $\pi$, and a verifier $V(x,\pi)$ which checks whether the proof object is sufficient evidence for the truth of the statement $V(x,\pi)\overset{?}{=}T_{L}(x)$. 

\section{Example: Proof-of-Knowledge}
\label{sec:proof-of-knowledge}

As discussed in the Introduction chapter, the purpose of such a proof system demonstrates value in distributed computational settings. Suppose one component in a distributed system performs a computation and claims the output is correct, then instead of requiring every other component to repeat the entire computation to attain the desired output, the computing component can provide a proof  so that the other components need only run a significantly cheaper verifier  to forgo recomputing the original task. 

Suppose a component within a distributed system needs to find the factors of any given large integer. In this case, our language of consideration $L$ would be the set of all composite integers. If a connected node is provided the statement "$x=15$ is composite" then the attached proof for this statement would be $\pi=(3,5)$. The verifier would then check whether $3 \times 5=15$ and whether both factors are non-trivial, namely $1<3<15$ and $1<5<15$. If these arithmetic constraints are fulfilled, then the verifier accepts by executing a set of checks $\mathcal{O}(n^{2})$ which is easier to verify than finding a factorization from scratch $\mathcal{O}(2^{n/2}\text{poly}(n))$. However, this proof also reveals the entire underlying data as to the reason why the statement is true i.e. it reveals the factors $3$ and $5$.

\section{Zero Knowledge Proofs}
\label{sec:zero-knowledge-Proofs}

For zero knowledge proofs, however, we go one step richer. We model not only whether a statement is true, but also model private data as to \textit{why} its true. Therefore, the more useful object is not just a truth predicate $T_{L}(x)$, but a \textit{relation} $R$ involving both the public statement $x$ and some private data $w\in \{ 0,1 \}^{*}$ (also known as a witness) which serves as necessary to explain why the relation holds. $$
R(x,w)=\begin{cases}
1 & \text{if }w \text{ certifies that }x \text{ is true} \\
0 & \text{otherwise}
\end{cases}
$$The corresponding language is $$
L_{R}=\{ x \,|\,\exists\,w \,\text{ s.t. }\, R(x,w)=1 \}
$$
A ZKP system for a relation $R$ can therefore be modeled as a protocol between a prover $P$ (which receives the public statement $x$ and a private witness $w$) and a verifier $V$ (which receives only the public statement $x$). At the end of the protocol, the verifier outputs either accept or reject: $$
\langle P(x,w),\,V(x) \rangle\in \{ 0,1 \}  
$$This protocol should satisfy three properties.

First, it should be \textbf{complete}. If the prover knows a valid witness, then the verifier should accept: $$
R(x,w)=1 \implies \mathbb{P}\big( \langle P(x,w),\,V(x) \rangle=1 \big) \approx 1
$$Second, it should be \textbf{sound}. If the statement $\bar{x}$ is false, then no valid witness $\bar{w}$ should exist, meaning no dishonest prover should be able to convince the verifier except with negligible probability: $$
x \not\in L_{R} \implies \mathbb{P}\big( \langle P(\bar{x},\bar{w}),\,V(\bar{x}) \rangle =1 \big) \approx 0
$$If a prover can convince the verifier, then the prover must know a valid witness $w$. 

Third, it should be \textbf{zero knowledge} (ZK), meaning the verifier should learn nothing beyond the fact that the statement is true. The factorization example above does not give zero-knowledge, because the proof reveals all of the underlying data. To see how a proof can convince the verifier without revealing the witness, we next consider a standard ZK proof of knowledge based on graph colorings [9].

\section{Example: Zero Knowledge Proof}
\label{zero-knowledge-proof-example}

Let $\mathcal{G}=(\mathcal{V},\mathcal{E})$ be a graph, where $\mathcal{V}$ is a set of vertices and $\mathcal{E}$ is a set of edges. The public statement $x=$ "$\mathcal{G}$ is 3-colorable" means that each vertex of $\mathcal{G}$ can be assigned one of three colors such that no two connected vertices have the same color. The private witness is a valid coloring $w=\varphi:\mathcal{V} \to \{ 1,2,3 \}$, and the relation checks whether the coloring is valid: $$
R(x,\varphi)=1 \iff \varphi(u)\ne \varphi(v)
$$$\forall$ edges $(u,v)\in \mathcal{E}$. 

In an ordinary proof, the prover could simply reveal the full coloring $\varphi$ and the verifier could then check every edge and accept if all connected vertices have different colors. However, this reveals the entire witness. A ZKP should instead convince the verifier that such a coloring exists without revealing the coloring itself. 

The ZKP protocol begins with the prover randomly renaming the three colors i.e. red, blue, and green are randomly renamed via a permutation of the set $\{ 1,2,3 \}$. This is done to preserve the privacy of the true underlying coloring of the graph, while also preserving the fact that adjacent vertices have different colors. The prover then commits to the color of every vertex using e.g. some hash function using fresh randomness. Since hash functions are designed to yield outputs which are (almost) random and unique, this commitment (hash) serves to prevent the prover from deceiving the verifier by later changing its stated knowledge of the coloring in an attempt to satisfy the subsequent acceptance criteria. The protocol is specifically set up so that the prover commits to all vertex colors before knowing which part of the graph the verifier will inspect

After receiving the commitments, the verifier chooses one random edge $(u,v)\in \mathcal{E}$ and asks the prover to open (i.e. reveal the inputs to) only the commitments for the two endpoints $u$ and $v$. If these two checks pass, then the verifier repeats the entire process again until enough rounds have surpassed to achieve negligible "lucky guessing" probability. 

This protocol is \textbf{complete} because an honest prover who knows a valid coloring can always answer the verifier's challenge, as every edge in a valid 3-coloring has endpoints with different colors. It is additionally \textbf{sound} because the prover must commit to the coloring before seeing the verifier's random edge. If the prover does not know a valid coloring, then the pre-committed coloring must contain at least one incorrectly colored edge whose endpoints have the same color. Since the verifier chooses these edges randomly, then for a graph with $m$ edges, a cheating prover is caught in a single round with probability $\ge \frac{1}{m}$. After $k$ independent rounds, the probability of cheating successfully is at most $$
\left( 1- \frac{1}{m} \right)^{k}
$$By repeating the protocol enough times, the verifier can make the probability of accepting a false claim negligibly small. 

The protocol is also \textbf{zero knowledge}, because the verifier never sees the full coloring. In each round, the verifier sees only the colors of two connected vertices, and those colors are randomly renamed before every round. In addition to seeing just that one edge has two different colors, the protocol only reveals that each inspected edge is locally valid and does not reveal how the entire graph is colored. 

\section{Fiat-Shamir Transform}
\label{sec:fiat-shamir}

In the above example, the proof $\pi$ is the transcript of the repeated interaction, containing: the commitments, the verifier's random edge challenges, and the openings of the challenged endpoints. This highlights an important limitation of the protocol as described so far, namely the required sustained interaction between a proving and verifying entity. The prover cannot produce $\pi$ alone, because part of $\pi$ depends on random challenges chosen and communicated by the verifier during the protocol. If a proof is to be stored, verified by many parties, or checked long after it was produced, then it unreasonable to require a live verifier to participate in the proof generation process. Therefore, what is needed is a non-interactive proof, i.e. a standalone object $\pi$ that can be generated once by the prover and later verified by anyone using only the public statement $x$. 

The Fiat-Shamir transform provides a way of removing this interaction for challenge-response protocols, where instead of asking the verifier to choose a random challenge, the prover derives the challenge itself by hashing the public statement and the prover's previous message. $$
\text{challenge} = H(x,\,\text{commitment})
$$where $H$ is modeled as a random oracle via a cryptographic hash function. The crucial point is that the prover can compute the challenge, but cannot freely choose it. Once the commitments are fixed, the hash output is modeled as unpredictable and outside the prover's control. The prover also cannot wait for the challenge and then change the committed values, because the commitments are binding. Therefore, for any fixed commitment, the prover is in the same position as in the interactive protocol where it must answer a challenge that it did not control.

At first glance, this may appear weaker than the interactive protocol. In the non-interactive version, the prover works offline and may discard failed attempts without anyone seeing them. Thus, a dishonest prover can try many different commitments until the hash-derived challenge happens to be favorable. Fiat-Shamir does not prevent this type of offline brute-force. Instead, the security parameters make brute-force attack infeasible. For a protocol with the necessary parameters to make this attack successful with negligible probability, any prover thus can be reliably left to generate the full transcript alone: $$
\pi= (\text{commitment}, \,\text{challenge},\,\text{response})
$$The verifier needs only to then recompute the challenge from the public data and check that it matches the transcript by the proof $\pi$. $$
\text{challenge}\overset{?}{=}H(x,\,\text{commitment})
$$In the graph-coloring example, this means that the verifier no longer needs to choose a random edge interactively. Instead, the prover first commits to the randomly permuted coloring of the graph, and the edge-challenge is then derived by hashing the public graph and commitments. Specifically, the hash output comes from selecting an edge $(u,v)\in \mathcal{E}$ where then the prover opens only the commitments for the two selected endpoints. The proof $\pi$ now contains the commitments and the openings for the hash-selected edge. The offline verifier later recomputes the same edge-challenge from the hash, checks that the prover opened the correct commitments, and verifies that the two revealed endpoint colors are indeed different.

This procedure preserves soundness because the prover cannot adapt its response to a challenge of its own choosing. The prover may grind over many commitments, but each commitment induces only a fresh random challenge through the hash. Therefore, the non-interactive proof remains sound as long as the challenge space is large enough to make repeated brute-force attempts to match the challenge infeasible.

This procedure additionally preserves zero knowledge because this non-interactive proof reveals the same type of information as the interactive transcript. As before, the verifier sees randomly permuted local colors each round, learning only that the opened edge is locally valid and never learning the global coloring of the graph.

As a result, the Fiat-Shamir transform only changes how the challenge is generated, without changing the basic logic of the proof. It replaces verifier-generated challenges with hash-generated challenges, thereby turning the interactive transcript into a standalone proof object, allowing for the missing flexibility ZKPs require for use in real-world distributed systems. 

\section{zkVM Architecture}
\label{sec:zkvm-architecture}

A zkVM is a system architecture automated for producing ZKPs for computer programs. It provides a virtual machine whose executions can be proven, so that developers can write programs, run it inside the zkVM, and obtain a proof that the program was executed correctly on some input to achieve some output. Rather than needing to design a separate proof system for each individual computation, zkVMs tie every piece of the underlying arithmetic circuit down to each and every instruction-level memory and execution event which occurs within the virtual machine on some host computer. At a high level, a zkVM therefore proves the following claim: 

\begin{center}
    \textit{There exists an execution trace and private input data such that running the guest program under the zkVM rules produces the stated public values.}
\end{center}


As a result, our mathematical ZK tools of analysis now take on more specific meanings: 
\begin{itemize}
    \item Our statement $x$ turns from "any simple mathematical claim" into a claim stating that a given guest program was executed according to the rules of the virtual machine, using some input to produce the claimed public output
    \item Our private witness $w$ becomes the detailed execution data explaining why $x$ is true, including: sequences of machine states, memory accesses, register updates, and auxiliary variables generated during execution. 
    \item Our relation $R$ becomes the set of rules that determine whether the witness is valid by checking that the execution starts from the correct initial state, follows the instruction semantics of the virtual machine at every step, handles memory consistently, and ends with the claimed output
\end{itemize}

The execution, proof, and verification procedure of a zkVM can be generalized into the following abstract architecture:

\begin{figure}[h]
    \includegraphics[width=1.02\textwidth]{tumbeamer/pics/zkvm abstract architecture.png}
    \label{fig:abstract-architecture}
\end{figure}

\textbf{Guest Program and Inputs}

The architecture begins by taking in a guest program in the form of a compiled Executable and Linkable File (ELF), together with a set of inputs for the program to run on (normally in JavaScript Object Notation). Depending on the application, some of this data may be public and some may remain private.

\textbf{Executor}

The first internal component is the executor, whose role is to run the guest program inside the virtual machine and record the step-by-step computation history from which the proof will later be derived. It records behaviors such as which computer instructions were executed, how/what registers changed, how/what memory was accessed, and what public values (pv) were produced. The history of these execution and memory events are assembled first as a raw trace.

\textbf{Witness Builder}

The witness builder then converts this raw trace into the structured witness $w$ required by the proof system. It organizes the execution and memory data into a format appropriate for algebraic checking, often structuring events into blocks and deriving flags which can be used to later easily establish "$=0$" arithmetic constraints for the subsequent module. Conceptually, the witness builder translates "the program ran this way" into "here are the values that should satisfy the VM's constraints." The witness therefore contains the private execution data needed to certify the statement, while the public values remain available to the verifier.

\textbf{Polynomial \& Commitment Builder}

The polynomial and commitment builder then transforms the execution witness into algebraic objects. zkVMs do not ask the verifier to inspect every execution step, and instead improve efficiency by encoding the entire witness into polynomials, and commits to these polynomials so as to bind itself to the claimed execution data without revealing all of it. Some zkVMs (such as RISC Zero) induce the ZK effect at this point in the process by adding randomness into the polynomials before commitment at this step in the process, while others do so towards the end of the proving pipeline [10]. 

\textbf{Transcript \& Challenge Generator}

The transcript and challenge generator implements the Fiat-Shamir transform, where instead of relying on an interactive verifier to issue random challenges, the zkVM derives challenges by hashing the public values and its commitments. As discussed in the previous section, since the proof is non-interactive, the prover still cannot choose the challenges freely, because once the commitments are fixed, the hash-derived challenges are determined. The challenges then specify which polynomial evaluations and openings the prover must provide.

\textbf{Proof Assembler}

The proof assembler collects all required proof components into a single proof structure. This includes the polynomial commitments, the Fiat-Shamir challenges, the claimed polynomial evaluations, the openings (i.e. inputs into the polynomial evaluations), and the public values needed by the verifier. At this point, the proof has the same conceptual role as $\pi$ in the earlier sections by serving as the object which convinces the verifier that a valid witness exists.

\textbf{Proof Serializer}

The proof serializer converts this internal proof structure into proof bytes. This is the portable representation of the proof which can be stored, transmitted, and verified later by any party that has access to the verifier and the public statement.

\textbf{Verifier}

Finally, the verifier evaluates internal consistency of the proof $\pi$ by checking that the Fiat-Shamir challenges were derived correctly, that the polynomial openings are valid, and that the encoded execution satisfies the virtual machine constraints. If these checks pass, the verifier accepts the claim that the program was executed correctly and produced the stated public values.

Overall, this procedure realizes the abstract zero-knowledge proof framework in a real computational setting. The statement is a claim about program execution, the witness is the execution trace and (depending on the program) a portion of the inputs meant to remain private, the relation is the VM’s validity constraints, and the proof is a non-interactive certificate of correct execution.


\chapter{Analysis}
\label{chap:analysis}

zkVMs inherit the correctness requirements of ZKP systems while also introducing the implementation complexity of a virtual machine. While the previous chapter introduced the general zkVM pipeline from guest program execution through proof verification, we now focus specifically on why zkVMs are difficult to debug, what prior work exists for this, and how these consequences motivate our approach. 

\section{Issues Facing zkVMs}
\label{sec:issues-facing-zkvms}

Traditional ZK circuit security is already difficult because its various constraints must match the intended underlying program/computation/statements exactly. Underconstraints in the translated arithmetic circuit can lead to invalid witnesses being accepted, while overconstraints lead to valid executions being unprovable. In a zkVM, this problem expands from a single circuit to an entire general-purpose execution environment. As discussed in Chapter 2, this system must correctly constrain instruction semantics, register updates, memory accesses, control-flow behavior, trace construction, proof generation, and verification. This larger surface area for attack exposes zkVMs to soundness and completeness bugs during the entire process in which these machines prove that an execution trace is consistent with the semantics of the virtual CPU architecture implemented by the zkVM. Furthermore, improper constraints related to edge-case instructions, addresses, or other uncommonly exercised VM behaviors may only arise as failures for only a narrow class of programs and inputs. 

A further difficulty in testing zkVMs lies with oracles. For ordinary programs, a fuzzer can detect crashes, assertion failures, or output mismatches, yet for a zkVM, this remains insufficient as it does not address the correctness of the attached proof. Executing a guest program and producing the expected output does not mean that the verifier would reject all maliciously modified executions. Soundness bugs typically manifest within proofs for which the associated outputs remain correct for the given inputs and guest program (as otherwise the verifier would trivially reject the proof due to the mismatch in expected public values). Conversely, a failed proof does not immediately reveal whether the cause is an invalid guest program, witness generation bug, overconstraint, or other backend issue. 

Finally, fuzzing zkVMs is expensive, as (depending on which component of the pipelines the fuzzer is targeting) each test requires compiling a guest program, executing it in the VM, constructing a witness, generating a proof, and verifying it. Since proof generation dominates runtime, naive fuzzing strategies can waste large amounts of time on tests that exercise the same paths and constraints repeatedly. The challenge here is therefore not to only generate and run many tests, but to figure out ways to stress test semantically meaningful parts and edge-case behaviors of the zkVM pipeline. 

\section{Related Work}
\label{sec:related-work}

Direct academic work on automated bug finding in zkVMs is still limited, with the most relevant prior work being \emph{Arguzz}, introduced by Hochrainer, Wüstholz, and Christakis and presents an automated fuzzing approach for discovering soundness and completeness bugs in zkVMs. It evaluated six real-world RISC-V based zkVMs: RISC Zero, Nexus, Jolt, SP1, OpenVM, and Pico where it found eleven previously unknown bugs (including three soundness bugs and eight completeness bugs) in three different zkVMs. These systems have undergone multiple audits, with the world's first production-ready zkVM (RISC Zero 1.0) having been commercially deployed in June 2024 [11], and for which a critical soundness bug was found by Arguzz and awarded a \$50,000 bounty [8].

The key methodological contribution of Arguzz is its combination of metamorphic testing and fault injection. Metamorphic testing focuses on discovering bugs in the executor by generating semantically equivalent programs whose outputs are designed to agree. Fault injection instead focuses on discovering bugs within the proving process by simulating a malicious prover and testing whether the verifier accepts a proof that has been deliberately corrupted. These two techniques focus on two different modules shown within our abstract zkVM architecture (c.f. Fig. ?). Metamorphic testing works inside the \textbf{Guest ELF + Input JSON} module by mutating only inputs and guest programs, while fault injection works inside the \textbf{Executor} module by injecting faults into the \texttt{RawTrace} object as it is being constructed by the executor. 

For the purposes of this thesis, Arguzz establishes the closest baseline. It shows that fuzzing can find real zkVM soundness bugs via fault injection, and both soundness and completeness bugs via metamorphic programs while also serving as a useful oracle. At the same time, Arguzz leaves several open questions about how to broaden the attack surface and how to guide mutations using feedback from the zkVM proving process. These questions motivate the our approach, which we introduce in Section ?. 

\section{Deeper Dive Into Arguzz}
\label{sec:deeper-dive}

In order to properly motivate our approach and to addresses how we expand upon the limitations of Arguzz, we first need to dive deeper into its fuzzing architecture. Arguzz  is a pipeline with the following seven main stages:

\begin{figure}[h]
    \includegraphics[width=1\textwidth]{tumbeamer/pics/arguzz.png}
    \label{fig:abstract-architecture}
\end{figure}


\subsection{Metamorphic Testing}
\label{subsec:metamorphic-testing}

As discussed earlier, metamorphic testing exists inside the \textbf{Guest ELF + Input JSON} module of our abstract zkVM architectural diagram (c.f. Fig. ?). This means that only the guest program and inputs are instrumented, not the zkVM itself. Arguzz begins instrumenting these by generating a random computation in CircIL (an intermediate circuit language where it is easier to apply semantics-preserving transformations). To gather enough diversity, these programs utilize various arithmetic and control-flow structures, together with custom functions to emit inline RISC-V assembly. The authors argue that "this enables our circuit generator to use all instructions supported by the target VMs ... since CircIL does not support the full instruction set ... this ensures that even low-level or uncommon operations are exercised during testing." These initial sets of programs undergo various transformations designed to produce syntactically different computations that evaluate to the same result via simple rewrites such as e.g. commutativity $a+b \rightarrow  b + a$, associativity $(a+b)+c \rightarrow a+(b+c)$, and distributivity $a(b+c)\rightarrow ab+bc$. Arguzz then merges equivalent Rust functions into a single "product program," which executes each function internally and returns a fixed success value if their outputs match, and a special failure output if they differ. 

The product program has the advantage of encoding the oracle inside the guest program itself. Since the expected output is known in advance, the program should return the success value unless the zkVM exhibits inconsistent behavior. The authors also argue a second benefit, which is that it improves efficiency as running one combined program is cheaper than proving several separate executions, especially when proof-generation overheads dominate runtime. However, it is not necessary to run the entire proof-generation procedure when only doing metamorphic testing without fault injection, as many zkVMs allow you to execute guest programs without creating the additional proof. The authors do in fact run metamorphic tests without fault injection, but do not specify if they only use the executor, but instead explicitly state they only omit step 7 from Fig. (?). 

This metamorphic testing approach is well suited for discovering completeness bugs due to its focus on searching for divergences in outputs from semantically equivalent programs. However, this approach alone does not search for cases where programs are incorrectly executed for the purposes of deceiving the verifier. In order for their framework to also detect soundness bugs, the authors additionally design a fault injection mechanism.

\subsection{Fault Injection}
\label{subsec:fault-injection}

The verifier of a zkVM should reject invalid proofs even if the prover deliberately constructs an invalid execution trace. Arguzz simulates such a malicious prover by injecting faults into the VM's execution logic. Mapping this back to our abstract zkVM architectural diagram (c.f. Fig. ?), Arguzz's fault injection specifically works within the \textbf{Executor} component of the pipeline. 

Upon receiving the guest program and respective inputs, the zkVM begins running the program and records every intricate microarchitectural event that occurs within the virtual machine for construction of the \texttt{RawTrace}. Before this trace can be completed and sent to the \textbf{Witness Builder}, Arguzz activates its hooks inside the zkVM's executor, and a fault is injected into the VM's execution logic. Typical injections include modifications of fetched instructions, register values, addresses, or program counters (c.f. Appendix ? for the catalog of Arguzz mutations). Important to note is that once the fault is in place, the program continues execution as if that fault were there to begin with. For example, if at step 209 the values $(3,4)$ are read from source registers 1 and 2, and an \texttt{Add} instruction is fetched, then Arguzz can modify the source register 2 value to instead have the zkVM execute $3+9$ at step 209. Then not only is the source register 2 value wrong, but also the destination register value, and both errors propagate into subsequent instruction steps. If the verifier accepts the proof, then a soundness bug is present.

Arguzz's RISC Zero bug (ID 1: \textit{Missing constraint in three-register instructions}) shows this example playing out in a real production-grade zkVM. Arguzz injected a fault into an unsigned remainder instruction so that one operand was replaced. Since a constraint distinguishing between the values of the first and second source registers was missing, a false arithmetic statement became misinterpreted by the VM as true. The verifier nevertheless accepted the proof because the relevant register operands were insufficiently constrained.

Just as important as it is to have an effective catalog of soundness-testing mutations, it is equally as important to design an effective decision-making framework as to when and where to execute each mutation. A naive fault injector could choose random instruction positions uniformly from the execution trace, but then common instructions would then dominate the search. Instructions such as additions or memory operations occur frequently, while rare instructions may receive little attention, which is a problem because rare instructions and edge-case behaviors are likely less frequently audited, can be just as security-critical, and may have less mature constraint implementations. This waste's expensive bandwidth on testing reliable regions in the constraint-space, while leaving sensitive regions potentially unexplored due to time constraints. 

Arguzz addresses this with a scheduler that attempts to balance fault injection across the available RISC-V instruction set. It tracks how often each instruction has been selected for injection, identifies instructions that have been targeted less frequently, and chooses among them. This approach improves coverage of instruction-level behavior, but it remains primarily coverage-balancing rather than feedback-driven. The scheduler attempts to distribute injections uniformly across instruction types, but it does not learn how their mutations interact with the zkVM's constraint system. 

\subsection{Limitations}
\label{subsec:limitations}

As briefly mentioned in Subsection (?), this metamorphic testing approach is only designed to surface completeness bugs within the execution logic of the zkVM. Testing for soundness bugs would require introducing some kind of mutation into the inputs/guest-programs themselves and observing whether the zkVM processes these mutated inputs/guest-programs correctly (i.e. with the correct Rust/C++/RISC-V semantics the VM is designed to support). A fuzzer here could mutate semantics at both the source code (Rust/C++) level, or at the ELF level (RISC-V), while additionally, providing this mutated program with a wide variety of inputs in order to test many different paths within the mutated guest program in pursuit of exercising these potentially incorrectly handled semantics. Arguzz does not exercise any of these input/program mutation options, instead opting only for completeness bug discovery via their product programs. 

Furthermore, Arguzz's fault injector sits at a very specific point within the zkVM proving pipeline. Arguzz mutates the \texttt{RawTrace} object as it is being created, and has no effect upon the remaining proving process upon its completion. By injecting faults solely within the executor of the zkVM, the total range of variables available for mutation becomes limited, as many witness variables are later created after the raw trace is made. In addition, mutating within the executor while it is running the guest program biases the kinds of constraints which are tested during the proof generation and verification process. 

To illustrate this bias, lets consider our previous example where Arguzz decides to mutate the value of source register 2 at some arbitrary instruction step: 
\begin{align*}
&\texttt{Step 209:}&\texttt{add x3, x1, x2}  \\ 
&\text{with }&\texttt{x1}=3 \\
& &\texttt{x2}=4 \\
& &\texttt{x3}\rightarrow7
\end{align*}
Here we simply add the value of first source register \texttt{x1} to the value of the second source register \texttt{x2}, and set this addition as the new value for our destination register \texttt{x3}. Suppose once again that Arguzz modifies $4 \rightarrow 9$. The zkVM execution logic will proceed by computing $3+9=12$, and record this event within the $\texttt{RawTrace}$. Once the raw trace is complete, the zkVM will begin its proof construction within the witness builder, where the it will begin reviewing this execution record, and checking a variety of different constraints: 
\begin{align*}
\text{Local Constraints} &\rightarrow \begin{cases}
\text{fetched}(\texttt{word})\overset{\checkmark}{=}\text{memory}(\texttt{pc}) \\
\text{decode}(\texttt{word})\overset{\checkmark}{=} \texttt{add x3, x1, x2}  \\
\text{read}(\texttt{rs1}) \overset{\checkmark}{=}\text{val}(\texttt{x1}) \\
\text{read}(\texttt{rs2}) \overset{\times}{=}\text{val}(\texttt{x2}) \\
\text{write}(\texttt{rd}) \overset{\checkmark}{=}\text{val}(\texttt{x3}) \\
\text{read}(\texttt{rs1})+\text{read}(\texttt{rs2})\overset{\times}{=}\text{write}(\texttt{rd})
\end{cases} \\ \\
\text{Local Interstep Constraints}&\rightarrow \begin{cases}
\text{prev\_write}(\texttt{rs1})\overset{\checkmark}{=} \text{read}(\texttt{rs1}) \\
\text{prev\_write}(\texttt{rs2})\overset{\checkmark}{=} \text{read}(\texttt{rs2})  \\
\text{write}(\texttt{rd})\overset{\checkmark}{=} \text{next\_read}(\texttt{rd}) 
\end{cases} \\
 \\
\text{Global Constraints} &\rightarrow \begin{cases}  
(\texttt{pc}, \texttt{word})  
\overset{\checkmark}{\in}  
\text{program\_memory\_table} \\
(\texttt{step}, \texttt{x1}, \text{val}(\texttt{x1}))  
\overset{\checkmark}{\in}  
\text{register\_memory\_argument} \\
(\texttt{step}, \texttt{x2}, \text{val}(\texttt{x2}))  
\overset{\checkmark}{\in}  
\text{register\_memory\_argument} \\
(\texttt{step}, \texttt{x3}, \text{val}(\texttt{x3}))  
\overset{\checkmark}{\in}  
\text{register\_memory\_argument} 
\end{cases}\\
\end{align*}
Since this mutation occurs as the guest program is being executed, only a specific handful of the constraints above are actually violated by Arguzz. 

\begin{itemize}
\item \textbf{Global Constraints:} None of these are violated because these values enter the permutation argument once the current instruction step is executed, but before the next one begins. The permutation argument simply receives the mutated addition and keeps a record of these values and registers participating in step 209.
\item \textbf{Interstep Local Constraints:} None of these are violated in this case either. Arguzz's \texttt{PRE\_EXEC\_REG\_MOD} mutation (which we are considering in this example) modifies the value of a register before execution and after the relevant register values are read. The zkVM reads the correct values $(3,4)$ from the source registers (unchanged from the previous writes), and stores the mutated output $12$ into the destination register, which will match correctly to the value the next time that source register is read
\item \textbf{Interstep Local Constraints:} Exactly two of these are violated. The value read from source register 2 is not going to match the operand used for the addition. Similarly the values read and added from both registers is not going to match the value written to the destination register
\end{itemize}

This example illustrates that Arguzz's bias towards exercising local constraints. Injecting faults during the execution of an instruction step tends to violate the strict subset of constraints whose purpose is to ensure that the events which occurred specifically within that step are properly constrained. Previous and subsequent steps will simply adopt those new values, and propagate the error forward unchecked, meaning that the connective tissue constraining the relationships of these variables globally or between neighboring steps tends not to be exercised. 

Finally, as mentioned in Subsection (?), Arguzz's scheduling logic for its fault injector works by choosing mutations uniformly from a list of RISC-V instructions. As Arguzz begins fuzzing with fault injection, it keeps track of which instructions from this list have been targeted and how often. It attempts to maintain a uniform histogram of targeted instructions, so that instructions which appear less frequently receive an approximately equal amount of injection attacks. The authors argue that unconstrained behavior is more likely to exist within these edge cases, however no feedback measuring how useful each injection was in finding these underconstraints is given back to the scheduling logic.


\section{Our Approach}
\label{subsec:our-approach}

Having highlighted the limitations of Arguzz in the previous subsections, namely: 
\begin{itemize}
\item \textbf{1)} Bias towards exercising specific types of constraints 
\item \textbf{2)} Decreased catalog of witness variables available for mutation
\item \textbf{3)} No constraint-specific feedback mechanism for the scheduler
\item \textbf{4)} No input/guest-program soundness fuzzing
\end{itemize}
We design our approach around each limitation, producing a new architecture which explores different areas of zkVM proof creation and equips our fuzzer with a feedback mechanism used to guide mutations through a space spanned by zkVM constraints.



\subsection{Guest Program \& Input Fuzzing}
\label{subsec:guest-inputs-fuzzing}

Rather than solely providing semantically equivalent guest programs to the zkVM, we can test for soundness bugs by mutating the guest program itself. These program mutations can happen on two levels: the source code level and the ELF (RISC-V) level. Additionally, these mutations can be used to test soundness and completeness bugs separately. The difference between testing for completeness or soundness bugs boils down to whether you mutate your guest program in ways that preserve or do not preserve the original semantics of the program. 

At the source code level, semantics-preserving mutations can be done via Arguzz's metamorphic testing approach, where transformations using associativity, commutativity, and distributivity are applied. To instead test for soundness bugs and violate the original semantics, we provide a catalog of source-code mutations against numeric/bit-level operators, control-flow conditions/relations, memory/layout operations, and serialization or I/O boundaries in Appendix (?). We further combine these source-code level guest program mutations together with input mutations. By testing all of these different semantics-violating guest programs on a variety of different inputs, we not only get path coverage from the different source code mutations, but also via all the different edge cases that are tested via small, large, or otherwise abnormal inputs. 

Although these source code mutations can test a wide variety of different code paths, it is not expected for this strategy to be efficient at discovering soundness bugs. This is because a source-code mutation can create a different but still valid guest program, so the zkVM is only asked to prove the execution of that new program rather than detect a malicious deviation from it. For a soundness bug to appear, there must be a mismatch between the low-level execution semantics and the constraints checked by the verifier, and source-level fuzzing reaches this layer only indirectly after compiler lowering, optimization, and instruction selection. As a result, many source mutations are either optimized away, correctly compile into common instruction patterns, or simply fail to target the exact RISC-V instruction events where underconstraints are likely to exist. ELF-level mutations are therefore better aligned with soundness testing because they perturb the actual instruction stream consumed by the zkVM, allowing the fuzzer to target low-level VM semantics without relying on the compiler to accidentally produce the relevant edge case.

At the ELF-level, guest-program mutations testing for soundness bugs can be executed by our catalog of RISC-V mutations in Appendix (?) including: instruction substitutions, register overwrites, load/store width and sign extensions, and control-flow/boundary mutations. A zkVM which incorrectly executes these mutated guest programs and produces a proof which is accepted by the verifier indicates a soundness bug. Additionally, completeness bugs can also be tested via ELF-level mutations. Mutating padding, code segments, or other resources that do not corrupt the ELF nor change its instruction-level semantics may target an overconstraint by the zkVM. If the zkVM fails to run on an ELF that a correct RISC-V emulator (running with the same specifications supported by the zkVM) runs fine, can indicate a completeness bug.

The architectures for the source code fuzzer (which we name A1) and the ELF-level fuzzer (which we name A2) are introduced in technical depth in Chapter 4. Next we introduce our witness fuzzer, which we name A3.


\subsection{Witness Fuzzing}
\label{subsec:witness-fuzzing}

The \texttt{RawTrace} is a record of multiple execution events which occur within each RISC-V instruction step. These events document e.g. the instruction word decoded, the address of the first source register, the value read from that register, etc. In Subsection 3.3.3, we showed how many different constraints are built around these recorded execution events within the Witness Builder. This served to show how Arguzz tends to violate multiple local constraints as it mutates RISC-V instruction variables while the zkVM is executing each instruction step. We now aim to shift this constraint-targeting bias by changing where our fuzzer operates within the zkVM pipeline while simultaneously offering solutions to the other limitations addressed.

At the beginning of this section, we highlighted four limitations of Arguzz, three of which come from its fault injector. Of these three limitations, two of them come from fuzzing only within the \textbf{Executor} module of our general zkVM architecture (c.f. Fig ?). To address limitations (1) and (2), we propose a fuzzer which exists \textit{after} the \texttt{RawTrace} has been created and before it is fed to the \textbf{Witness Builder}: 

\begin{figure}[h]
    \includegraphics[width=1\textwidth]{tumbeamer/pics/a3.png}
    \label{fig:abstract-architecture}
\end{figure}

The above diagram shows a new concept, where mutations are done post-execution. This changes the constraint-targeting bias in two ways:
\begin{enumerate}
    \item Rather than mutating one RISC-V instruction variable that appears in multiple execution events, we mutate a single variable within a single execution event.
    \item Since construction of the raw trace has completed, our mutation does not propagate, meaning that local constraints become less exercised, while local-interstep and global constraints become more exercised.
\end{enumerate}

Looking back at our example list of constraints in Subsection 3.3.3, our fuzzer can now choose among events and identify a variable to mutate, meaning that $\text{read}(\texttt{rs1})+\text{read}(\texttt{rs2})\overset{?}{=}\text{write}(\texttt{rd})$ can now stay valid, while $\text{read}(\texttt{rs2})\overset{?}{=}\text{val}(\texttt{x2})$ stays invalid. 

some issues here, i am conflating execution events and whatever txns are in preflight with witness variables and constraints, i need an example of actual constraints broken for the register value mutation in A4 to ground out my intuitive example in facts, i need to see constraints satisfied and constraints broken to make help me get this explanation right.

a good punch to highlight is that arguzz has higher expected failures per mutation but lower total constraint failure probability mass sum




\chapter{Design}
\label{chap:design}

In Chapter 3, we discussed prior work in zkVM fuzzing and how their specific design choices motivate our new approach. Arguzz only mutates variables that are visible to the execution logic of the RISC-V VM, and lacks any mechanism providing constraint-level data back to the fuzzing engine to help guide future mutations as a fuzzing campaign progresses. These insights led to our two proposed approaches, each designed to answer a specific question: 
\begin{enumerate}
    \item Can information describing a mutation's interactions with the constraint system of a zkVM help guide future mutations closer towards regions containing an underconstraint (soundness bug)?
    \item Does mutating the post-execution trace help discover and stress-test underexplored and vulnerable regions in the constraint system of a zkVM?
\end{enumerate}

In this Chapter, we will now describe these two mechanisms in formal theoretical detail, and how they combine to create our new fuzzing architecture, namely A3. In Chapter 5, we will show their implementation in source code, and guide the reader through the structure of our repository and its capabilities.

\section{Mutation Feedback}
\label{sec:mutation-feedback}

Mutating the internal variables of a zkVM (either as it is executing a guest program or after it completes execution) means that you are fundamentally changing the semantics of the guest program being executing, and should result in a proof that is unverifiable for that original guest program. The mechanism \textit{responsible} for catching these deviations from the expected logic is the zkVM's \textbf{constraint system}. In Section ?, we introduced a brief example showing how a RISC-V instruction step enters a variety of different constraints during the witness building stage to help the zkVM guard against incorrect or malformed executions. Our goal is now to design a mechanism by which a mutation's interactions with the constraint system can be extracted from the zkVM and fed back into the fuzzer's decision-making logic. It is hypothesized that a fuzzer can incrementally learn from its interactions with the constraint system to then adapt its mutation decisions in search of regions which are vulnerable i.e. underconstrained.

A zkVM's system of constraints divides into two kinds with fundamentally different scope and detection mechanisms. This dichotomy is the backbone of the fuzzer's entire feedback and decision-making design, so we treat it formally.

\subsection{Local Constraint Failure Retrieval}
\label{subsec:local-constraint-failure-retrieval}

A local constraint is an equality check between two execution events that enforces some aspect of the execution within a specific instruction-step or between neighboring steps. In our Example ?, we showed that if we take the post-execution trace of an \texttt{add x3, x1, x2} instruction and modify the value read by the second source register \texttt{x2}, then the local constraint enforcing which value was read by this source register, along with the local constraint enforcing the arithmetic logic between the registers will break: 
\begin{align}
\text{read}(\texttt{x1}) &\overset{\times}{=} \text{val}(\texttt{x1}) \\
\text{read}(\texttt{rs1}) + \text{read}(\texttt{rs2}) &\overset{\times}{=} \text{write}(\texttt{rd})
\end{align}
These failures provide information on the precise effect this mutation had on the zkVMs constraint system, including how many constraints broke and what kind of semantics these broken constraints were guarding. Collecting this information over multiple mutations can help us identify which witness variables are guarded heavily (by a high number of constraints) versus weakly (by a low number of constraints). To help build these metrics of interest, we define a \textit{failure context} as the triple: $$
\gamma \;=\; \big(\texttt{Name@file:line},\; \texttt{major},\; \texttt{minor}\big),
$$identifying which Zirgen constraint template (\texttt{Name\@file:line}) was violated and towards which instruction semantics (\texttt{major, minor}) this template was applied (note: zkVMs generally use Zirgen as their circuit language/compiler infrastructure). 

The constraint template on its own is not enough to help distinguish mutation-effects. For example, consider \texttt{MemoryWrite@mem.zir:99} (c.f. Appendix A.?), which serves as the template responsible for enforcing that the write to an address is consistent between the post-execution trace and the instruction path. Then applying this template to the major/minor pair for immediate addition i.e. (0,7) constraints writing the instruction result into a register, while applying this template to the major/minor pair for word stores i.e. (6,2) constrains the action of writing a register value into memory. Both $\gamma$ constrain fundamentally different semantics, which is why the above-defined triple helps provide our fuzzing logic with the precise effects each mutation induces on the zkVM's constraint system.

We want our fuzzing logic to choose mutations that are likely to guide the fuzzer towards underconstrained regions in the zkVM's constraint system. Equipped with this new definition for mutation-induced local constraint failure $\gamma$, we now have the tool we need to define these metrics-of-interest. Let $\Gamma$ be the set of failure contexts $\gamma$ emitted by a specific mutation during a single run, we define: 
\begin{align} 
n_{\text{fail}} &= |\Gamma| \\
d_{\text{loc}} &= |\mathrm{set}(\Gamma)| \\ 
r_{\text{rep}} &=  n_{\text{fail}} - d_{\text{loc}}
\end{align}
Where $n_{\text{fail}}$ measures how many total constraint contexts our mutation induced, while $d_{\text{loc}}$ measures how many of those were distinct. The only way a mutation can surface a soundness bug is for it to break the intended instruction semantics without any other constraint being broken (as otherwise the proof would not verify and we would be none the wiser that such an underconstraint existed). Therefore, we provide our fuzzer's decision-making logic with these metrics so that it can guide its decisions towards mutations which minimize these values. $r_{\text{rep}}$ additionally builds on these in order to measure how many times a single mutation caused the same failure context to break at once, giving us a sense as to how "tied up" i.e. protected the targeted constraint is within the system. 

Having introduced the feedback extracted from local constrain failures, we will shift our focus towards our second vector of feedback, global constraint failure retrieval.

\subsection{Global Constraint Failure Retrieval}
\label{subsec:global-constraint-failure-retrieval}


Unlike local constraints which are tied to instruction events within a single step or between neighboring steps, global constraints couple the entire trace. Rather than checking that a small piece of zkVM execution is internally consistent, they check that all the pieces fit together when viewed as one whole object i.e. that the trace of zkVM execution tells a globally consistent story. In the previous Subsection we looked at an example for $\gamma$ which enforced that the write to an address is consistent between the post-execution trace and the instruction path. A global constraint would instead take all of the writes and their respective addresses from the post-execution trace and enforce that every memory read must match the correct earlier memory write.

The intuition behind global constraints does not vary among zkVMs, but their implementation does. Since our work is focused around RISC Zero (for the reasons mentioned in Section ?), in order to design a feedback mechanism around global constraint failures, we must ground it upon the implementation chosen by the developers of RISC Zero. In this zkVM, two flavors of global constraints exist:

\begin{itemize}
    \item \textbf{Memory Consistency:} A read at cycle $j$ must return the value of the most recent write to that address, possibly thousands of rows earlier. The circuit certifies this via a multiset equality claim (where a multiset is a set which tracks how many times each element appears). For memory consistency, if the read multiset shows a value read from e.g. a register which the write multiset doesn't contain, then this indicates a deviation from the guest program's intended semantics.
    \item \textbf{Lookup / Range Arguments:} A byte column should contain a value in $\{0,\dots,255\}$, a bit column should contain a value in $\{0,1\}$, and an opcode or table-index column should correspond to one of the allowed table entries. However, since the proof system only ever sees field elements, the zkVM needs a way to predefine what the correct e.g. $\{0,\dots,255\}$ values correspond to in the respective field. Lookup and range arguments enforce that values must exists within their respective ranges by collecting the looked-up values across the trace and checking them against the corresponding allowed table. 
\end{itemize}

Unfortunately, failure retrieval for global constraints is more difficult than for local constraints. In the previous subsection, we saw how local constraints test the internal consistency of some aspect of an instruction execution via a simple equality constraint. If it’s nonzero, you know exactly which rule failed, making the hook for the retrieval mechanism fairly simple. However for global constraints, when asking if every memory read canceled with its matching write, then no single line of RISC Zero source code is going to tell us exactly which entry into the multiset broke the global constraint. As a result, our global constraint failure retrieval mechanism is going to require an extensive collection and reconstruction procedure. To properly explain how this mechanism works, we first need to explain how RISC Zero enforces multiset equality.

\subsubsection{Logarithmic Derivative Identity}
\label{subsubsec:logarithmic-derivative-identity}


Every memory and lookup event is encoded as a tuple: 
\begin{align*}
z_{\text{mem}}&=(\text{addr},\,\text{step},\,\text{data}) \\
z_{\text{look}}&=(\text{index},\,\text{table})
\end{align*}
The circuit assigns $m=+1$ for a write (insertion into the multiset), and assigns $m=-1$ for a read (removal from the multiset), which in $\mathbb{F}_{p}$ is written as $p-1$. So if a read correctly matches a prior write, they contribute the same tuple to the multiset with opposite signs i.e. $+z-z=0$. A consistent execution pairs each read with its matching write so that identical tuples cancel, otherwise: 
\begin{align}
(\text{addr}=\texttt{0x1E9FF2},\,\text{step}=92,\,\text{data}=28) \,\,\,\,:\,\,\,\,& +1 \\
(\text{addr}=\texttt{0x1E9FF2},\,\text{step}=92,\,\text{data}=43) \,\,\,\,:\,\,\,\,& -1
\end{align}
means the memory transcript is inconsistent. Since the trace can contain a very large number of events, with each event being a multi-field tuple, direct comparison of every individual element would be unnecessarily expensive. Therefore, the zkVM compresses each tuple into one field element via the random affine hash: $$
h_{r}(z)=r_{0}+r_{1}\text{addr}+r_{2}\text{step}+r_{3}\text{data}
$$with random coefficients $r$ coming from post-execution commitments of the entire trace to prevent a dishonest prover from creating a trace or tuning different $z$ to engineer cancellations (c.f. Section ? for our discussion on Fiat-Shamir). 

Now that we have a signed multiset $\mathcal{M}=\big\{ \big(h_{1}(z_{i}),m_{i}\big) \big\}$ (assume non-random linear combination $r=1$ for now), we need to check that all multiplicities cancel out. However, verifying this for every $h_{1}(z_{i})$ would be expensive and unnecessary. Instead, we organize all of our elements in $\mathcal{M}$ into an algebraic expression whose value is zero exactly when all these grouped counts are zero. RISC Zero does this by organizing all of these elements into the rational function: 
\begin{align}
F(X)&=\frac{\prod_{\{ i\,|\,m_{i}=+1 \}}\big(X-h_{1}(z_{i})\big)}{\prod_{\{ i\,|\,m_{i}=-1 \}}\big(X-h_{1}(z_{i})\big)} \\
&=\prod_{i}\big(X-h_{1}(z_{i})\big)^{m_{i}}
\end{align}
where different values do not freely cancel each other out e.g. $F(X)=\frac{(X-5)(X-7)}{(X-5)(X-8)}\ne 1$. At this point, one possible check is to evaluate the polynomial at a random challenge $\alpha$ and check if $F(\alpha)\overset{?}{=}1$, but LogUp uses a different representation of the same condition for convenience. 
\begin{align}
G(X)&= \frac{F'(X)}{F(X)}\\
&=\sum_{i}\frac{m_{i}}{\alpha-h_{1}(z_{i})} \\
&\overset{?}{=}0
\end{align}
The LogUp form (which comes from the above shown logarithmic derivative) allows for zkVMs to aggregate and batch linear sums of contributions more cheaply than they can prove a long multiplicative recurrence [?]. 

Equipped with this understanding of how RISC Zero checks multiset equality, we can engineer an approach to retrieve global constraint failures down to the specific address and data involved. After the guest program is finished executing and the trace is complete, the witness building process begins. During witness generation, every memory access $z_{\text{mem}}$ and every lookup $z_{\text{look}}$ enters the multiset via with zirgen-enforced multiplicities $m\in \{ +1,-1 \}$ and the respective tuple into the witness. RISC Zero breaks multisets down into families $\mathcal{F}\in \{ \text{memory},\,\text{u8},\,\text{u16},\,\text{cycle} \}$ where a cycle is simply a zkVM instruction-level substep, and computes residues $$
\text{res}_{\mathcal{F}}=\sum_{i\in \mathcal{F}}m_{i}h_{r}(z_{i})^{-1}
$$where for a consistent trace, each residue (along with the sum of residues) must be equal to zero. For any residue where $\text{res}_{\mathcal{F}}\ne 0$, we can filter our collected tuples and multiplicities for this family, and identify which tuple is uncanceled. 

This leaves us with granular feedback available to send back to our fuzzer. Not only can we identify which of the four global constraint families does our mutation break, but via the address and data of the tuple we can immediately extract relevant memory-level exploration diagnostics each mutation reaches. This allows our fuzzer to schedule mutations which can explore and exploit constraints guarding regions such as user memory, kernel memory, machine special memory, or environment call dispatch memory (c.f. Appendix A.? for definitions). 

Until now we have discussed the precise feedback we can extract from the zkVM's internal proving pipeline. In the next subsection we will use this extracted data as the fundamental building blocks for defining a new notion of coverage (specific to the zkVM's constraint system). In subsection ? we will use the feedback we extract and the coverage that we measure to equip our fuzzer with the necessary information it needs to navigate the constraint system and learn from its decisions. In Chapter 7, we will show the specific implementation of how our architecture extracts these metrics from the zkVM internally.


\subsection{Constraint Coverage}
\label{subsec:constraint-coverage}

In computer science, coverage is a broad term meant to provide some quantitative measure of how thoroughly a program has been run. Typically, we specify this to a specific aspect of a program, such as control-flow, where e.g. edge coverage measures what percentage of every edge in the control-flow graph has been executed. For our purposes, we are interested in applying this notion to the zkVM's constraint system in order to establish some quantitative measure behind how thoroughly this space of circuit constraints has been exercised during a fuzzing campaign for a specific guest program. 

The feedback of the previous section (the local contexts $\Gamma$ broken + the global tuples $Z$ broken) describes a \textit{single} run. To steer a campaign, the fuzzer must remember what it has already exercised, so it can tell whether a new mutation reaches somewhere new, or merely re-treads old ground. We therefore accumulate the per-run feedback into local $\mathcal{L}_{t}$, global $\mathcal{G}_{t}$, and structural $\mathcal{S}_{t}$ coverage sets as each pull $t$ (i.e. mutation decision) is executed and our coverage sets grow monotonically over the campaign:
\begin{align}
\mathcal{L}_{t}&=\mathcal{L}_{t-1}\cup \text{set}(\Gamma_{t}) \\
\mathcal{G}_{t}&=\mathcal{G}_{t-1}\cup \{ \text{cgc}(z_{t})\,|\,\text{res}_{\mathcal{F}}\ne  0,\,m \text{ uncanceled} \} \\
\mathcal{S}_{t}&=\mathcal{S}_{t-1}\cup \sigma_{t}
\end{align}
Since our global failure retrieval mechanism provides us raw broken memory addresses and lookup indices, using a raw address as a coverage coordinate in a space the size of $2^{32}$ would make every break "new" forever. We therefore compress each broken tuple $z$ into a semantically meaningful key, the Compressed Global Context $\text{cgc}(z)$. This key breaks down the global constraint failure feedback into into functional regions (e.g. user, kernel, etc.), opcode classes (e.g. arithmetic, branch, etc.) to understand what kind of instruction family the break is belonged to, cycle phases to understand where in the machine's control flow the mutation sat, and more (c.f. Appendix ? for precise definitions). 

$\mathcal{L}$ and $\mathcal{G}$ measure the environment's response to a mutation and help us measure our exploration (and future exploitation) of the constraint system. However to help the fuzzer ensure that a variety of mutations are applied over a variety of instruction types and trace zones, we further keep track of what the fuzzer tried $\mathcal{S}_{t}$ (c.f. Definition ? Appendix ?). 

These three newly defined notions of coverage not only serve as auxiliary diagnostics, but also as fundamental items of live information that our fuzzer can use to adaptively learn which mutations provide more value than others and schedule mutations accordingly. Specifically, $\mathcal{L},\mathcal{G},\mathcal{S}$ help us for:

\begin{enumerate}
    \item \textbf{Offline Mutation Experiments:} In pursuit of designing new zkVM mutation strategies (e.g. post-execution vs during-execution) constraint coverage tells us:
    \begin{itemize}
        \item Which constraints each mutation hits?
        \item Whether two mutations hit the same constraints/trace-semantics (redundancy)?
        \item Which mutations hit a wide variety of distinct constraints vs a narrow set?
        \item How often a single mutation triggers a cascade of constraint failures vs only a single surgical failure?
    \end{itemize}
    \item \textbf{Online Decision-Making Feedback:} Our coverage sets help our fuzzer keep live track of novelty, which becomes especially useful deep within a fuzzing session on a single guest program
    \begin{itemize}
        \item Has this mutation discovered a new local or global constraint not yet found by our coverage sets?
        \item Have we applied each mutation design to every instruction class and semantic trace zone?
    \end{itemize}
\end{enumerate}

The answers to these questions help our fuzzer distinguish between which mutation decisions are likely more useful than others. If we are 9000 mutations deep in a fuzzing session, and most mutation kinds $1,\dots,j$ are not adding anything to our coverages sets, while mutation kind $j+1$ continues to discover e.g. a new $\gamma$, then this mutation kind should be prioritized by our fuzzing logic. 

Having introduced the internal constraint and witness data we can extract from the zkVM, and having then shown the metrics we can build from the raw data, in the next section, we will go into more detail on how our fuzzing logic uses feedback and coverage to explore the zkVM's constraint system and adaptively learn which mutations provide the most value.



\section{Multi-Armed Bandit}
\label{sec:multi-armed-bandit}

A Multi‑Armed Bandit (MAB) is a sequential decision‑making problem originating from casino theory (alluding to a row of slot machines designed to steal your money) in which an agent (the slot machine user) repeatedly chooses among several uncertain options (“arms”), each yielding random rewards drawn from unknown distributions. The tradeoff the agent must grapple with is between exploring arms to learn their payoff distributions while simultaneously exploiting the information gathered to maximize cumulative reward. Just as the agent wants to maximize profits from the row of slot machines, we want to maximize coverage and exploit (mutate) "vulnerable" constraints: $$
C_{N}=\lvert \mathcal{L}_{N} \rvert +\lvert \mathcal{G}_{N} \rvert + \lvert \mathcal{S}_{N} \rvert 
$$where $C_{N}$ is the total discovered coverage after $N$ mutation decisions. The question looming over this chapter of "how do we maximize coverage and exploit vulnerable constraints" can now be expressed as a sequential decision-making problem. 

When making a mutation-decision, the fuzzer does not choose a mutation in isolation. At the moment of the $t$-th decision, it has already observed the outcomes of all previous decisions via our feedback of $\Gamma$ and $Z$. We collect this information into a history $$
\mathcal{H}_{t-1}=\big ( (a_{1},\gamma_{1},z_{1},\sigma_{1}),\dots,(a_{t-1},\gamma_{t-1},z_{t-1},\sigma_{t-1}) \big )
$$where $a_{t}$ refers to our $t$-th mutation decision i.e. our "arm" and $(\gamma_{t},z_{t},\sigma_{t})$ is the feedback observed resulting from that decision. Equipped with a set of observed decisions and their outcomes $\mathcal{H}_{t-1}$ together with a set of new decisions to make $a_{t}\in \mathcal{A}$ based on those outcomes, what we need next is a \textit{rule} which reads this history and makes a decision i.e. a policy $\pi_{t}$  $$
a_{t}\sim \pi_{t}(\cdot \mid \mathcal{H}_{t-1})\in \mathcal{P}(\mathcal{A}) \\
$$where $\mathcal{P}(\mathcal{A})$ is the set of probability distributions over arms ==?== and where $a_{t}$ is sampled according to this distribution. In our casino example, the policy $\pi$ is rule the agent uses to decide whether to pull underexplored slot-machine arms (to gather information into their hidden reward distribution) or whether to pull already-explored favorable slot-machine arms (to exploit favorable visible reward distributions). Applied to our problem at hand, it is our scheduling logic which reads the campaign state so far and decides whether to execute underexplored mutations or whether to execute already-explored mutations which we identify as \textit{favorable} (which we define soon on the next page). This notation is useful because it separates the abstract decision problem from any particular implementation of the scheduler. A purely random fuzzer, a greedy heuristic, Thompson sampling, and our implemented scheduler (which we define soon in Subsection ?) are all policies that differ only in how they map the accumulated history $\mathcal{H}_{t-1}$ into the next mutation-decision (arm) distribution. In the idealized form, the scheduler’s objective is therefore to choose a policy whose induced campaign trajectory produces as much terminal coverage as possible: $$
\pi^{*}\in \,
\arg\,\max_{\pi \in \Pi}  \,
\mathbb{E}_{\pi}  
\big[  
\lvert \mathcal{L}_{N} \rvert  
+  
\lvert \mathcal{G}_{N} \rvert  
+  
\lvert \mathcal{S}_{N} \rvert  
\big]
$$where the expectation is taken over the randomness of the policy, the mutation instantiation, and the zkVM's observed response to each mutation. The fuzzer does not know in advance which sequence of mutations will maximize $C_{N}$, nor does it search over all policies $\Pi$. Rather, this objective states the design goal, which is to make decisions that cause the discovered coverage sets to grow as much as possible under a fixed budget of $N$ mutation decisions. 

\subsection{Decision Logic}
\label{subsec:decision-logic}

A key benefit behind the maximization objective formulated above is that by telling us the end-quantity we need to maximize, we can extract a hint behind which key metric can help us achieve this maximization goal. We know that soundness bugs live as underconstraints deep within the zkVM's constraint system, so trying to schedule mutations uniformly around every instruction word (as Arguzz does) or among all memory regions in the VM is unlikely to sufficiently stress-test underconstrained RISC-V semantics within a reasonable budget $N$. What we can do, however, is take our objective above, and decompose it as such: 
\begin{align}
\mathbb{E}_{\pi}[C_{N}]&=\mathbb{E}_{\pi}\left[ \sum_{t=1}^{N}C_{t}-C_{t-1} \right] \\  
&=\sum_{t=1}^{N}\mathbb{E}_{\pi}\big[ \Delta C_{t} \big]
\\
&=\sum_{t=1}^{N}\mathbb{E}_{\pi}\big[l_{\text{new}}(t)+g_{\text{new}}(t)+s_{\text{new}}(t) \big]
\end{align}
since our three coverages spaces are disjoint, and where 
\begin{align}
\ell_{\text{new}}(t) &= \big|\,\mathrm{set}(\Gamma_t)\setminus\mathcal{L}_{t-1}\,\big| \\
g_{\text{new}}(t) &= \big|\,\mathcal{G}_t\setminus\mathcal{G}_{t-1}\,\big| \\
s_{\text{new}}(t) &= 1\big[\,\sigma_t\notin\mathcal{S}_{t-1}\,\big] 
\end{align}
shows us that our global campaign objective decomposes into the sum of incremental discoveries. This clearly shows that viewing constraint coverage as a pure exploration-exercise is ineffective. An effective policy $\pi$ is not going to maximize the number of mutations targeted at distinct instruction (like Arguzz' scheduler does), but rather its going choose mutations based on their likelihood of expanding one of our coverage frontiers. 

As a result of this insight, a natural first choice would be to treat $\Delta C_{t}$ itself as the reward our scheduling logic receives for its mutation decision $a_{t}$. However, this would mean a mutation receives a larger reward when it discovers more new local contexts $\gamma$ or more compressed global contexts $\text{cgc}(z)$. Yet a soundness bug is not going to be discovered if the mutation which targets it triggers (alongside the underconstraint) a large series of intertwined constraints. This means a mutation which triggers a large failure cascade should not be more favorable to one which is triggers less. The raw number of new contexts in a single run can be bursty and uneven, so a more stable question for the bandit to answer should not be "how many new objects did this pull find?", but rather "did this pull advance the frontier at all?" We therefore collapse the marginal gain into a binary discovery event: 
\begin{align}
B_{t}&=1[\Delta C_{t}>0] \\
&=1[\ell_{\text{new}}(t)+g_{\text{new}}(t)+s_{\text{new}}(t)>0]
\end{align}
This means $B_{t}=1$ selected a mutation arm $A_{t}$ which discovered at least one new local context $\gamma$, compressed global context $\text{cgc}(z_{t})$, or chose structural mutation $\sigma_{t}$ it had not tried yet. This is precisely the reward signal we provide to our fuzzer which, together with our policy $\pi$, drives all mutation decisions. 

\begin{figure}[h]
    \includegraphics[width=1\textwidth]{tumbeamer/pics/reward_arch.png}
    \label{fig:abstract-architecture}
\end{figure}

\subsection{Bayesian Learning}
\label{subsec:bayesian}

We started this chapter by establishing that in order to discover soundness bugs in the zkVM, the objective we must maximize is terminal coverage $C_{N}$. This is because underconstraints live deep within the zkVMs constraint system, so being able to reach as many distinct local and global constraints (i.e. maximize coverage sets $\mathcal{L}_{N}$ and $\mathcal{G}_{N}$) with as many mutations as possible (i.e. maximize coverage set $\mathcal{S}_{N}$) ensures that as many parts of the constraint system are covered and stress-tested by the end of our mutation budget $N$ as is possible. We then motivated that the best way to reward our scheduling policy $\pi$ is via a binary signal $B_{t}$ which activates whenever the scheduler chose a mutation decision $a_{t}$ that discovered at least one new local/global context (or chose a mutation that has not yet been attempted). The next question which naturally arises becomes "how can we actually \textit{translate} this reward into a mutation decision which is \textit{likely} to increase at least one of our coverage sets yet again?"

In order to answer this question, we must note that our binary reduction changes the bandit's learning problem into a problem of estimating (for each arm) the conditional probability $\theta_{a}$ that another pull from that arm still yields new coverage: $$
\theta_{a}=P(B_{t}=1\mid A_{t}=a)
$$where high values mean the arm is currently productive, while low values means the arm was never useful for this guest program, or has already exhausted most of the coverage it can reach. The scheduler's task therefore is to estimate these unknown $\theta_{a}$'s while continuing to spend its finite mutation budget. Since our reward has been reduced to a success-or-failure event, the outcome of pulling arm $a\in \mathcal{A}$ can be modeled as: $$  
\{B_t  
\mid  
A_t=a,\,\theta_a  \}
\sim  
\mathrm{Bernoulli}(\theta_a).  
$$If the scheduler had perfect knowledge of $\theta_{a}$ in advance, the logic would be simple as it would simply prefer arms with high discovery probability. The learning problem is precisely that each $\theta_{a}$ is hidden and must be inferred from the sequence of successes and failures observed from the campaign. 

Just as the casino player needed to figure out the probability distribution intrinsic to each slot machine, we need to do the same with our mutations, and will thus assign a probability distribution over each arm's unknown discovery probability. Since $\theta_{a}$ is itself a probability, it must lie in the interval $[0,1]$, making the Beta distribution a natural choice given its support over this interval: $$
\theta_a  
\sim  
\mathrm{Beta}(\alpha_a,\,\beta_a)
$$with parameters $\alpha_{a}$ and $\beta_{a}$ controlling the scheduler's current success/failure-belief about arm $a$ (informed each arm's number of successes $n^{(s)}$ and failures $n^{(f)}$ in discovering new contexts). Additionally, the Beta distribution is the conjugate to the Bernoulli distribution, meaning that after observing Bernoulli data, the posterior distribution $\theta_{a}\mid\text{data}$ remains a Beta distribution (c.f. Appendix ? for a short proof). This makes each update exact and computationally simple: 
\begin{align}
\theta_{a}&\sim \text{Beta}(\alpha_{a},\,\beta_{a}) \\
&\rightarrow  \\
\theta_{a}\mid\text{data}&\sim \text{Beta}(\alpha_{a}+n_{a}^{(s)},\,\beta_{a}+n_{a}^{(f)})
\end{align}
We do not have to fit a model from scratch after each mutation, we simply update the two numbers for the arm that was just pulled 
\begin{align}
\alpha_{a}&\leftarrow \alpha_{a}+B_{t} \\
\beta_{a}&\leftarrow \beta_{a}+(1-B_{t})
\end{align}
If the arm discovered a new context, we increase $\alpha_{a}$ by one, and if it did not, then we increase $\beta_{a}$. Thus, Bayesian learning reduces to simple counting. For each arm, how many times did it produce a discovery and how many times did it fail to do so? 

From this posterior, the scheduler can read two kinds of information. The posterior mean $\frac{\alpha_{a}}{\alpha_{a}+\beta_{a}}$ estimates the arm's discovery probability, while the width of the posterior captures uncertainty. An arm that has been pulled many times has a concentrated posterior, because the scheduler has \textit{substantial evidence} about it. An arm that has been pulled only a few times has a wider (higher entropy) posterior, because its true discover probability remains uncertain. 

The final question remains how to turn these posteriors into mutation decisions. A purely greedy scheduler could choose the arm with the highest posterior mean, but that would discard uncertainty and risk ignoring arms that have not yet been tested enough. A uniformly random scheduler (similar to Arguzz) would preserve exploration, but that would ignore the evidence accumulated so far. In order to work within this tradeoff, what we can instead do is sample one plausible discovery probability from each arm's posterior: $$  
\widetilde{\theta}_a  
\sim  
\mathrm{Beta}(\alpha_a,\beta_a)  
\quad  : \quad
\forall a\in\mathcal{A}.  
$$and then choose the arm whose sampled value is largest: $$
a^{*}=\,\arg\,\max_{a\in\mathcal{A}}\,  
\widetilde{\theta}_a
$$Arms with high posterior mean tend to sample high values and are therefore selected often, while arms with many failures have posteriors concentrated near low discovery probability and are selected less often. On the other hand, arms with little little evidence have \textit{wide} posteriors, so they occasionally sample optimistic values and are revisited. This technique (known as Thompson sampling) converts posterior uncertainty into a scheduling decision without requiring a separate hand-written exploration vs exploitation decision rule. 

At this point, we have shown how to convert our reward signal $B_{t}$ into an actionable policy $\pi$ our fuzzer can use to balance exploring new contexts $\gamma,\,\text{cgc}(z),$ and $\sigma$ vs exploiting known favorable contexts, all towards the goal of discovering novel coverage $\Delta C_{t}$ with each mutation $a$. We demonstrated that this policy works through an incremental statistical learning procedure. Specifically, it assumes each mutation has a fixed discovery probability $\theta_{a}$, where then the Beta posterior concentrates around this value, and then Thompson sampling increasingly favors mutations with the highest true discovery rates, while still sampling high-entropic arms containing little evidence. The remaining issue, however, is that our setting violates this fixed-probability assumption. 


\subsection{Non-Stationarity and Saturation}
\label{subsec:saturation}

The probability that a mutation discovers something new changes as the campaign itself changes, because each discovery removes one object from the remaining frontier. This means each arm does not have a fixed reward distribution. In our setting, the reward is novelty, and novelty is consumed when it is found. As a result, whether mutation $a_{t}$ discovers something new at time $t$ depends not only on the arm itself, but also on what the campaign has already discovered, making the true discovery probability history-dependent $$
\theta_{a,t}= P(B_{t}=1\mid A_{t}=a,\,\mathcal{H}_{t-1})
$$The additional conditioning on $\mathcal{H}_{t-1}$ expresses that the same mutation decision may be highly productive early in the campaign, but much less productive later. Not because the arm changed, but because the campaign has already exhausted many of the contexts it can reach. This means our discovery signal is non-stationary and decays toward a low residual (c.f. Appendix ? for a formal demonstration of the monotone submodularity of our coverage sets). 

This also explains why the Beta-Bernoulli model is useful, but imperfect. Early successes increase $\alpha_{a}$ and raise the posterior mean of an arm $a$, but those successes consume much of the frontier that made that mutation decision productive in the first place. The posterior therefore lags behind the campaign state by remembering that a mutation decision was productive, even after that mutation's reachable novelty began to saturate. 

This creates three specific risks for our scheduling policy $\pi$:
\begin{enumerate}
\item \textbf{Over-exploitation of early successes:} Mutations with early successes can dominate the posterior even after their most accessible coverage has been found. The learner then spends budget repeating regions that were historically productive, rather than regions that still have remaining novelty.
\item \textbf{Under-sampling valuable mutations:} Some mutations could have lower average discovery probability, but reach unusual parts of the constraint system at times. These are exactly the decisions that are easy to abandon under a reward-driven policy, even though their remaining discoveries may be valuable for soundness testing.
\item \textbf{Discovery Sparsity:} As the campaign saturates, the discovery bit signal becomes sparse for many arms simultaneously. Once most pulls return $B_{t=0}$, the posterior means of many arms drift toward similar low values. At that point, the learner has less signal with which to distinguish arms, even though the campaign still needs broad coverage of the long tail of rare reaches into the zkVM's constraint system.
\end{enumerate}

As a result of these diagnoses, Thompson sampling should not be the only mechanism controlling the scheduling policy. The Bayesian learning procedure is good at exploiting observed differences in discovery rate, but the nature of our coverage objective and zkVM constraint system also requires guaranteed breadth as a campaign progresses and coverage saturates.

\subsection{Bernoulli Floor}
\label{subsec:Bernoulli-floor}

To address the risks diagnosed in the previous subsection, we need a way to reserve part of the mutation budget for rare-signal exploration of mutations whose value may be rare, delayed or temporarily underestimated. Specifically, we need a clean way to express the following intended architecture:
\begin{enumerate} 
\item Broad exploration when coverage is still being mapped
\item Adaptive exploration when evidence has accumulated
\item Persistent floor to prevent rare-outcome mutations from disappearing completely
\end{enumerate}

We address this by separating our scheduler into two modes. The first is an adaptive (Thompson sampling) policy $\pi_{\text{TS}}$ which chooses mutations according to the learned posterior. The second is an exploratory floor policy $\pi_{\text{floor}}$ which chooses arms according to a coverage-balancing rule. The scheduler then needs a mechanism for deciding which policy controls decision $t$, which we design via an independent exploration coin: $$  
E_t  
\sim  
\mathrm{Bernoulli}(\phi(t)),  
$$where $\phi(t)\in[0,1]$ is the floor rate at time $t$. If $E_t=1$, the floor fires and the scheduler chooses an arm using the floor policy $\pi_{\text{floor}}^{(t)}$, while for $E_t=0$ the scheduler falls through to the adaptive Thompson-sampling policy $\pi_{\text{TS}}^{(t)}$. When the floor policy is activated, it does not pick uniformly at random, but rather picks the arm with the fewest pulls in the current epoch window. Therefore, this policy continuously provides the least explored mutations in $\mathcal{A}$ a chance of hitting the reward signal and entering the Thompson sampling domain even as novelty saturates and Thompson sampling naturally collapses around a decreasing set of preferred mutations.

There are different choices one can make for $\phi(t)$, and although we tested exponential decay (i.e. a decreasing exponential function of new discoveries) and piecewise epoch expressions, we found no statistical significance in performance improvement in comparison to using the constant rate $\phi_0=0.55$. In the following section, we bring all of these discussed components together to demonstrate the end-to-end learning algorithm. 


\section{Learning Algorithm}
\label{sec:learning-algorithm}

We can now assemble the full learning procedure after having introduced each mechanism separately:
\begin{itemize}
    \item The coverage sets define what the campaign is trying to grow
    \item The binary discovery signal \(B_t\) defines the reward observed after each mutation based on coverage set expansion
    \item The Beta posterior stores what the scheduler has learned about each mutation 
    \item Thompson sampling converts these posteriors into adaptive choices
    \item The Bernoulli floor preserves breadth when novelty begins to saturate
\end{itemize}



\begin{process2e}[t]
  \caption{\textsc{Multi-Armed Bandit}}
  \label{proc:a3-scheduler-2e}

  \KwIn{Mutation arms $\mathcal{A}$; budget $N$; floor rate $\phi_0\in[0,1]$;}

  \textbf{Initialize:} $\mathcal{L}_{0} \gets \varnothing$, $\mathcal{G}_{0} \gets \varnothing$, $\mathcal{S}_{0} \gets \varnothing$, $\mathcal{H}_{0} \gets \varnothing$\;
  \For{$a\in\mathcal{A}$}{
    $\alpha_a\gets 1$\\ 
    $\beta_a\gets 1$\
  }

  \For{$t\in \{1,...,N\}$}{
    \textbf{Sample} $E_t\sim\mathrm{Bernoulli}(\phi_0)$
    \eIf{$E_t=1$}{
      \textbf{Select} $A_t\gets \arg\underset{a \in \mathcal{A}}{\min}\sum_{s \le t}\textbf{1}[a_s\in\mathcal{H}_t]$\
    }{
      \textbf{Sample} $\Tilde{\theta}_a\sim\text{Beta}(\alpha_a,\beta_a)$\\
      \textbf{Select} $A_t \gets \arg \underset{a\in\mathcal{A}}{\max} \,\widetilde{\theta}_{a}$ \
      }
      \textbf{Execute} $\Gamma_t, Z_t, \sigma_t,\mathcal{O} \gets \text{mut}(A_t, \,\text{zkVM})$\\
      \Compute{\textrm{Incremental Novelty}}{
        $\ell_{\mathrm{new}}(t)\gets\left|\mathrm{set}(\Gamma_t)\setminus\mathcal{L}_{t-1}\right|$\\
        $g_{\mathrm{new}}(t)
        \gets
        \left|
          \{ z \in Z_t  \mid \text{res}_{\mathcal{F}\ne 0}\text{ uncanceled} \}\setminus\mathcal{G}_{t-1}
        \right|$\\
        $s_{\mathrm{new}}(t)
        \gets
        \textbf{1}
        \left[
          \sigma_t\notin\mathcal{S}_{t-1}
        \right]$\\
        }
    \textbf{Compute}  $B_t \gets\textbf{1}\left[\ell_{\mathrm{new}}(t)+g_{\mathrm{new}}(t)+s_{\mathrm{new}}(t)>0\right]$\\
    \Update{\textrm{Posterior and History}}{
    $\alpha_{A_t}\gets \alpha_{A_t}+B_t$\\
    $\beta_{A_t}\gets \beta_{A_t}+(1-B_t)$ \\
    $\mathcal{H}_{t}\gets \mathcal{H}_{t-1}\circ\big(A_t,\Gamma_t,Z_t,\sigma_t,B_t\big)$\
      }
  }
  \Return $\mathcal{L}_{N},\mathcal{G}_{N},\mathcal{O}$
\end{process2e}

Each of these steps are set into the above chronological procedure. At the end of a campaign run, our algorithm returns our local and global terminal coverage sets $\mathcal{L}_N$ and $\mathcal{G}_N$, along with a set of outcomes $\mathcal{O}$ informing us for each mutation executed, whether the respective zkVM proof was accepted or rejected by the verifier.


\subsection{Fuzzing Variants}
\label{subsec:fuzzing-variants}

In this chapter, we discussed the design of our feedback-aware mutation decision-making logic, and how this new approach is designed to address Question 1 put forth at the beginning of this chapter:

\textbf{Question 1.} Can information describing a mutation's interactions with the constraint system of a zkVM help guide future mutations closer towards regions containing an underconstraint (soundness bug)?

We hypothesize that our Multi-Armed Bandit learning algorithm provides the necessary information our fuzzer needs to explore the zkVM's constraint system and exploit this evidence to focus on mutations that are more likely to target and surface deeply entrenched soundness bugs. In Chapter 5 we will discuss our second approach designed to address Question 2 by introducing a new mutation implementation which targets a surface area of the zkVM different to Arguzz's implementation, specifically targeting the post-execution \texttt{RawTrace}. Once both of these questions are addressed in Chapter 5, we will then provide a high-level overview of our complete fuzzing architecture, and in Chapter 6 evaluate their coverage and bug discovery capabilities.

In order to properly evaluate the value provided by each these two approaches (i.e. our new scheduling logic + our expanded mutation implementation), we will test each component both in separation and in combination via the following architecture-variants:


\textbf{Arguzz Bandit}
\begin{itemize}
    \item This variant preserves Arguzz's (during-execution) trace mutation implementation and replaces its scheduling logic with our MAB learning algorithm
    \item \underline{Question to answer:} Do Arguzz's coverage and bug finding capabilities improve via learned constraint-failure feedback?
\end{itemize}

\textbf{A3 Bandit}
\begin{itemize}
    \item This variant only uses our new (post-execution) trace mutation implementation and is guided in its mutation decisions by our MAB learning algorithm
    \item \underline{Question to answer:} Does coverage-guided post-execution trace fuzzing improve in its coverage and bug finding capabilities in comparison to baseline-Arguzz?
\end{itemize}


\textbf{A3+Arguzz Bandit}
\begin{itemize}
    \item This variant uses both A3 and Arguzz trace mutation implementations and is guided in its mutation decisions by our MAB learning algorithm
    \item \underline{Question to answer:} Does expanding Arguzz's mutation implementation with our post-execution trace mutations under guidance from our MAB learning algorithm create the strongest architecture both in coverage and bug finding capability?
\end{itemize}

\textbf{Arguzz}
\begin{itemize}
    \item This variant is baseline Arguzz with its standard scheduling logic unmodified. Only RISC Zero is modified to explose local/global constraint failure information.
    \item \underline{Question to answer:} How thoroughly does baseline Arguzz cover the zkVM's constraint system?
\end{itemize}

\chapter{Implementation}
\label{chap:implementation}

In the previous chapter, we introduced a new approach to address the question of whether constraint-failure feedback and learning can help a fuzzer discover soundness bugs in zkVMs. In this chapter, we will propose a second approach focusing on new mutation strategy implementations to address our second question:

\textbf{Question 2.} Does mutating the post-execution trace help discover and stress-test underexplored and vulnerable regions in the constraint system of a zkVM?

We will explore the differences between this new surface area of mutations and Arguzz's during-execution mutation strategy, define our oracle implementation helping us classify soundness bug candidates, and then provide a higher-level overview of our end-to-end fuzzing architecture. 


\section{Post Execution Trace Mutations}
\label{sec:post-execution}

- talk about risc zero executor to preflight process and how it works and why
- talk about arguzz mutation kinds in rv32im.rs
- talk about what arguzz cannot mutate in preflight trace
- talk about a4 mutation kinds


\section{Oracle}
\label{sec:oracle}


\section{Fuzzing Architecture}
\label{sec:fuzzing-architecture}


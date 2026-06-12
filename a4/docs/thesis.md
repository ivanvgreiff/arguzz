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
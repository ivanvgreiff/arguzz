In Chapter 3, we discussed prior work in zkVM fuzzing and how their specific design choices motivate our new approach. Arguzz only mutates variables that are visible to the execution logic of the RISC-V VM, and lacks any mechanism providing constraint-level data back to the fuzzing engine to help guide future mutations as a fuzzing campaign progresses. These insights led to our two proposed approaches, each designed to answer a specific question: 

1. Can information describing a mutation's interactions with the constraint system of a zkVM help guide future mutations closer towards regions containing an underconstraint (soundness bug)?
2. Does mutating the post-execution trace help discover and stress-test underexplored and vulnerable regions in the constraint system of a zkVM?

In this Chapter, we will now describe these two mechanisms in formal theoretical detail, and how they combine to create our new fuzzing architecture, namely A3. In Chapter 5, we will show their implementation in source code, and guide the reader through the structure of our repository and its capabilities.

## Mutation Feedback

Mutating the internal variables of a zkVM (either as it is executing a guest program or after it completes execution) means that you are fundamentally changing the semantics of the guest program being executing, and should result in a proof that is unverifiable for that original guest program. The mechanism \textit{responsible} for catching these deviations from the expected logic is the zkVM's \textbf{constraint system|. In Section ?, we introduced a brief example showing how a RISC-V instruction step enters a variety of different constraints during the witness building stage to help the zkVM guard against incorrect or malformed executions. Our goal is now to design a mechanism by which a mutation's interactions with the constraint system can be extracted from the zkVM and fed back into the fuzzer's decision-making logic. It is hypothesized that a fuzzer can incrementally learn from its interactions with the constraint system to then adapt its mutation decisions in search of regions which are vulnerable i.e. underconstrained.

A zkVM's system of constraints divides into two kinds with fundamentally different scope and detection mechanisms. This dichotomy is the backbone of the fuzzer's entire feedback and decision-making design, so we treat it formally.

##### Local Constraint Interaction Retrieval

A local constraint is an equality check between two execution events that enforces some aspect of the execution within a specific instruction-step or between neighboring steps. In our Example ?, we showed that if we take the post-execution trace of an \texttt{add x3, x1, x2} instruction and modify the value read by the second source register \texttt{x2}, then the local constraint enforcing which value was read by this source register, along with the local constraint enforcing the arithmetic logic between the registers will break: $$
\begin{align}
\text{read}(\texttt{x1}) &\overset{\times}{=} \text{val}(\texttt{x1}) \\
\text{read}(\texttt{rs1}) + \text{read}(\texttt{rs2}) &\overset{\times}{=} \text{write}(\texttt{rd})
\end{align}
$$These failures provide information on the precise effect this mutation had on the zkVMs constraint system, including how many constraints broke and what kind of semantics these broken constraints were guarding. Collecting this information over multiple mutations can help us identify which witness variables are guarded heavily (by a high number of constraints) versus weakly (by a low number of constraints). To help build these metrics of interest, we define a \textit{failure context} as the triple: $$
\gamma \;=\; \big(\texttt{Name@file:line},\; \mathrm{major},\; \mathrm{minor}\big),
$$identifying which Zirgen constraint template (\texttt{Name\@file:line}) was violated and towards which instruction semantics (\texttt{major, minor}) this template was applied (note: zkVMs generally use Zirgen as their circuit language/compiler infrastructure). 

The constraint template on its own is not enough to help distinguish mutation-effects. For example, consider \texttt{MemoryWrite@mem.zir:99} (c.f. Appendix A.?), which serves as the template responsible for enforcing that the write to an address is consistent between the post-execution trace and the instruction path. Then applying this template to the major/minor pair for immediate addition i.e. $(0,7)$ constraints writing the instruction result into a register, while applying this template to the major/minor pair for word stores i.e. $(6,2)$ constrains the action of writing a register value into memory. Both $\gamma$ constrain fundamentally different semantics, which is why the above-defined triple helps provide our fuzzing logic with the precise effects each mutation induces on the zkVM's constraint system.

We want our fuzzing logic to choose mutations that are likely to guide the fuzzer towards underconstrained regions in the zkVM's constraint system. Equipped with this new definition for mutation-induced local constraint failure $\gamma$, we now have the tool we need to define these metrics-of-interest. Let $\Gamma$ be the set of failure contexts $\gamma$ emitted by a specific mutation during a single run, we define: $$
\begin{align} 
n_{\text{fail}} &= |\Gamma| \\
d_{\text{loc}} &= |\mathrm{set}(\Gamma)| \\ 
r_{\text{rep}} &=  n_{\text{fail}} - d_{\text{loc}}
\end{align}
$$Where $n_{\text{fail}}$ measures how many total constraint contexts our mutation induced, while $d_{\text{loc}}$ measures how many of those were distinct. The only way a mutation can surface a soundness bug is for it to break the intended instruction semantics without any other constraint being broken (as otherwise the proof would not verify and we would be none the wiser that such an underconstraint existed). Therefore, we provide our fuzzer's decision-making logic with these metrics so that it can guide its decisions towards mutations which minimize these values. $r_{\text{rep}}$ additionally builds on these in order to measure how many times a single mutation caused the same failure context to break at once, giving us a sense as to how "tied up" i.e. protected the targeted constraint is within the system. 

Having introduced the feedback extracted from local constrain failures, we will shift our focus towards our second vector of feedback, global constraint failure retrieval.

##### Global Constraint Failure Retrieval

Unlike local constraints which are tied to instruction events within a single step or between neighboring steps, global constraints couple the entire trace. Rather than checking that a small piece of zkVM execution is internally consistent, they check that all the pieces fit together when viewed as one whole object i.e. that the trace of zkVM execution tells a globally consistent story. In the previous Subsection we looked at an example for $\gamma$ which enforced that the write to an address is consistent between the post-execution trace and the instruction path. A global constraint would instead take all of the writes and their respective addresses from the post-execution trace and enforce that every memory read must match the correct earlier memory write.

The intuition behind global constraints does not vary among zkVMs, but their implementation does. Since our work is focused around RISC Zero (for the reasons mentioned in Section ?), in order to design a feedback mechanism around global constraint failures, we must ground it upon the implementation chosen by the developers of RISC Zero. In this zkVM, two flavors of global constraints exist:

- \textbf{Memory Consistency:} A read at cycle $j$ must return the value of the most recent write to that address, possibly thousands of rows earlier. The circuit certifies this via a multiset equality claim (where a multiset is a set which tracks how many times each element appears). For memory consistency, if the read multiset shows a value read from e.g. a register which the write multiset doesn't contain, then this indicates a deviation from the guest program's intended semantics.
- \textbf{Lookup / Range Arguments:} A byte column should contain a value in $\{0,\dots,255\}$, a bit column should contain a value in $\{0,1\}$, and an opcode or table-index column should correspond to one of the allowed table entries. However, since the proof system only ever sees field elements, the zkVM needs a way to predefine what the correct e.g. $\{0,\dots,255\}$ values correspond to in the respective field. Lookup and range arguments enforce that values must exists within their respective ranges by collecting the looked-up values across the trace and checking them against the corresponding allowed table. 

Unfortunately, failure retrieval for global constraints is much more difficult than for local constraints. In the previous subsection, we saw how local constraints test the internal consistency of some aspect of an instruction execution via a simple equality constraint. If it’s nonzero, you know exactly which rule failed, making the hook for the retrieval mechanism fairly simple. However for global constraints, when asking if every memory read canceled with its matching write, then no single line of RISC Zero source code is going to tell us exactly which entry into the multiset broke the global constraint. As a result, our global constraint failure retrieval mechanism is going to require an extensive collection and reconstruction procedure. To properly explain how this mechanism works, we first need to explain how RISC Zero enforces multiset equality.

###### Logarithmic Derivative Identity

Every memory and lookup event is encoded as a tuple: $$
\begin{cases}
z_{\text{mem}}&=(\text{addr},\text{step},\text{data}) \\
z_{\text{look}}&=(\text{index},\,\text{table})
\end{cases}
$$The circuit assigns $m=+1$ for a write (insertion into the multiset), and assigns $m=-1$ for a read (removal from the multiset), which in $\mathbb{F}_{p}$ is written as $p-1$. So if a read correctly matches a prior write, they contribute the same tuple to the multiset with opposite signs i.e. $+z-z=0$. A consistent execution pairs each read with its matching write so that identical tuples cancel, otherwise: $$
\begin{align}
(\text{addr}=\texttt{0x1E9FF2},\,\text{step}=92,\,\text{data}=28) \,\,\,\,:\,\,\,\,& +1 \\
(\text{addr}=\texttt{0x1E9FF2},\,\text{step}=92,\,\text{data}=43) \,\,\,\,:\,\,\,\,& -1
\end{align}
$$means the memory transcript is inconsistent. Since the trace can contain a very large number of events, with each event being a multi-field tuple, direct comparison of every individual element would be unnecessarily expensive. Therefore, the zkVM compresses each tuple into one field element via the random affine hash: $$
h_{r}(z)=r_{0}+r_{1}\text{addr}+r_{2}\text{step}+r_{3}\text{data}
$$with random coefficients $r$ coming from post-execution commitments of the entire trace to prevent a dishonest prover from creating a trace or tuning different $z$ to engineer cancellations (c.f. Section ? for our discussion on Fiat-Shamir). 

Now that we have a signed multiset $\mathcal{M}=\big\{ \big(h_{1}(z_{i}),m_{i}\big) \big\}$ (assume non-random linear combination $r=1$ for now), we need to check that all multiplicities cancel out. However, verifying this for every $h_{1}(z_{i})$ would be expensive and unnecessary. Instead, we organize all of our elements in $\mathcal{M}$ into an algebraic expression whose value is zero exactly when all these grouped counts are zero. RISC Zero does this by organizing all of these elements into the rational function: $$
\begin{align}
F(X)&=\frac{\prod_{\{ i\,|\,m_{i}=+1 \}}\big(X-h_{1}(z_{i})\big)}{\prod_{\{ i\,|\,m_{i}=-1 \}}\big(X-h_{1}(z_{i})\big)} \\
&=\prod_{i}\big(X-h_{1}(z_{i})\big)^{m_{i}}
\end{align}
$$where different values do not freely cancel each other out e.g. $F(X)=\frac{(X-5)(X-7)}{(X-5)(X-8)}\ne 1$. At this point, one possible check is to evaluate the polynomial at a random challenge $\alpha$ and check if $F(\alpha)\overset{?}{=}1$, but LogUp uses a different representation of the same condition for convenience. $$
\begin{align}
G(X)&= \frac{F'(X)}{F(X)}\\
&=\sum_{i}\frac{m_{i}}{\alpha-h_{1}(z_{i})} \\
&\overset{?}{=}0
\end{align}
$$The LogUp form (which comes from the above shown logarithmic derivative) allows for zkVMs to aggregate and batch linear sums of contributions more cheaply than they can prove a long multiplicative recurrence [?]. 

Equipped with this understanding of how RISC Zero checks multiset equality, we can engineer an approach to retrieve global constraint failures down to the specific address and data involved. After the guest program is finished executing and the trace is complete, the witness building process begins. During witness generation, every memory access $z_{\text{mem}}$ and every lookup $z_{\text{look}}$ enters the multiset via with zirgen-enforced multiplicities $m\in \{ +1,-1 \}$ and the respective tuple into the witness. RISC Zero breaks multisets down into families $\mathcal{F}\in \{ \text{memory},\,\text{u8},\,\text{u16},\,\text{cycle} \}$ where a cycle is simply a zkVM instruction-level substep, and computes residues $$
\text{res}_{\mathcal{F}}=\sum_{i\in \mathcal{F}}m_{i}h_{r}(z_{i})^{-1}
$$where for a consistent trace, each residue (along with the sum of residues) must be equal to zero. For any residue where $\text{res}_{\mathcal{F}}\ne 0$, we can filter our collected tuples and multiplicities for this family, and identify which tuple is uncanceled. 

This leaves us with granular feedback available to send back to our fuzzer. Not only can we identify which of the four global constraint families does our mutation break, but via the address and data of the tuple we can immediately extract relevant memory-level exploration diagnostics each mutation reaches. This allows our fuzzer to schedule mutations which can explore and exploit memory regions such as user memory, kernel memory, machine special memory, or environment call dispatch memory (c.f. Appendix A.? for definitions). 

Until now we have discussed the precise feedback we can extract from the zkVM's internal proving pipeline. In the next subsection we will use this extracted data as the fundamental building blocks for defining a new notion of coverage (specific to the zkVM's constraint system). In subsection ? we will use the feedback we extract and the coverage that we measure to equip our fuzzer with the necessary information it needs to navigate the constraint system and learn from its decisions. In Chapter 7, we will show the specific implementation of how our architecture extracts these metrics from the zkVM internally.

https://eprint.iacr.org/2022/1530.pdf


##### Constraint Coverage


## Multi-Armed Bandit


##### Semantic Decomposition of a Mutation


##### Scheduling Mutations via Feedback


###### Bayesian Learning from Mutation Outcomes


###### Coverage Floor


##### Bandit Algorithm


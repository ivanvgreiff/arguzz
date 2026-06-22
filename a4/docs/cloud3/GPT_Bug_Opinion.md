## Verdict

The **original public RISC Zero ARGUZZ bug is best understood as a same-source-register double-read constraint bug**, not merely as “take any `remu rd, rs1, rs2` with distinct registers and mutate the decoded `rs2` index to `rs1`.”

The strongest evidence is not the ARGUZZ paper’s simplified prose; it is the actual RISC Zero advisory and the two fixing PRs. The advisory says the bug affected 3-register RISC-V instructions such as `remu` and `divu`, and that the attack confused the VM into treating `rs1` and `rs2` incorrectly because of a missing rv32im constraint. It also identifies the fixes as `risc0/zirgen#238` and `risc0/risc0#3181`. ([GitHub][1])

The decisive patch is `zirgen#238`, titled **“Fix to remove extra register read when both source registers are the same.”** The fix adds `ReadSourceRegs`: when `decoded.rs1 == decoded.rs2`, it constrains that equality, performs **one** `ReadReg`, and returns that same value for both source operands; otherwise it reads the two registers separately. The comments explicitly say the separate-read path would fail for same registers because one read would occur on the same cycle. ([GitHub][2]) ([GitHub][2])

So the mechanism is:

```text
Vulnerable circuit:
    instruction encodes rs1 == rs2
    circuit effectively allows two source-register reads
    malicious prover can make those two reads disagree

Fixed circuit:
    if rs1 == rs2:
        read once
        duplicate value into both operands
    else:
        read both separately
```

That means the backport scoping doc is directionally right on the guest shape: use an instruction like `remu x3, x5, x5`, then mutate the witness so the two reads of `x5` disagree. It says to build a bug-targeting guest containing a 3-register op with `rs1 == rs2`, e.g. `remu x3,x5,x5`, and then validate that a same-register-constraint mutation is accepted on the bug commit. 

## Who is right and wrong

**Backport scoping:** right on the bug-trigger shape. It correctly says the target guest should contain a 3-register op with `rs1 == rs2`. Its caveat is that its confidence in `98387806` as “the” bug commit still needs a deterministic pre-fix-accepts/post-fix-rejects repro. 

**ProG_Report_5:** right about one important experimental-design risk, but probably wrong about the original CVE mechanism. It is right that if your mutation is literally “set `rs2 := rs1`,” then a guest already encoded as `rs1 == rs2` makes that mutation a no-op. But the real same-register exploit is not “set `rs2 := rs1`”; it is “make the two reads of the same encoded register disagree.” Pro’s normal-`rs1 != rs2` / fault-creates-equality framing follows the ARGUZZ paper’s simplified example, but it does not match the fixing PR as closely. 

**Opus Opinion:** best meta-analysis. It correctly identifies the conflict and the reconciliation: if the guest has `rs1 == rs2`, the fault must be **read divergence**, not a no-op `rs2 := rs1`. It also correctly says the final arbiter should be a deterministic MODE-2 repro. 

**ARGUZZ paper:** useful but misleading if read literally. The paper describes `rs1 = 7`, `rs2 = 5`, then replacing divisor `rs2` with `rs1`, yielding `7 % 7 = 0`, while the verifier accepts; it also says the bug affected three-register instructions such as `divu` and was patched in Zirgen and RISC Zero.  That is likely an explanatory/fuzzer-level shorthand. The actual fix does not say “prevent changing distinct `rs2` to `rs1`”; it says “remove extra register read when both source registers are the same,” and the code implements a same-register special case. ([GitHub][2])

## What you should implement for the race

Use a deterministic smoke guest like:

```asm
remu xD, xS, xS
```

with `xS != 0`, and make the honest reference expect:

```text
xS % xS = 0
```

Then the targeted malicious mutation should not be “change the instruction to `rs2 := rs1`.” It should be:

```text
for the same encoded source register:
    source-read #1 returns a
    source-read #2 returns b
    with a != b
```

For example:

```text
encoded instruction: remu x3, x5, x5
honest semantics:    7 % 7 = 0
malicious witness:   first x5 read = 7, second x5 read = 5
faulty computation:  7 % 5 = 2
oracle:              committed output/OOPS diverges, proof still accepts pre-fix
fixed behavior:      same witness rejected after #238/#3181
```

`divu` is also a good companion:

```text
encoded instruction: divu x3, x5, x5
honest semantics:    7 / 7 = 1
malicious witness:   first x5 read = 7, second x5 read = 5
faulty computation:  7 / 5 = 1   // bad example, no divergence
```

So choose `divu` inputs carefully, e.g. `13 / 13 = 1` versus `13 / 5 = 2`. For `remu`, many pairs are easier because `a % a = 0` and `a % b` is often nonzero.

## Commit choice

`98387806` is a plausible vulnerable target but not proven by its label alone. GitHub shows that commit `9838780` is a CI-runner change, **“Replace `3090_ti` jobs with `4090`,”** with only three workflow files changed. It is not itself the vulnerability-introducing or vulnerability-fixing commit. ([GitHub][3])

The actual RISC Zero update PR is `#3181`, merged May 23, 2025 as **“Disallow memory I/O to same address in the same memory cycle,”** with merge commit `67f2d81`; it references the follow-up commits `1873bbb` and `006d86c`. ([GitHub][4]) The Zirgen-side circuit fix is `#238`, also merged May 23, 2025. ([GitHub][2])

So the correct policy is:

```text
Use 98387806 only if all three pass:

1. It is before the #238/#3181 fix state actually used by your checkout.
2. The rv32im circuit still has the vulnerable pattern:
       separate ReadReg(decoded.rs1)
       separate ReadReg(decoded.rs2)
   rather than ReadSourceRegs.
3. Deterministic repro:
       pre-fix: same-register read-divergence witness is accepted
       post-fix: the identical witness is rejected
```

Do not rely on “last good state before #3181” as a verbal label. The operational definition is the repro.

## Bottom line

For your race, I would revise A1/A2 as follows:

```text
Guest:
    must contain encoded rs1 == rs2 3-register ops:
        remu xD, xS, xS
        optionally divu xD, xS, xS

Mutation:
    same-register dual-read divergence
    not rs2 := rs1 as an instruction-index mutation

Oracle:
    pre-fix accepts + wrong journal/OOPS
    post-fix rejects identical witness

Commit:
    98387806 is candidate, not authority
    authority = vulnerable-source invariant + deterministic repro
```

That gives you the best match to the original public bug reports and prevents the benchmark from accidentally measuring a no-op or a different bug.

[1]: https://github.com/advisories/GHSA-g3qg-6746-3mg9 "zkVM Underconstrained Vulnerability · CVE-2025-52484 · GitHub Advisory Database · GitHub"
[2]: https://github.com/risc0/zirgen/pull/238/files "ZIR-366: Fix to remove extra register read when both source registers are the same by jbruestle · Pull Request #238 · risc0/zirgen · GitHub"
[3]: https://github.com/risc0/risc0/commit/98387806 "ZKVM-1387: Replace `3090_ti` jobs with `4090` (#3171) · risc0/risc0@9838780 · GitHub"
[4]: https://github.com/risc0/risc0/pull/3181 "ZKVM-1392: Disallow memory I/O to same address in the same memory cycle by flaub · Pull Request #3181 · risc0/risc0 · GitHub"

# Phase 5: Main Fuzzer Integration -- Hook 3 + Accum Constraints

## Goal

Integrate Hook 3 (per-family residues + per-address broken chain detail) and accum constraint data into the MAIN A4 standalone fuzzer (`a4.standalone.cli fuzz` / `fuzzer.py`). Only Hook 3 is activated -- NOT Hooks 1 or 2.

Each per-mutation terminal output must show human-readable global constraint info alongside existing local constraint details. The output should make it immediately clear to a human reader:
- Which global constraint families were broken (memory, U16, U8, cycle)
- Which specific memory addresses or lookup values have broken chains
- Whether registers are involved (and which ones)
- Whether the mutation is "global-only" (no local failures but global violation detected)

---

## Current State

### What the main fuzzer currently shows per mutation

```
[1] ✓ COMP_OUT_MOD @ step 785: 2 failures, 15234ms, outcome: REJECTED, exit: 101
       Value: 0x00000003 -> 0x045C6103
       Destination: rd = x12 (a2)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:99
           cycle=16777, step=198, pc=0x0020B4A4, major=0, minor=7
         - MemoryWrite@mem.zir:100
           cycle=16777, step=198, pc=0x0020B4A4, major=0, minor=7
```

### What we want to ADD

```
[1] ✓ COMP_OUT_MOD @ step 785: 2 failures, 15234ms, outcome: REJECTED, exit: 101
       Value: 0x00000003 -> 0x045C6103
       Destination: rd = x12 (a2)
       Constraints hit (2 unique):
         - MemoryWrite@mem.zir:99
           cycle=16777, step=198, pc=0x0020B4A4, major=0, minor=7
         - MemoryWrite@mem.zir:100
           cycle=16777, step=198, pc=0x0020B4A4, major=0, minor=7
       Global: memory permutation broken
         - x12 (0x3fffc02c): 816 reads, 816 writes -- chain mismatch
```

For a global-only mutation:
```
[7] ✓ MEM_VAL_MOD @ step 3929: 0 failures, 14613ms, outcome: REJECTED, exit: 101
       Value: 0x00000000 -> 0x37F6EC8B
       Transaction: mem (write) at address 0x3fffc0b2
       No local constraint failures
       Global: memory permutation broken [GLOBAL-ONLY]
         - 0x3fffc0b2: chain mismatch
```

---

## Implementation Plan

### Step 1: Update `run_a4_mutation` in executor.py

**File:** [a4/core/executor.py](a4/core/executor.py)

Add `A4_FAMILY_RESIDUE=1` to the env dict. Do NOT add `A4_GLOBAL_RESIDUE` (Hook 1 not wanted).

```python
env = {
    "A4_MUTATION_CONFIG": str(config_path),
    "CONSTRAINT_CONTINUE": "1",
    "A4_COVERAGE_TOUCH": "1",
    "A4_FAMILY_RESIDUE": "1",   # NEW: Hook 3 per-family residues
}
```

### Step 2: Update `MutationExecutionResult` dataclass

**File:** [a4/core/executor.py](a4/core/executor.py)

Add fields for Hook 3 data:

```python
@dataclass
class MutationExecutionResult:
    stdout: str
    stderr: str
    combined_output: str
    exit_code: int
    failures: List[ConstraintFailure]
    touch_bitmap: Optional[bytes] = None
    family_residues: Optional[List[dict]] = None     # NEW
    family_details: Optional[List[dict]] = None      # NEW
```

### Step 3: Parse Hook 3 data in `run_a4_mutation`

**File:** [a4/core/executor.py](a4/core/executor.py)

After parsing failures and touch_bitmap, add:

```python
from a4.core.touch_coverage import parse_family_residues, parse_family_detail

family_residues = parse_family_residues(combined)
family_details = parse_family_detail(combined)

return MutationExecutionResult(
    ...,
    family_residues=family_residues,
    family_details=family_details,
)
```

### Step 4: Update `MutationResult` in fuzzer.py

**File:** [a4/standalone/fuzzer.py](a4/standalone/fuzzer.py)

The fuzzer has its own `MutationResult` dataclass that wraps `MutationExecutionResult`. Add fields:

```python
broken_families: List[str] = None         # e.g., ["memory"]
broken_addresses: List[dict] = None       # e.g., [{"addr":..., "hex":..., "reg":"x17", ...}]
is_global_only: bool = False              # True when 0 local failures + global violation
```

Populate these after executing the mutation:

```python
# After getting exec_result
broken_families = []
broken_addresses = []
if exec_result.family_residues:
    for fr in exec_result.family_residues:
        if fr.get("nonzero"):
            broken_families.append(fr["family"])
if exec_result.family_details:
    for fd in exec_result.family_details:
        if fd.get("broken_addrs"):
            broken_addresses.extend(fd["broken_addrs"])

is_global_only = len(broken_families) > 0 and len(local_failures) == 0
```

### Step 5: Update `_print_mutation_result` display

**File:** [a4/standalone/fuzzer.py](a4/standalone/fuzzer.py)

After the existing constraint failure display (around line 1406), add global constraint display:

```python
# Global constraint info (Hook 3)
if result.broken_families:
    families_str = ", ".join(result.broken_families)
    global_only_str = " [GLOBAL-ONLY]" if result.is_global_only else ""
    print(f"       Global: {families_str} permutation/lookup broken{global_only_str}")
    
    USER_REG_BASE = 0x3fffc020
    for addr_info in (result.broken_addresses or [])[:5]:
        addr = addr_info.get("addr", 0)
        hex_str = addr_info.get("hex", f"0x{addr:08x}")
        reg = addr_info.get("reg", "")
        plus = addr_info.get("plus", 0)
        minus = addr_info.get("minus", 0)
        
        if reg:
            print(f"         - {reg} ({hex_str}): {plus} +entries, {minus} -entries -- chain mismatch")
        else:
            print(f"         - {hex_str}: {plus} +entries, {minus} -entries -- chain mismatch")
    
    if len(result.broken_addresses or []) > 5:
        print(f"         ... and {len(result.broken_addresses) - 5} more broken addresses")
elif result.proof_verify_failed and not result.failures:
    # No local failures AND no global families broken -- unusual
    pass  # existing "no local constraint failures" message handles this
```

Also update the status line (around line 1286) to include a global indicator:

```python
global_marker = ""
if result.broken_families:
    global_marker = f" G={'|'.join(result.broken_families)}"
    if result.is_global_only:
        global_marker += " [GO]"

# In the print:
print(f"  [{num}] {status} {result.kind} @ step {result.step}: "
      f"{len(result.failures)} failures, {result.execution_time_ms:.0f}ms, "
      f"outcome: {outcome}, exit: {result.exit_code}"
      f"{proof_status}{new_cov}{new_touch_str}{global_marker}{bug_marker}")
```

### Step 6: Separate local and accum failures in display

Currently `_print_mutation_result` shows all failures together. Update to separate by phase:

```python
if result.failures:
    local_failures = [f for f in result.failures if f.phase == "local"]
    accum_failures = [f for f in result.failures if f.phase == "accum"]
    
    if local_failures:
        # Group local failures by constraint location (existing logic)
        failures_by_loc = {}
        for f in local_failures:
            loc = f.constraint_loc()
            if loc not in failures_by_loc:
                failures_by_loc[loc] = []
            failures_by_loc[loc].append(f)
        
        print(f"       Local constraints hit ({len(failures_by_loc)} unique):")
        for loc, failures in sorted(failures_by_loc.items()):
            first = failures[0]
            count_str = f" (x{len(failures)})" if len(failures) > 1 else ""
            print(f"         - {loc}{count_str}")
            print(f"           cycle={first.cycle}, step={first.step}, "
                  f"pc=0x{first.pc:08X}, major={first.major}, minor={first.minor}")
    
    if accum_failures:
        accum_by_loc = {}
        for f in accum_failures:
            loc = f.constraint_loc()
            if loc not in accum_by_loc:
                accum_by_loc[loc] = []
            accum_by_loc[loc].append(f)
        
        print(f"       Accum constraints hit ({len(accum_by_loc)} unique):")
        for loc, failures in sorted(accum_by_loc.items()):
            first = failures[0]
            count_str = f" (x{len(failures)})" if len(failures) > 1 else ""
            # Identify BigInt vs GenerateAccum
            if "BigIntPolyOpEqz" in loc or "inst_bigint" in loc:
                label = "BigInt"
            elif "GenerateAccum" in loc:
                label = "AccumDelta"
            else:
                label = "Accum"
            print(f"         - [{label}] {loc}{count_str}")
            print(f"           cycle={first.cycle}, step={first.step}, "
                  f"pc=0x{first.pc:08X}, major={first.major}, minor={first.minor}")
```

### Step 7: Update campaign summary

In `_print_campaign_summary` (around line 1408), add global constraint stats:

```python
# Global constraint stats
if hasattr(stats, 'global_violations'):
    print(f"\nGlobal Constraints:")
    print(f"  Mutations with global violations: {stats.global_violations}")
    print(f"  Global-only mutations (no local failures): {stats.global_only}")
```

### Step 8: Update CampaignStats

Add global tracking fields to the `CampaignStats` dataclass:

```python
global_violations: int = 0
global_only: int = 0
```

Update `_update_stats` to count these:

```python
if result.broken_families:
    stats.global_violations += 1
    if result.is_global_only:
        stats.global_only += 1
```

---

## Testing Plan

### T1: Run 5 mutations with verbose output

```bash
cd /root/arguzz && python -m a4.standalone.cli fuzz \
    --host ./workspace/output/target/release/risc0-host \
    --num 5 --seed 42 \
    -- --in1 5 --in4 10
```

Verify:
- Each mutation shows global constraint info after local constraint info
- `G=memory` (or `G=--`) appears in the status line
- Broken addresses show register names where applicable

### T2: Run with INSTR_WORD_MOD_SUR to get a global-only mutation

```bash
cd /root/arguzz && python -m a4.standalone.cli fuzz \
    --host ./workspace/output/target/release/risc0-host \
    --kind INSTR_WORD_MOD_SUR --num 20 --seed 42 \
    -- --in1 5 --in4 10
```

Verify:
- Some mutations show `[GLOBAL-ONLY]` tag
- These show `0 failures` in the status line
- Global section shows broken addresses (PC, registers)
- No accum constraint failures (expected)

### T3: Run with bandit selector

```bash
cd /root/arguzz && python -m a4.standalone.cli fuzz \
    --host ./workspace/output/target/release/risc0-host \
    --selector bandit --num 30 --seed 42 \
    -- --in1 5 --in4 10
```

Verify:
- Bandit selector works correctly with global data present
- Campaign summary shows global constraint stats
- No crashes or parsing errors

### T4: Verify proof pipeline unaffected

Run T1 and check that mutations with `outcome: REJECTED` correctly show exit code 101 (not a crash or other error). Hook 3 should NOT interfere with proof generation or verification.

---

## What This Does NOT Include (Deferred)

- **Bandit reward integration** (Phase 5c from master plan): G_new/G_rare reward components are NOT included in this implementation. They require a design decision (Option A vs B vs C) and significant changes to `coverage_state.py` and `bandit.py`. Deferred to a subsequent phase.
- **Database integration** (Phase 5d): Storing global data in SQLite. Deferred.
- **Hook 1 activation**: NOT included per user request.
- **Hook 2 / circuit_debug**: NOT included per user request.

---

## Files to Modify

| File | Changes |
|------|---------|
| [a4/core/executor.py](a4/core/executor.py) | Add `A4_FAMILY_RESIDUE=1` env var, add fields to `MutationExecutionResult`, parse Hook 3 tags |
| [a4/standalone/fuzzer.py](a4/standalone/fuzzer.py) | Add global fields to `MutationResult`, update `_print_mutation_result` for global display, separate local/accum failures, update status line, update `CampaignStats` |

No C++ changes needed -- Hook 3 is already fully implemented in `ffi.cpp`.
No new Python parsing code needed -- `parse_family_residues` and `parse_family_detail` already exist in `touch_coverage.py`.

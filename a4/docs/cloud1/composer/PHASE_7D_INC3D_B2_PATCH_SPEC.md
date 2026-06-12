# Phase 7d Inc 3d Phase B2 — Memory-record fingerprint patch (B4)

**Goal:** Pinpoint the exact cycle where memory operations first diverge between paired runs (A vs B). This is the LAST piece of instrumentation needed to determine the race root cause.

**Background:** Phase B1+B2+B3 proved the race is real. New finding: `<a4_family_residue>` for the memory family differs between A and B on **45–48 out of 50 mutations** in every pair (Pass 1 and Pass 2 alike), not just on the visibly racy mutations. This means the executor is doing different memory work on every run, but most differences cancel out before they reach visible constraint failures.

The B4 patch dumps a per-cycle FNV-1a 64-bit fingerprint of all recorded memory transactions, so we can diff A vs B and pinpoint the exact cycle range where divergence begins.

---

## Patch (already applied to `arguzz/b7-race-instrumentation`)

### `ffi.cpp` — single addition right after the existing `emit("memory", res_memory)` call

```cpp
// B4 (Inc 3d Phase B2): memory-record fingerprinting for race localization.
if (std::getenv("A4_MEM_FINGERPRINT") != nullptr) {
  std::map<uint32_t, uint64_t> per_cycle_hash;
  std::map<uint32_t, uint32_t> per_cycle_count;
  uint64_t total_hash = 0xcbf29ce484222325ULL;
  auto fnv_mix32 = [](uint64_t h, uint32_t v) -> uint64_t {
    for (int b = 0; b < 4; b++) {
      h ^= ((v >> (b * 8)) & 0xff);
      h *= 0x100000001b3ULL;
    }
    return h;
  };
  for (const auto& rec : g_a4_memory_records) {
    uint64_t rh = 0xcbf29ce484222325ULL;
    rh = fnv_mix32(rh, rec.addr);
    rh = fnv_mix32(rh, rec.cycle);
    rh = fnv_mix32(rh, rec.dataLow);
    rh = fnv_mix32(rh, rec.dataHigh);
    rh = fnv_mix32(rh, rec.count);
    per_cycle_hash[rec.cycle] ^= rh;
    per_cycle_count[rec.cycle]++;
    total_hash ^= rh;
  }
  std::printf("<a4_mem_total_hash records=\"%zu\" hash=\"%016llx\"/>\n",
              g_a4_memory_records.size(), (unsigned long long)total_hash);
  for (auto& kv : per_cycle_hash) {
    std::printf("<a4_mem_cycle_hash cycle=\"%u\" count=\"%u\" hash=\"%016llx\"/>\n",
                kv.first, per_cycle_count[kv.first], (unsigned long long)kv.second);
  }
  std::fflush(stdout);
}
```

### `executor.py` passthrough — updated to re-emit the new tags

Already done in `a4/core/executor.py`:
- Added `<a4_mem_total_hash[^>]*/>` and `<a4_mem_cycle_hash[^>]*/>` to `_A4_DIAG_LINE_RE`
- Added `passthrough_mem = os.environ.get("A4_MEM_FINGERPRINT") == "1"` gate

---

## Build cost

Single source file changed (`ffi.cpp`). `steps.cpp` not touched. Expected incremental rebuild: **~5–10 minutes** (not 60 like the original B1+B2+B3 build).

Build command (same as before):

```bash
cd /root/arguzz/workspace/output
cargo build --release --bin risc0-host
```

After build, the new host SHA will differ — write it down and update bundle metadata accordingly.

---

## What the patch outputs

For every host invocation with `A4_MEM_FINGERPRINT=1` AND `A4_FAMILY_RESIDUE=1`:

```
<a4_mem_total_hash records="69448" hash="abc123def456789a"/>
<a4_mem_cycle_hash cycle="0" count="64" hash="..."/>
<a4_mem_cycle_hash cycle="1" count="128" hash="..."/>
<a4_mem_cycle_hash cycle="2" count="128" hash="..."/>
...
<a4_mem_cycle_hash cycle="40686" count="3" hash="..."/>
```

Roughly: 1 `total_hash` + ~40,000 `cycle_hash` lines per mutation, ~50 mutations per campaign = ~2M extra lines per log. At ~80 bytes/line that's ~150 MB per log. **Plan for larger log volume** than even Pass 1.

(If this proves too large, we can later add `A4_MEM_FP_USTRIDE=N` to subsample, but for the first run we want everything.)

---

## What to look for in the output

For each pair (A vs B), Opus will compute:

1. `total_hash` differs → confirms records differ overall (already established at residue level)
2. Per-cycle: find FIRST cycle where `cycle_hash` differs between A and B
3. Find LAST cycle where A and B agree
4. Map those cycles to userCycle range (cross-reference with `<a4_ftw>` data already in Pass 1 logs)

If the divergence cycle aligns with userCycle 3929 for flare mut 30 (the racy one we already know), root cause is in trace generation at that user cycle.

If the divergence is pervasive (every cycle differs), root cause is upstream in executor scheduling itself.

---

## Notes

- The XOR-combine within each cycle bucket means record ORDER within a cycle doesn't affect the hash. Witgen is sequential anyway, so this matters only for robustness — same records in same cycle should produce same hash regardless of insertion order.
- `total_hash` is XOR of all per-record hashes, which is also order-independent. If `total_hash` differs but no `cycle_hash` differs, that would indicate a bug in the patch (impossible by construction — XOR-combine is associative).
- `A4_MEM_FINGERPRINT=1` is INDEPENDENT of `A4_COVERAGE_TOUCH_VERBOSE` and `A4_FTW291_TRACE`. They can be combined or used in isolation.

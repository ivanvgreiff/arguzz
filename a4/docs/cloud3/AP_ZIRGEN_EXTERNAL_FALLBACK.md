# AP.B2 — External Zirgen Codegen Fallback

If in-box Bazel fails (conda flexible-solve, OOM on 11 GiB during LLVM link), build offline on a beefier host and vendor-copy OUTS.

## What you need back (~20 files)

Copy into `workspace/risc0-modified`:

| Path | Files |
|------|-------|
| `risc0/circuit/rv32im/src/zirgen/` | `poly_ext.rs`, `info.rs`, `taps.rs`, `layout.rs.inc`, … |
| `risc0/circuit/rv32im-sys/kernels/cxx/` | `steps.cpp`, `rust_poly_fp_{0..3}.cpp`, `steps.h`, `layout.*.inc` |
| `risc0/circuit/rv32im-sys/kernels/cuda/` | `steps.cu`, `steps.cuh`, `eval_check_{0..3}.cu`, `eval_check.cuh`, `layout.*.inc` |

**Do NOT overwrite:** `ffi.cpp`, `witgen.h`, `eval_check.cpp`, `rv32im/src/prove/witgen/mod.rs`

## On external host

```bash
git clone https://github.com/risc0/zirgen.git && cd zirgen
git checkout df6fb9dda1c20209058d6ee90a8912351b741081

# Holed .zir edits (AP IsRead hole):
#   mem.zir: add MemoryReadNoIsRead (no IsRead)
#   inst.zir: ReadReg -> MemoryReadNoIsRead

# Optional: skip conda if only building C++ targets
bash a4/scripts/ap_zirgen_conda_prune.sh apply   # from arguzz checkout

## In-box build (this WSL environment)

```bash
# 1. Skip conda (gen_zirgen is C++ only)
bash a4/scripts/ap_zirgen_conda_prune.sh apply

# 2. Build with WSL sandbox workaround
USE_BAZEL_VERSION=6.0.0 bazelisk build --config=bootstrap_linux_amd64 \
  --spawn_strategy=local --genrule_strategy=local \
  //zirgen/circuit/rv32im/v2/dsl:codegen

# Restore WORKSPACE when done:
bash a4/scripts/ap_zirgen_conda_prune.sh restore
```

**11 GiB RAM:** LLVM link may OOM; prefer external host if build fails mid-link.

# Or bootstrap install:
cd zirgen/bootstrap && cargo run --release -- rv32im-v2 --output /path/to/risc0-modified
```

## Pack and transfer

```bash
tar czf rv32im_v2_outs_holed.tgz -C risc0-modified \
  risc0/circuit/rv32im/src/zirgen \
  risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp \
  risc0/circuit/rv32im-sys/kernels/cxx/rust_poly_fp_*.cpp \
  risc0/circuit/rv32im-sys/kernels/cuda/steps.cu \
  risc0/circuit/rv32im-sys/kernels/cuda/eval_check_*.cu
# scp rv32im_v2_outs_holed.tgz user@this-box:/root/arguzz/
```

## On this box after transfer

```bash
# Extract to risc0-modified (preserve harness files)
tar xzf rv32im_v2_outs_holed.tgz -C workspace/risc0-modified

# Snapshot for build script
bash a4/scripts/ap_zirgen_regen.sh  # or manual snapshot to regen-snapshots/holed-*

bash a4/scripts/build_ap_binaries.sh --from-regen
python3 a4/scripts/ap_b1_verify.py
```

## Control + holed pair (Option B)

Need **two** codegen runs:
1. **Control:** unmodified `.zir` → snapshot `regen-snapshots/control-*`
2. **Holed:** `MemoryReadNoIsRead` `.zir` → snapshot `regen-snapshots/holed-*`

Or build both on external host and scp both tarballs.

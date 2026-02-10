"""
A4 Patch for risc0/circuit/rv32im/src/prove/hal/mod.rs

This patch forces sequential witness generation when A4_MUTATION_CONFIG is set.

Without this, parallel execution causes SIGSEGV crashes because:
1. A4 mutation corrupts transaction data
2. Other threads continue processing with corrupted data
3. Buffer indices become invalid, causing out-of-bounds memory access

The fix ensures single-threaded execution for A4 mutations while preserving
parallel execution for normal (non-mutated) runs.
"""

# Original code pattern to find
SEARCH_PATTERN = '''        cfg_if::cfg_if! {
            if #[cfg(feature = "witgen_debug")] {
                let mode = if std::env::var_os("RISC0_WITGEN_DEBUG").is_some() {
                    StepMode::SeqForward
                } else {
                    StepMode::Parallel
                };
            } else {
                let mode = StepMode::Parallel;
            }
        }'''

# Replacement with A4 sequential mode
REPLACE_PATTERN = '''        // A4: Force sequential mode when A4_MUTATION_CONFIG is set to avoid SIGSEGV
        // from parallel thread corruption. Original RISC0_WITGEN_DEBUG requires
        // compile-time feature flag, but A4 mutations need this always.
        let mode = if std::env::var_os("A4_MUTATION_CONFIG").is_some() {
            StepMode::SeqForward
        } else {
            cfg_if::cfg_if! {
                if #[cfg(feature = "witgen_debug")] {
                    if std::env::var_os("RISC0_WITGEN_DEBUG").is_some() {
                        StepMode::SeqForward
                    } else {
                        StepMode::Parallel
                    }
                } else {
                    StepMode::Parallel
                }
            }
        };'''


def get_patch():
    """Return the patch specification for hal/mod.rs"""
    return {
        'search': SEARCH_PATTERN,
        'replace': REPLACE_PATTERN,
        'description': 'hal/mod.rs: Force sequential mode for A4'
    }


# For checking if already patched
PATCH_MARKERS = [
    "A4: Force sequential mode",
    "A4_MUTATION_CONFIG",
]

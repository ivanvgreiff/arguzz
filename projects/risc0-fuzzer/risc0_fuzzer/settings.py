from risc0_fuzzer.kinds import InjectionKind, InstrKind

#
# ZKVM Specific Versions and URLs
#

RISC0_AVAILABLE_COMMITS_OR_BRANCHES = [
    "main",
    "ebd64e43e7d953e0edcee2d4e0225b75458d80b5",
    # Title: ZKVM-1392: Disallow memory I/O to same address in the same memory cycle #3181
    # Links:
    #   - https://github.com/risc0/risc0/pull/3181)
    #   - https://github.com/risc0/risc0/security/advisories/GHSA-g3qg-6746-3mg9)
    # Type: soundness / injection
    "67f2d81c638bff5f4fcfe11a084ebb34799b7a89",  # <= fix
    "98387806fe8348d87e32974468c6f35853356ad5",  # <= bug
    # Title: ZKVM-1260: Account for missing ControlDone cycle in executor #3015
    # Links:
    #   - https://github.com/risc0/risc0/pull/3015)
    # Type: completeness / fuzzer
    "31f657014488940913e3ced0367610225ab32ada",  # <= fix
    "4c65c85a1ec6ce7df165ef9c57e1e13e323f7e01",  # <= bug
]
RISC0_ZKVM_GIT_REPOSITORY = "https://github.com/DanielHoffmann91/risc0.git"
RUST_TOOLCHAIN_VERSION = "1.85.0"
RISC0_PROVER = "local"  # "ipc", "bonsai"
GLOBAL_FAULT_INJECTION_ENV_KEY = "FAULT_INJECTION_ENABLED"
CONSTRAINT_TRACE_ENV_KEY = "CONSTRAINT_TRACE_ENABLED"
CONSTRAINT_CONTINUE_ENV_KEY = "CONSTRAINT_CONTINUE"

#
# Rust Magic Values
#

RUST_GUEST_RETURN_TYPE = "u32"
RUST_GUEST_CORRECT_VALUE = 0xDEADBEEF

#
# Flag to decide if division and modulo of 0 should be transformed
#

APPLY_SAFE_REM_DIV_TRANSFORMATION = True

#
# Special Timeout handling
#

TIMEOUT_PER_RUN = 60 * 4  # 4 min, in seconds
TIMEOUT_PER_BUILD = 60 * 60 * 2  # 2 h  , in seconds

#
# Injection Specifics
#

ENABLED_INJECTION_KINDS: list[InjectionKind] = [
    InjectionKind.PRE_EXEC_PC_MOD,
    InjectionKind.POST_EXEC_PC_MOD,
    InjectionKind.INSTR_WORD_MOD,
    InjectionKind.BR_NEG_COND,
    InjectionKind.COMP_OUT_MOD,
    InjectionKind.LOAD_VAL_MOD,
    InjectionKind.STORE_OUT_MOD,
    InjectionKind.PRE_EXEC_MEM_MOD,
    InjectionKind.POST_EXEC_MEM_MOD,
    InjectionKind.PRE_EXEC_REG_MOD,
    InjectionKind.POST_EXEC_REG_MOD,
]

# NOTE: empty list disables preferences
PREFERRED_INSTRUCTIONS: list[InstrKind] = []

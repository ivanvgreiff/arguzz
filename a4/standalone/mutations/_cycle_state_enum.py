"""CycleState enum extracted from platform.rs (Batch 1.0b, Q15)."""

from __future__ import annotations

# Source: workspace/risc0-modified/risc0/circuit/rv32im/src/execute/platform.rs
# Commit: cloud2 HEAD at Batch 1 implementation time
CYCLE_STATE = {
    "LoadRootAndNonce": 0,
    "Resume": 1,
    "Suspend": 4,
    "StoreRoot": 5,
    "ControlTable": 6,
    "ControlDone": 7,
    "MachineEcall": 8,
    "Terminate": 9,
    "HostReadSetup": 10,
    "HostWrite": 11,
    "HostReadBytes": 12,
    "HostReadWords": 13,
    "PoseidonEntry": 16,
    "PoseidonLoadState": 17,
    "PoseidonLoadIn": 18,
    "PoseidonDoOut": 21,
    "PoseidonPaging": 22,
    "PoseidonStoreState": 23,
    "PoseidonExtRound": 24,
    "PoseidonIntRound": 25,
    "ShaEcall": 32,
    "ShaLoadState": 33,
    "ShaLoadData": 34,
    "ShaMix": 35,
    "ShaStoreState": 36,
    "BigIntEcall": 40,
    "BigIntStep": 41,
    "Decode": 48,
}

CYCLE_STATE_BY_NAME = CYCLE_STATE

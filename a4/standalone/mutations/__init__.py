"""
Standalone A4 Mutations

Clean mutation implementations for standalone fuzzing.
These are independent of Arguzz and designed for autonomous fuzzing campaigns.

Each module provides:
- Target dataclass (e.g., CompOutModTarget)
- get_targets_at_step(step, data) -> Optional[Target] or List[Target]
- create_config(target, mutated_value, output_path) -> Path

Supported mutation kinds:
- COMP_OUT_MOD: Mutate compute instruction output (register write)
- LOAD_VAL_MOD: Mutate load instruction output (register write)
- STORE_OUT_MOD: Mutate store instruction output (memory write)
- PRE_EXEC_REG_MOD: Mutate register read/write transactions
- INSTR_TYPE_MOD: Mutate instruction type (major/minor)
- MEM_VAL_MOD: Mutate memory transaction values (non-register, non-instruction-fetch)
- INSTR_WORD_MOD: Mutate instruction fetch word (fills gap excluded by MEM_VAL_MOD)
"""

from a4.standalone.mutations.comp_out_mod import (
    CompOutModTarget,
    get_targets_at_step as get_comp_out_targets,
    create_config as create_comp_out_config,
)

from a4.standalone.mutations.load_val_mod import (
    LoadValModTarget,
    get_targets_at_step as get_load_val_targets,
    create_config as create_load_val_config,
)

from a4.standalone.mutations.store_out_mod import (
    StoreOutModTarget,
    get_targets_at_step as get_store_out_targets,
    create_config as create_store_out_config,
)

from a4.standalone.mutations.pre_exec_reg_mod import (
    PreExecRegModTarget,
    get_targets_at_step as get_pre_exec_reg_targets,
    create_config as create_pre_exec_reg_config,
)

from a4.standalone.mutations.instr_type_mod import (
    InstrTypeModTarget,
    get_targets_at_step as get_instr_type_targets,
    create_config as create_instr_type_config,
)

from a4.standalone.mutations.mem_val_mod import (
    MemValModTarget,
    get_targets_at_step as get_mem_val_targets,
    create_config as create_mem_val_config,
    get_valid_steps as get_mem_val_valid_steps,
)

from a4.standalone.mutations.instr_word_mod import (
    InstrWordModTarget,
    get_targets_at_step as get_instr_word_targets,
    create_config as create_instr_word_config,
    get_valid_steps as get_instr_word_valid_steps,
)

from a4.standalone.mutations.txn_prev_word_mod import (
    TxnPrevWordModTarget,
    get_targets_at_step as get_txn_prev_word_targets,
    create_config as create_txn_prev_word_config,
)

from a4.standalone.mutations.txn_prev_cycle_mod import (
    TxnPrevCycleModTarget,
    get_targets_at_step as get_txn_prev_cycle_targets,
    create_config as create_txn_prev_cycle_config,
)

from a4.standalone.mutations.cycle_mode_mod import (
    CycleModeModTarget,
    get_targets_at_step as get_cycle_mode_targets,
    create_config as create_cycle_mode_config,
)

__all__ = [
    # COMP_OUT_MOD
    'CompOutModTarget',
    'get_comp_out_targets',
    'create_comp_out_config',
    # LOAD_VAL_MOD  
    'LoadValModTarget',
    'get_load_val_targets',
    'create_load_val_config',
    # STORE_OUT_MOD
    'StoreOutModTarget',
    'get_store_out_targets',
    'create_store_out_config',
    # PRE_EXEC_REG_MOD
    'PreExecRegModTarget',
    'get_pre_exec_reg_targets',
    'create_pre_exec_reg_config',
    # INSTR_TYPE_MOD
    'InstrTypeModTarget',
    'get_instr_type_targets',
    'create_instr_type_config',
    # MEM_VAL_MOD
    'MemValModTarget',
    'get_mem_val_targets',
    'create_mem_val_config',
    'get_mem_val_valid_steps',
    # INSTR_WORD_MOD
    'InstrWordModTarget',
    'get_instr_word_targets',
    'create_instr_word_config',
    'get_instr_word_valid_steps',
    # TXN_PREV_WORD_MOD
    'TxnPrevWordModTarget',
    'get_txn_prev_word_targets',
    'create_txn_prev_word_config',
    # TXN_PREV_CYCLE_MOD
    'TxnPrevCycleModTarget',
    'get_txn_prev_cycle_targets',
    'create_txn_prev_cycle_config',
    # CYCLE_MODE_MOD
    'CycleModeModTarget',
    'get_cycle_mode_targets',
    'create_cycle_mode_config',
]

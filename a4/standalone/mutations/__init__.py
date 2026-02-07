"""
Standalone A4 Mutations

Clean mutation implementations for standalone fuzzing.
These are independent of Arguzz and designed for autonomous fuzzing campaigns.

Each module provides:
- Target dataclass (e.g., CompOutModTarget)
- get_targets_at_step(step, data) -> Optional[Target]
- create_config(target, mutated_value, output_path) -> Path

Supported mutation kinds:
- COMP_OUT_MOD: Mutate compute instruction output (register write)
- LOAD_VAL_MOD: Mutate load instruction output (register write)
- STORE_OUT_MOD: Mutate store instruction output (memory write)
- PRE_EXEC_REG_MOD: Mutate register read/write transactions
- INSTR_TYPE_MOD: Mutate instruction type (major/minor)
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
]

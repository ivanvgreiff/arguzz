"""
A4 Arguzz-Dependent Mutations

Mutation implementations with Arguzz wrappers.
These modules contain find_mutation_target(arguzz_fault, ...) functions
that map Arguzz faults to A4 mutation targets.

For standalone mutations without Arguzz dependencies, see standalone/mutations/.
"""

from a4.arguzz_dependent.mutations.instr_type_mod import (
    MutationTarget as InstrTypeMutationTarget,
    find_mutation_target as find_instr_type_target,
    create_config as create_instr_type_config,
)

from a4.arguzz_dependent.mutations.comp_out_mod import (
    CompOutModTarget,
    find_mutation_target as find_comp_out_target,
    create_config as create_comp_out_config,
    run_full_inspection as run_comp_out_inspection,
)

from a4.arguzz_dependent.mutations.load_val_mod import (
    LoadValModTarget,
    find_mutation_target as find_load_val_target,
    create_config as create_load_val_config,
    run_full_inspection as run_load_val_inspection,
)

from a4.arguzz_dependent.mutations.store_out_mod import (
    StoreOutModTarget,
    find_mutation_target as find_store_out_target,
    create_config as create_store_out_config,
    run_full_inspection as run_store_out_inspection,
)

from a4.arguzz_dependent.mutations.pre_exec_reg_mod import (
    PreExecRegModTarget,
    find_mutation_target as find_pre_exec_reg_target,
    create_config as create_pre_exec_reg_config,
    run_full_inspection as run_pre_exec_reg_inspection,
)

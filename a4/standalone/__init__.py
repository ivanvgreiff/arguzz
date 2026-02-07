"""
A4 Standalone Fuzzing

Autonomous fuzzing of RISC Zero PreflightTrace without Arguzz dependency.

Main components:
- fuzzer.py: A4Fuzzer orchestrator
- coverage_db.py: SQLite coverage tracking
- step_selector.py: Step selection strategies
- value_generator.py: Value mutation strategies
- mutations/: Mutation implementations by kind

Usage:
    from a4.standalone import A4Fuzzer
    
    with A4Fuzzer(host_binary, host_args, db_path) as fuzzer:
        stats = fuzzer.run_campaign(num_mutations=100)

CLI:
    python -m a4.standalone.cli fuzz --host ./risc0-host --num 100 -- program arg
"""

from a4.standalone.fuzzer import A4Fuzzer, MutationResult, CampaignStats
from a4.standalone.coverage_db import CoverageDB, CampaignInfo, MutationRecord
from a4.standalone.step_selector import (
    StepSelector, RandomStepSelector, HeuristicStepSelector,
    GuidedStepSelector, SequentialStepSelector, create_selector
)
from a4.standalone.value_generator import (
    ValueGenerator, RandomValueGenerator, BitFlipValueGenerator,
    BoundaryValueGenerator, ArithmeticValueGenerator, SmartValueGenerator,
    CompositeValueGenerator, create_generator
)

__all__ = [
    # Fuzzer
    'A4Fuzzer',
    'MutationResult',
    'CampaignStats',
    # Coverage DB
    'CoverageDB',
    'CampaignInfo',
    'MutationRecord',
    # Step selectors
    'StepSelector',
    'RandomStepSelector',
    'HeuristicStepSelector',
    'GuidedStepSelector',
    'SequentialStepSelector',
    'create_selector',
    # Value generators
    'ValueGenerator',
    'RandomValueGenerator',
    'BitFlipValueGenerator',
    'BoundaryValueGenerator',
    'ArithmeticValueGenerator',
    'SmartValueGenerator',
    'CompositeValueGenerator',
    'create_generator',
]

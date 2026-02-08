"""
Value Generation Strategies for Standalone A4 Fuzzing

Different strategies for generating mutated values:
- RandomValueGenerator: Fully random 32-bit values
- BitFlipValueGenerator: Flip random bits in original value
- BoundaryValueGenerator: Use boundary values (0, 1, -1, MAX, etc.)
- SmartValueGenerator: Context-aware mutations based on instruction type

The generate_different() method ensures the mutated value is always
different from the original, raising ValueGeneratorExhaustedError if
retries are exhausted (indicates a bug).
"""

import random
from abc import ABC, abstractmethod
from typing import List, Optional, Tuple

__all__ = [
    'ValueGenerator',
    'ValueGeneratorExhaustedError',
    'RandomValueGenerator',
    'BitFlipValueGenerator',
    'BoundaryValueGenerator',
    'ArithmeticValueGenerator',
    'SmartValueGenerator',
    'CompositeValueGenerator',
    'create_generator',
]


class ValueGeneratorExhaustedError(Exception):
    """Raised when generate_different() exhausts retries without finding a different value"""
    pass


class ValueGenerator(ABC):
    """Abstract base class for value generation strategies"""
    
    @abstractmethod
    def generate(self, original_value: int, context: dict = None) -> int:
        """
        Generate a mutated value.
        
        Args:
            original_value: The original value being mutated
            context: Optional context (major, minor, register, etc.)
            
        Returns:
            Mutated value (32-bit unsigned)
        """
        pass
    
    def generate_different(
        self, 
        original_value: int, 
        context: dict = None, 
        max_retries: int = 10
    ) -> int:
        """
        Generate a value guaranteed to be different from the original.
        
        Retries up to max_retries times. If all retries produce the same
        value as original, raises ValueGeneratorExhaustedError.
        
        Args:
            original_value: The original value being mutated
            context: Optional context (major, minor, register, etc.)
            max_retries: Maximum number of generation attempts
            
        Returns:
            Mutated value (32-bit unsigned) that is different from original_value
            
        Raises:
            ValueGeneratorExhaustedError: If max_retries exhausted without
                finding a different value. This indicates a bug in the
                generator or seed configuration.
        """
        for attempt in range(max_retries):
            value = self.generate(original_value, context)
            if value != original_value:
                return value
        
        # This should be extremely rare - indicates a bug
        raise ValueGeneratorExhaustedError(
            f"Value generator exhausted {max_retries} retries without producing "
            f"a value different from {original_value} (0x{original_value:08X}). "
            f"This indicates a bug in the generator or seed configuration."
        )


class RandomValueGenerator(ValueGenerator):
    """
    Fully random value generation.
    
    Generates uniformly random 32-bit values, ignoring the original.
    Simple but effective for finding unexpected edge cases.
    """
    
    def __init__(self, seed: Optional[int] = None):
        self.rng = random.Random(seed)
    
    def generate(self, original_value: int, context: dict = None) -> int:
        return self.rng.randint(0, 0xFFFFFFFF)


class BitFlipValueGenerator(ValueGenerator):
    """
    Bit-flip based mutation.
    
    Flips 1-31 random bits in the original value (matching Arguzz's selector 4).
    Good for testing single-bit errors and multi-bit corruption scenarios.
    
    Arguzz's random_mod_of_u32() uses: rng.random_range(1..=31) for number of bits.
    """
    
    def __init__(self, seed: Optional[int] = None, max_flips: int = 31):
        self.rng = random.Random(seed)
        self.max_flips = min(max_flips, 31)  # Cap at 31 (all bits except one)
    
    def generate(self, original_value: int, context: dict = None) -> int:
        # Match Arguzz: flip 1 to max_flips random bits
        num_flips = self.rng.randint(1, self.max_flips)
        result = original_value
        
        # Select unique bit positions to flip (like Arguzz's index::sample)
        bits_to_flip = self.rng.sample(range(32), num_flips)
        for bit in bits_to_flip:
            result ^= (1 << bit)
        
        return result & 0xFFFFFFFF


class BoundaryValueGenerator(ValueGenerator):
    """
    Boundary value generation.
    
    Uses values known to cause edge cases:
    - 0, 1, -1 (0xFFFFFFFF)
    - MAX_INT, MIN_INT
    - Powers of 2
    - Byte boundaries
    """
    
    # Standard boundary values
    # These match Arguzz's random_mod_of_u32() strategies plus additional edge cases
    BOUNDARIES = [
        0,                  # Zero (Arguzz selector 0)
        1,                  # One (Arguzz selector 1)
        0xFFFFFFFF,         # -1 / unsigned max (Arguzz selector 2)
        0xFFFFFFFE,         # Max - 1 (Arguzz selector 3)
        0x7FFFFFFF,         # INT_MAX (signed)
        0x80000000,         # INT_MIN (signed)
        0xFF,               # Byte max
        0x100,              # Byte overflow
        0xFFFF,             # Halfword max
        0x10000,            # Halfword overflow
        0x7FFF,             # Short max (signed)
        0x8000,             # Short min (signed)
    ]
    
    # Powers of 2
    POWERS_OF_2 = [1 << i for i in range(32)]
    
    def __init__(self, seed: Optional[int] = None):
        self.rng = random.Random(seed)
        self.all_values = self.BOUNDARIES + self.POWERS_OF_2
    
    def generate(self, original_value: int, context: dict = None) -> int:
        return self.rng.choice(self.all_values)


class ArithmeticValueGenerator(ValueGenerator):
    """
    Arithmetic-based mutation.
    
    Applies arithmetic operations to the original value:
    - Add/subtract small values
    - Multiply/divide
    - Negate
    """
    
    def __init__(self, seed: Optional[int] = None):
        self.rng = random.Random(seed)
    
    def generate(self, original_value: int, context: dict = None) -> int:
        operation = self.rng.choice(['add', 'sub', 'mul', 'neg', 'not'])
        
        if operation == 'add':
            delta = self.rng.choice([1, 2, 4, 8, 16, 256, 65536])
            return (original_value + delta) & 0xFFFFFFFF
        elif operation == 'sub':
            delta = self.rng.choice([1, 2, 4, 8, 16, 256, 65536])
            return (original_value - delta) & 0xFFFFFFFF
        elif operation == 'mul':
            factor = self.rng.choice([2, 3, 4, 8, 16])
            return (original_value * factor) & 0xFFFFFFFF
        elif operation == 'neg':
            return (-original_value) & 0xFFFFFFFF
        else:  # not
            return (~original_value) & 0xFFFFFFFF


class SmartValueGenerator(ValueGenerator):
    """
    Context-aware value generation.
    
    Uses instruction context to generate more targeted mutations:
    - For loads/stores: Generate aligned/unaligned addresses
    - For branches: Generate values to flip branch conditions
    - For arithmetic: Generate overflow-inducing values
    """
    
    def __init__(self, seed: Optional[int] = None):
        self.rng = random.Random(seed)
        self.fallback = RandomValueGenerator(seed)
    
    def generate(self, original_value: int, context: dict = None) -> int:
        if context is None:
            return self.fallback.generate(original_value)
        
        major = context.get('major', -1)
        minor = context.get('minor', -1)
        
        # Memory operations (major 5-6): try misaligned addresses
        if major in (5, 6):
            return self._generate_for_memory(original_value)
        
        # Branch/compare operations (major 1-2): try branch-flipping values
        if major in (1, 2):
            return self._generate_for_branch(original_value, context)
        
        # Arithmetic (major 0, 3, 4): try overflow values
        if major in (0, 3, 4):
            return self._generate_for_arithmetic(original_value)
        
        return self.fallback.generate(original_value)
    
    def _generate_for_memory(self, original_value: int) -> int:
        """Generate values for memory operations"""
        strategies = [
            # Misalign by 1, 2, or 3 bytes
            lambda v: (v + self.rng.choice([1, 2, 3])) & 0xFFFFFFFF,
            # Large address change
            lambda v: self.rng.randint(0, 0xFFFFFFFF),
            # Boundary addresses
            lambda v: self.rng.choice([0, 0xFFFFFFFC, 0x80000000]),
        ]
        return self.rng.choice(strategies)(original_value)
    
    def _generate_for_branch(self, original_value: int, context: dict) -> int:
        """Generate values to flip branch conditions"""
        strategies = [
            # Flip sign
            lambda v: (-v) & 0xFFFFFFFF,
            # Make zero/non-zero
            lambda v: 0 if v != 0 else 1,
            # Boundary crossing
            lambda v: 0x7FFFFFFF if v < 0x80000000 else 0x80000000,
        ]
        return self.rng.choice(strategies)(original_value)
    
    def _generate_for_arithmetic(self, original_value: int) -> int:
        """Generate values for arithmetic overflow"""
        strategies = [
            # Near overflow
            lambda v: 0x7FFFFFFF,
            lambda v: 0x80000000,
            lambda v: 0xFFFFFFFF,
            # Small perturbation
            lambda v: (v + 1) & 0xFFFFFFFF,
            lambda v: (v - 1) & 0xFFFFFFFF,
        ]
        return self.rng.choice(strategies)(original_value)


class CompositeValueGenerator(ValueGenerator):
    """
    Combines multiple generators with configurable weights.
    
    Allows mixing strategies for better coverage.
    """
    
    def __init__(
        self, 
        generators: List[Tuple[ValueGenerator, float]],
        seed: Optional[int] = None
    ):
        """
        Initialize with weighted generators.
        
        Args:
            generators: List of (generator, weight) tuples
            seed: Random seed for selection
        """
        self.generators = [g for g, _ in generators]
        self.weights = [w for _, w in generators]
        self.rng = random.Random(seed)
    
    def generate(self, original_value: int, context: dict = None) -> int:
        generator = self.rng.choices(self.generators, weights=self.weights, k=1)[0]
        return generator.generate(original_value, context)


def create_generator(
    strategy: str, 
    seed: Optional[int] = None
) -> ValueGenerator:
    """
    Factory function to create a value generator.
    
    Args:
        strategy: One of "random", "bitflip", "boundary", "arithmetic", 
                  "smart", "mixed"
        seed: Random seed for reproducibility
        
    Returns:
        Configured ValueGenerator instance
    """
    if strategy == "random":
        return RandomValueGenerator(seed)
    elif strategy == "bitflip":
        return BitFlipValueGenerator(seed)
    elif strategy == "boundary":
        return BoundaryValueGenerator(seed)
    elif strategy == "arithmetic":
        return ArithmeticValueGenerator(seed)
    elif strategy == "smart":
        return SmartValueGenerator(seed)
    elif strategy == "mixed":
        # Default mixed strategy with good coverage
        return CompositeValueGenerator([
            (RandomValueGenerator(seed), 0.3),
            (BitFlipValueGenerator(seed), 0.3),
            (BoundaryValueGenerator(seed), 0.2),
            (ArithmeticValueGenerator(seed), 0.2),
        ], seed)
    else:
        raise ValueError(f"Unknown strategy: {strategy}")

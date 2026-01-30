import json
import logging
import re
from typing import Any, Generic, Type

from zkvm_fuzzer_utils.cmd import ExecStatus
from zkvm_fuzzer_utils.kinds import InjectionKind, InstrKind

logger = logging.getLogger("fuzzer")


# ---------------------------------------------------------------------------- #
#                               Single Trace Step                              #
# ---------------------------------------------------------------------------- #


class TraceStep(Generic[InstrKind]):
    __step: int
    __pc: int
    __instruction: InstrKind
    __assembly: str

    def __init__(self, step: int, pc: int, instruction: InstrKind, assembly: str):
        self.__step = step
        self.__pc = pc
        self.__instruction = instruction
        self.__assembly = assembly

    def __str__(self) -> str:
        return self.__repr__()

    def __repr__(self):
        return (
            f"TraceStep(step={self.__step}, "
            f"pc={self.__pc}, instruction={self.__instruction}, "
            f'assembly="{self.__assembly}")'
        )

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, TraceStep):
            return (
                self.__step == other.__step
                and self.__pc == other.__pc
                and self.__instruction == other.__instruction
                and self.__assembly == other.__assembly
            )
        return False

    def __hash__(self) -> int:
        h1 = hash(self.__step)
        h2 = hash(self.__pc)
        h3 = hash(self.__instruction)
        h4 = hash(self.__assembly)
        result = h1 * 31 + h2 * 37 + h3 * 41 + h4 * 43
        result ^= result >> 16
        result *= 0x45D9F3B
        result ^= result >> 16
        return result

    @property
    def step(self) -> int:
        return self.__step

    @property
    def pc(self) -> int:
        return self.__pc

    @property
    def instruction_as_str(self) -> str:
        return self.__instruction.value

    @property
    def instruction(self) -> InstrKind:
        return self.__instruction

    @property
    def assembly(self) -> str:
        return self.__assembly

    @classmethod
    def from_json(cls, data: str, instr_kind_enum: Type[InstrKind]) -> "TraceStep":
        trace_step_dict = json.loads(data)
        step = int(trace_step_dict["step"])
        pc = int(trace_step_dict["pc"])
        instruction = instr_kind_enum(
            trace_step_dict["instruction"].lower().replace("_", "").replace(".", "")
        )
        assembly = re.sub(r"\s+", " ", trace_step_dict["assembly"])
        return TraceStep(step, pc, instruction, assembly)


# ---------------------------------------------------------------------------- #
#                                  Trace Fault                                 #
# ---------------------------------------------------------------------------- #


# ---------------------------------------------------------------------------- #
#                              Constraint Failure                              #
# ---------------------------------------------------------------------------- #


class ConstraintFailure:
    """Represents a constraint that failed during witness generation (Phase 1)."""
    __cycle: int
    __loc: str
    __value: int

    def __init__(self, cycle: int, loc: str, value: int):
        self.__cycle = cycle
        self.__loc = loc
        self.__value = value

    def __str__(self) -> str:
        return self.__repr__()

    def __repr__(self):
        return (
            f"ConstraintFailure(cycle={self.__cycle}, "
            f'loc="{self.__loc}", value={self.__value})'
        )

    def __eq__(self, other) -> bool:
        if isinstance(other, ConstraintFailure):
            return (
                self.__cycle == other.__cycle
                and self.__loc == other.__loc
                and self.__value == other.__value
            )
        return False

    def __hash__(self) -> int:
        h1 = hash(self.__cycle)
        h2 = hash(self.__loc)
        h3 = hash(self.__value)
        result = h1 * 31 + h2 * 37 + h3 * 41
        result ^= result >> 16
        result *= 0x45D9F3B
        result ^= result >> 16
        return result

    @property
    def cycle(self) -> int:
        return self.__cycle

    @property
    def loc(self) -> str:
        return self.__loc

    @property
    def value(self) -> int:
        return self.__value

    @classmethod
    def from_json(cls, data: str) -> "ConstraintFailure":
        constraint_dict = json.loads(data)
        cycle = int(constraint_dict["cycle"])
        loc = constraint_dict["loc"]
        value = int(constraint_dict["value"])
        return ConstraintFailure(cycle, loc, value)


# ---------------------------------------------------------------------------- #
#                                  Trace Fault                                 #
# ---------------------------------------------------------------------------- #


class TraceFault(Generic[InjectionKind]):
    __step: int
    __pc: int
    __kind: InjectionKind
    __info: str

    def __init__(self, step: int, pc: int, kind: InjectionKind, info: str):
        self.__step = step
        self.__pc = pc
        self.__kind = kind
        self.__info = info

    def __str__(self) -> str:
        return self.__repr__()

    def __repr__(self):
        return (
            f"TraceFault(step={self.__step}, "
            f"pc={self.__pc}, kind={self.__kind}, "
            f'info="{self.__info}")'
        )

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, TraceFault):
            return (
                self.__step == other.__step
                and self.__pc == other.__pc
                and self.__kind == other.__kind
                and self.__info == other.__info
            )
        return False

    def __hash__(self) -> int:
        h1 = hash(self.__step)
        h2 = hash(self.__pc)
        h3 = hash(self.__kind)
        h4 = hash(self.__info)
        result = h1 * 31 + h2 * 37 + h3 * 41 + h4 * 43
        result ^= result >> 16
        result *= 0x45D9F3B
        result ^= result >> 16
        return result

    @property
    def step(self) -> int:
        return self.__step

    @property
    def pc(self) -> int:
        return self.__pc

    @property
    def kind_as_str(self) -> str:
        return self.__kind.value

    @property
    def kind(self) -> InjectionKind:
        return self.__kind

    @property
    def info(self) -> str:
        return self.__info

    @classmethod
    def from_json(cls, data: str, kind_enum: Type[InjectionKind]) -> "TraceFault":
        trace_step_dict = json.loads(data)
        step = int(trace_step_dict["step"])
        pc = int(trace_step_dict["pc"])
        kind = kind_enum(trace_step_dict["kind"])
        info = re.sub(r"\s+", " ", trace_step_dict["info"])
        return TraceFault(step, pc, kind, info)


# ---------------------------------------------------------------------------- #
#                                     Trace                                    #
# ---------------------------------------------------------------------------- #


class Trace(Generic[InstrKind, InjectionKind]):
    __steps: list[TraceStep[InstrKind]]
    __faults: list[TraceFault[InjectionKind]]
    __constraint_failures: list[ConstraintFailure]

    __instr_kind_enum: Type[InstrKind]
    __injection_kind_enum: Type[InjectionKind]

    def __init__(
        self,
        steps: list[TraceStep[InstrKind]],
        faults: list[TraceFault[InjectionKind]],
        instr_kind_enum: Type[InstrKind],
        injection_kind_enum: Type[InjectionKind],
        constraint_failures: list[ConstraintFailure] | None = None,
    ):
        self.__steps = steps
        self.__faults = faults
        self.__instr_kind_enum = instr_kind_enum
        self.__injection_kind_enum = injection_kind_enum
        self.__constraint_failures = constraint_failures if constraint_failures else []

    def __str__(self) -> str:
        len_steps = len(self.__steps)
        len_faults = len(self.__faults)
        len_constraint_failures = len(self.__constraint_failures)
        return (
            f"Trace(steps=TraceStep[{len_steps}], faults=TraceFault[{len_faults}], "
            f"constraint_failures=ConstraintFailure[{len_constraint_failures}])"
        )

    def __repr__(self):
        len_steps = len(self.__steps)
        len_faults = len(self.__faults)
        len_constraint_failures = len(self.__constraint_failures)
        return (
            f"Trace[{self.__instr_kind_enum.name},{self.__injection_kind_enum.name}]"
            f"(steps=TraceStep[{len_steps}], faults=TraceFault[{len_faults}], "
            f"constraint_failures=ConstraintFailure[{len_constraint_failures}])"
        )

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, Trace):
            return (
                self.__steps == other.__steps
                and self.__faults == other.__faults
                and self.__constraint_failures == other.__constraint_failures
                and self.__instr_kind_enum == other.__instr_kind_enum
                and self.__injection_kind_enum == other.__injection_kind_enum
            )
        return False

    def __hash__(self) -> int:
        h1 = hash(self.__steps)
        h2 = hash(self.__faults)
        h3 = hash(self.__instr_kind_enum)
        h4 = hash(self.__injection_kind_enum)
        h5 = hash(tuple(self.__constraint_failures))
        result = h1 * 31 + h2 * 37 + h3 * 41 + h4 * 43 + h5 * 47
        result ^= result >> 16
        result *= 0x45D9F3B
        result ^= result >> 16
        return result

    def has_fault_injection(self) -> bool:
        return len(self.__faults) > 0

    def as_instruction_to_count(self) -> dict[InstrKind, int]:
        summary = {e: 0 for e in list(self.__instr_kind_enum)}
        for step in self.__steps:
            summary[step.instruction] += 1
        return summary

    def as_instruction_to_steps(self) -> dict[InstrKind, list[TraceStep[InstrKind]]]:
        mapping = {}
        for step in self.__steps:
            if step.instruction not in mapping:
                mapping[step.instruction] = []
            mapping[step.instruction].append(step)
        return mapping

    @property
    def steps(self) -> list[TraceStep[InstrKind]]:
        return self.__steps

    @property
    def faults(self) -> list[TraceFault[InjectionKind]]:
        return self.__faults

    @property
    def constraint_failures(self) -> list[ConstraintFailure]:
        return self.__constraint_failures

    def has_constraint_failures(self) -> bool:
        return len(self.__constraint_failures) > 0

    def get_first_constraint_failure(self) -> ConstraintFailure | None:
        """Returns the first constraint failure, or None if there are no failures."""
        return self.__constraint_failures[0] if self.__constraint_failures else None

    def correlate_failure_to_step(
        self, failure: ConstraintFailure
    ) -> TraceStep[InstrKind] | None:
        """Find the instruction step that corresponds to a constraint failure cycle.

        Returns the trace step at the given cycle, or the nearest preceding step
        if no exact match is found.
        """
        # Try exact match first
        for step in self.__steps:
            if step.step == failure.cycle:
                return step

        # If no exact match, find nearest preceding step
        preceding = [s for s in self.__steps if s.step <= failure.cycle]
        return max(preceding, key=lambda s: s.step) if preceding else None


# ---------------------------------------------------------------------------- #
#                                Emulator Parser                               #
# ---------------------------------------------------------------------------- #


def trace_from_str(
    data: str, instr_kind_enum: Type[InstrKind], injection_kind_enum: Type[InjectionKind]
) -> Trace[InstrKind, InjectionKind]:

    tag_patterns = re.compile(
        r"(\<trace\>(?P<trace>.+?)\<\/trace\>)"
        r"|(\<fault\>(?P<fault>.+?)\<\/fault\>)"
        r"|(\<constraint_fail\>(?P<constraint_fail>.+?)\<\/constraint_fail\>)"
    )

    # ----------------------- retrieve information packages ---------------------- #

    raw_steps = []
    raw_faults = []
    raw_constraint_failures = []

    tag_match = None
    group_dic = None

    try:
        for tag_match in re.finditer(tag_patterns, data):
            group_dic = tag_match.groupdict()
            if group_dic["trace"] is not None:
                raw_steps.append(TraceStep.from_json(group_dic["trace"], instr_kind_enum))
            elif group_dic["fault"] is not None:
                raw_faults.append(TraceFault.from_json(group_dic["fault"], injection_kind_enum))
            elif group_dic["constraint_fail"] is not None:
                raw_constraint_failures.append(
                    ConstraintFailure.from_json(group_dic["constraint_fail"])
                )

    except Exception as e:
        logger.critical("Unable to retrieve trace information for specific tag!")
        logger.info(f"matched tag: {tag_match}")
        logger.info(f"match group dictionary: {group_dic}")
        raise e  # rethrow

    # ----------------------- invariant checks and bundling ---------------------- #

    steps = []

    expected_trace_step = 0
    for trace in raw_steps:
        if expected_trace_step == trace.step:  # first trace
            expected_trace_step = trace.step + 1
            steps.append(trace)

        elif expected_trace_step > trace.step:  # compare any following steps
            if steps[trace.step] != trace:
                logger.info(trace)
                logger.info(steps[trace.step])
                print(trace)
                print(steps[trace.step])
                raise ValueError(f"diverging trace at step {trace.step}")

        else:
            logger.info(trace)
            raise ValueError(
                f"Unexpected trace step! Expected: {expected_trace_step}, but was {trace.step}!"
            )

    faults = []

    last_fault_step = None
    for fault in raw_faults:
        if last_fault_step is None or last_fault_step < fault.step:
            last_fault_step = fault.step
            faults.append(fault)
        elif last_fault_step >= fault.step and fault not in faults:
            logger.info(fault)
            raise ValueError("Unordered / multiple or new fault detected!")

    # Phase 1: Deduplicate constraint failures (multiple workers may report same failure)
    constraint_failures = []
    seen_constraint_locs = set()
    for cf in raw_constraint_failures:
        # Use (cycle, loc) as dedup key since multiple processes may report the same failure
        key = (cf.cycle, cf.loc)
        if key not in seen_constraint_locs:
            seen_constraint_locs.add(key)
            constraint_failures.append(cf)

    return Trace(steps, faults, instr_kind_enum, injection_kind_enum, constraint_failures)


def trace_from_exec(
    exec_status: ExecStatus,
    instr_kind_enum: Type[InstrKind],
    injection_kind_enum: Type[InjectionKind],
) -> Trace[InstrKind, InjectionKind]:
    return trace_from_str(exec_status.stdout, instr_kind_enum, injection_kind_enum)

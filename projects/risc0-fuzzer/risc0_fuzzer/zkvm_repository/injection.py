import logging
import re
from pathlib import Path

from risc0_fuzzer.settings import GLOBAL_FAULT_INJECTION_ENV_KEY, CONSTRAINT_TRACE_ENV_KEY
from risc0_fuzzer.zkvm_repository.fuzzer_utils_crate import create_fuzzer_utils_crate
from risc0_fuzzer.zkvm_repository.injection_sources import (
    risc0_circuit_rv32im_src_execute_rv32im_rs,
)
from zkvm_fuzzer_utils.file import overwrite_file, prepend_file, replace_in_file

logger = logging.getLogger("fuzzer")


def risc0_fault_injection(risc0_install_path: Path, commit_or_branch: str):

    # create crate fuzzer_utils
    create_fuzzer_utils_crate(risc0_install_path)

    # add fuzzer_utils to main cargo
    fuzzer_utils_crate_path = risc0_install_path / "fuzzer_utils"

    # add fuzzer utils to root Cargo.toml
    replace_in_file(
        risc0_install_path / "Cargo.toml",
        [
            (r"members = \[", f'members = [\n    "{fuzzer_utils_crate_path}",'),
            (
                r"\[workspace\.dependencies\]",
                f"""[workspace.dependencies]
    fuzzer_utils = {{ path = "{fuzzer_utils_crate_path}" }}""",
            ),
        ],
    )

    # overwrite execute/rv32im.rs
    overwrite_file(
        risc0_install_path / "risc0" / "circuit" / "rv32im" / "src" / "execute" / "rv32im.rs",
        risc0_circuit_rv32im_src_execute_rv32im_rs(commit_or_branch),
    )

    # remove throws from the cxx constraint files
    cxx_dir = risc0_install_path / "risc0" / "circuit"

    excluded_list = [risc0_install_path / "risc0" / "circuit" / "keccak" / "src" / "lib.rs"]

    working_list: list[Path] = [cxx_dir]
    while len(working_list) > 0:
        working_dir = working_list.pop()
        for element in working_dir.iterdir():
            if element in excluded_list:
                continue  # skip
            if element.is_dir():
                working_list.append(element)
            if element.is_file():
                element = element.absolute()
                if element.name == "Cargo.toml":
                    replace_in_file(
                        element.absolute(),
                        [
                            (
                                r"\[dependencies\]",
                                "[dependencies]\nfuzzer_utils.workspace = true",
                            )
                        ],
                    )

                elif element.suffix in [".rs"]:
                    # NOTE: the order matters here because the replacement is done iteratively
                    is_updated = replace_in_file(
                        element,
                        [
                            (r"\bassert!", "fuzzer_utils::fuzzer_assert!"),
                            (r"\bassert_eq!", "fuzzer_utils::fuzzer_assert_eq!"),
                            (r"\bassert_ne!", "fuzzer_utils::fuzzer_assert_ne!"),
                            (r"\bdebug_assert!", "fuzzer_utils::fuzzer_assert!"),
                            (r"\bdebug_assert_eq!", "fuzzer_utils::fuzzer_assert_eq!"),
                            # NOTE: just comment it out because we have no std in these files
                            (r"ensure!\s*\((.*?)\)\s*;", "// ensure!(...);"),
                        ],
                    )
                    if is_updated:
                        prepend_file(element, "#[allow(unused_imports)]\nuse fuzzer_utils;\n")

                elif element.suffix in [".c", ".inc", ".h", ".cpp", ".hpp", ".metal"]:
                    replace_in_file(
                        element.absolute(),
                        [
                            (
                                r'^([\t ]*)throw\s+std::runtime_error\s*\(\s*"([^"]*)"\s*\)\s*;',
                                r'''
\1// <----------------------- START OF FAULT INJECTION ----------------------->
\1if(std::getenv("'''
                                + GLOBAL_FAULT_INJECTION_ENV_KEY
                                + r"""") != NULL) {
\1  printf("SKIP THROW: %s @ %s:%d\\n", "\2", __FILE__, __LINE__);
\1} else {
\1  throw std::runtime_error("\2");
\1}
\1// <------------------------ END OF FAULT INJECTION ------------------------>
""",  # noqa: E501
                            ),
                            (
                                r"^([\t ]*)assert\s*\((.*?)\)\s*;",
                                # r"^([\t ]*)assert\(([^)]+)\);",
                                r'''
\1// <----------------------- START OF FAULT INJECTION ----------------------->
\1if(std::getenv("'''
                                + GLOBAL_FAULT_INJECTION_ENV_KEY
                                + r"""") != NULL && !(\2)) {
\1  printf("SKIP ASSERT: %s:%d\\n", __FILE__, __LINE__);
\1} else {
\1  assert(\2);
\1}
\1// <------------------------ END OF FAULT INJECTION ------------------------>
""",
                            ),
                            (
                                r"^([\t ]*)Fp ret = buf\[col \* rows \+ row\];",
                                r'''
\1// <----------------------- START OF FAULT INJECTION ----------------------->
\1Fp ret = buf[col * rows + row];
\1ret = (std::getenv("'''
                                + GLOBAL_FAULT_INJECTION_ENV_KEY
                                + r"""") != NULL && ret == Fp::invalid() ? Fp() : ret);
\1// <------------------------ END OF FAULT INJECTION ------------------------>
""",
                            ),
                            (
                                r"buf\[col \* rows \+ row\]",
                                f'(std::getenv("{GLOBAL_FAULT_INJECTION_ENV_KEY}") != NULL ? '
                                "buf[(col % cols) * rows + (row % rows)] "
                                ": buf[col * rows + row])",
                            ),
                        ],
                        flags=re.MULTILINE,
                    )

                    # Special case: Add constraint tracing hook to witgen.h
                    if element.name == "witgen.h":
                        # Phase 0: Hello constraint hook (existing)
                        replace_in_file(
                            element.absolute(),
                            [
                                (
                                    r"inline void eqz\(ExecContext& ctx, Val a, const char\* loc\) \{",
                                    'inline void eqz(ExecContext& ctx, Val a, const char* loc) {\n'
                                    '  // <----------------------- CONSTRAINT TRACING ----------------------->\n'
                                    '  static bool first_constraint = true;\n'
                                    '  if (std::getenv("' + CONSTRAINT_TRACE_ENV_KEY + '") != NULL) {\n'
                                    '    if (first_constraint) {\n'
                                    '      printf("<hello_constraint>{\\\\"source\\\\":\\\\"cpp_witgen\\\\", \\\\"message\\\\":\\\\"constraint_hook_active\\\\"}</hello_constraint>\\\\n");\n'
                                    '      fflush(stdout);\n'
                                    '      first_constraint = false;\n'
                                    '    }\n'
                                    '  }\n'
                                    '  // <---------------------- END CONSTRAINT TRACING --------------------->',
                                ),
                            ],
                        )
                        # Phase 1: Constraint failure hook - emit tag BEFORE throwing
                        replace_in_file(
                            element.absolute(),
                            [
                                (
                                    r"if \(a\.asUInt32\(\)\) \{\s*\n\s*std::stringstream ss;",
                                    'if (a.asUInt32()) {\n'
                                    '    // <---- PHASE 1: CONSTRAINT FAILURE TRACING ---->\n'
                                    '    printf("<constraint_fail>{\\\\"cycle\\\\":%zu, \\\\"loc\\\\":\\\\"%s\\\\", \\\\"value\\\\":%u}</constraint_fail>\\\\n",\n'
                                    '           ctx.cycle, loc, a.asUInt32());\n'
                                    '    fflush(stdout);\n'
                                    '    // <---- END PHASE 1 ---->\n'
                                    '    std::stringstream ss;',
                                ),
                            ],
                        )
"""Standalone tests for JmriMcpBridge.py's _split_last_expression
(jmri-mcp issue #6: manager.eval() only ever returns a value for a
single bare expression -- this recovers REPL-style last-expression
semantics for multi-statement scripts).

Runnable under plain CPython even though the containing module can't be
(it imports `java.io`/`jmri.script`/etc. and only really runs inside
JMRI's embedded Jython JVM): extracts just this one function's AST from
the real source file and execs it in isolation, so these tests exercise
the exact code that ships, not a hand-copied duplicate that could drift
(CLAUDE.md Parallel Implementation Rule).

`_split_last_expression` itself only depends on the stdlib `ast` module,
which both CPython and Jython 2.7 implement -- but the actual runtime
behavior of `manager.eval()` across two calls sharing one engine's
Bindings is NOT covered here; that requires a live JVM (see the TESTME
note on `_split_last_expression`'s docstring in the source).

Run with: python3 -m pytest tests/test_split_last_expression.py -v
"""

import ast
import os

import pytest

_SOURCE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..",
    "CO_in_Virginia.jmri",
    "jython",
    "JmriMcpBridge.py",
)


def _load_split_last_expression():
    with open(_SOURCE_PATH) as f:
        source = f.read()
    tree = ast.parse(source)
    func_node = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_split_last_expression"
    )
    module = ast.Module(body=[func_node], type_ignores=[])
    ast.fix_missing_locations(module)
    namespace = {"ast": ast}
    exec(compile(module, _SOURCE_PATH, "exec"), namespace)
    return namespace["_split_last_expression"]


@pytest.fixture(scope="module")
def split():
    return _load_split_last_expression()


# --- The two bugs from jmri-mcp issue #6/#4, now fixed --------------------


def test_multi_statement_bare_expression_splits(split):
    exec_part, eval_part = split("x = 5\nx+1")
    assert exec_part.strip() == "x = 5"
    assert eval_part.strip() == "x+1"


def test_real_world_logixng_example(split):
    script = (
        "mgr = jmri.InstanceManager.getDefault(jmri.jmrit.logixng.LogixNG_Manager)\n"
        "mgr.getNamedBeanSet().size()"
    )
    exec_part, eval_part = split(script)
    assert exec_part.strip().startswith("mgr =")
    assert eval_part.strip() == "mgr.getNamedBeanSet().size()"


# --- Already-working single-expression case: must stay a single eval() ----


def test_single_expression_stays_unsplit(split):
    # exec_part must be None (not "") -- _run_jython uses `if exec_part:`
    # to decide whether to issue a first eval() call at all.
    assert split("1+1") == (None, "1+1")


def test_single_expression_no_leading_blank_exec_call(split):
    exec_part, _ = split("jmri.Version.name()")
    assert exec_part is None


# --- Assignment-only / no trailing expression: unchanged (result: None) ---


def test_assignment_only_no_split(split):
    exec_part, eval_part = split("x = 5")
    assert exec_part is None
    assert eval_part == "x = 5"


def test_multi_statement_last_not_expression_no_split(split):
    exec_part, eval_part = split("x = 5\ny = 6")
    assert exec_part is None
    assert eval_part == "x = 5\ny = 6"


# --- Ambiguous / adversarial inputs (Threshold-Boundary Testing Rule) -----


def test_semicolon_joined_same_line_falls_back(split):
    # Two statements sharing one physical line -- a line-based split
    # can't separate "x = 1" from "x + 1" here; must fall back rather
    # than produce a wrong split.
    exec_part, eval_part = split("x = 1; x + 1")
    assert exec_part is None
    assert eval_part == "x = 1; x + 1"


def test_empty_script_falls_back(split):
    exec_part, eval_part = split("")
    assert exec_part is None
    assert eval_part == ""


def test_whitespace_only_script_falls_back(split):
    exec_part, eval_part = split("   \n\n  ")
    assert exec_part is None
    assert eval_part == "   \n\n  "


def test_syntax_error_falls_back(split):
    exec_part, eval_part = split("def (:")
    assert exec_part is None
    assert eval_part == "def (:"


def test_compound_statement_last_no_split(split):
    # Last top-level statement is an `if`, not a bare Expr, even though
    # its BODY ends in one -- must not split (the value the JMRI issue
    # cares about is a bare *top-level* expression; reaching inside a
    # compound statement's body would change what actually executes).
    script = "x = 1\nif True:\n    x\n"
    exec_part, eval_part = split(script)
    assert exec_part is None
    assert eval_part == script


def test_multiline_last_expression_splits_whole_statement(split):
    script = "x = 1\nlong_function_call(\n    x,\n    2,\n)"
    exec_part, eval_part = split(script)
    assert exec_part.strip() == "x = 1"
    assert "long_function_call(" in eval_part
    assert eval_part.count("\n") == 3  # all 4 lines of the call, verbatim


def test_three_statements_only_first_two_execed(split):
    exec_part, eval_part = split("a = 1\nb = 2\na + b")
    assert exec_part.strip() == "a = 1\nb = 2"
    assert eval_part.strip() == "a + b"


def test_leading_blank_lines_preserved_in_exec_part(split):
    exec_part, eval_part = split("\n\nx = 5\nx + 1")
    assert exec_part is not None
    assert "x = 5" in exec_part
    assert eval_part.strip() == "x + 1"

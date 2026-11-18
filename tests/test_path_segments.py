"""Every id a request path carries is encoded as one segment.

A request path is built by interpolating ids into a template. An id holding
``/``, ``?``, ``#`` or ``%`` would otherwise add segments, start a query or
cut the path short, and one that is a dot segment would climb out of its
endpoint: the request would reach another endpoint, with the caller's
credentials, than the one its tool calls. Every interpolation into a path in
``client.py`` goes through ``_seg``; this test reads the source and fails on
any that does not, so a method added later cannot skip it."""

import ast
import pathlib

import pytest

from mipiti_mcp.client import UnsafePath, _seg

CLIENT = pathlib.Path(__file__).resolve().parent.parent / "src" / "mipiti_mcp" / "client.py"

#: Interpolations that are not ids: the internal tail a path helper appends,
#: always a literal or an f-string itself checked here.
_NOT_IDS = {("_behavioural", "tail"), ("_inventory", "tail")}


def _path_fstrings(tree):
    """``(function name, f-string)`` for every f-string that builds a path
    (its first part a literal starting with ``/``) or appends a query
    (``?``)."""
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(func):
            if (isinstance(node, ast.JoinedStr) and node.values
                    and isinstance(node.values[0], ast.Constant)
                    and str(node.values[0].value).startswith(("/", "?"))):
                yield func.name, node


def test_every_path_interpolation_is_one_encoded_segment():
    tree = ast.parse(CLIENT.read_text())
    raw = []
    for func, node in _path_fstrings(tree):
        for part in node.values:
            if not isinstance(part, ast.FormattedValue):
                continue
            expr = part.value
            if isinstance(expr, ast.Call) and getattr(expr.func, "id", "") == "_seg":
                continue
            if isinstance(expr, ast.Name) and (func, expr.id) in _NOT_IDS:
                continue
            raw.append(f"{func} line {node.lineno}: {ast.unparse(expr)}")
    assert not raw, "path interpolations not encoded with _seg:\n" + "\n".join(raw)


def test_the_reader_finds_the_paths():
    assert sum(1 for _ in _path_fstrings(ast.parse(CLIENT.read_text()))) > 150


@pytest.mark.parametrize("value,encoded", [
    ("m1", "m1"), ("CO-12", "CO-12"), ("a/b", "a%2Fb"), ("a?b", "a%3Fb"), ("a#b", "a%23b"),
    ("100%", "100%25"), ("a\\b", "a%5Cb"), ("a b", "a%20b"), ("x..y", "x..y"), (7, "7"),
])
def test_a_segment_is_encoded_whole(value, encoded):
    assert _seg(value) == encoded


@pytest.mark.parametrize("value", ["", ".", "..", "%2e", ".%2E", "%2e%2e", ".\t."])
def test_an_empty_or_dot_segment_is_refused(value):
    with pytest.raises(UnsafePath):
        _seg(value)

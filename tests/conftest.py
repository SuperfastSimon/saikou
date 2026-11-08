"""Shared fixtures."""

import ast

import pytest

from saikou import engine

_CACHED = ("_parsed", "_tokens_trustworthy", "_security_lines")


def _clear_engine_caches() -> None:
    for name in _CACHED:
        getattr(engine, name).cache_clear()


@pytest.fixture
def engine_ast_raises(monkeypatch):
    """`engine_ast_raises("parse", RecursionError)` makes saikou.engine's ast.parse raise.

    That is what the parser, or a check walking the tree, does on code that nests deeper
    than the interpreter allows. The depth at which it happens differs between Python
    versions and with the stack depth at the call, so tests simulate it instead of relying
    on one input being too deep everywhere. Only the engine's view of `ast` changes.
    """
    class _Ast:
        def __getattr__(self, attr):
            return getattr(ast, attr)

    proxy = _Ast()

    def install(name: str, exc: type) -> None:
        def raiser(*args, **kwargs):
            raise exc("simulated: nested too deeply")

        setattr(proxy, name, raiser)
        monkeypatch.setattr(engine, "ast", proxy)
        _clear_engine_caches()

    yield install
    monkeypatch.undo()
    _clear_engine_caches()

"""ContextVar-backed run, turn, edge and agent attribution."""

from contextlib import contextmanager
from contextvars import ContextVar


_run = ContextVar("aciarena_run", default=None)
_turn = ContextVar("aciarena_turn", default=0)
_edge = ContextVar("aciarena_edge", default=None)
_agent = ContextVar("aciarena_agent", default=None)


def set_run_context(**fields):
    _run.set(dict(fields))
    _turn.set(0)
    _edge.set(None)
    _agent.set(None)


def get_run_context():
    return _run.get()


def clear_run_context():
    _run.set(None)
    _turn.set(0)
    _edge.set(None)
    _agent.set(None)


def set_turn(turn):
    _turn.set(turn)


def get_turn():
    return _turn.get()


def set_edge(edge_id):
    _edge.set(edge_id)


def get_edge():
    return _edge.get()


def get_agent():
    return _agent.get()


@contextmanager
def bind_edge(edge_id):
    token = _edge.set(edge_id)
    try:
        yield
    finally:
        _edge.reset(token)


@contextmanager
def bind_agent(agent):
    token = _agent.set(agent)
    try:
        yield
    finally:
        _agent.reset(token)

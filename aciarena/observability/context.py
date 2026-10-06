"""ContextVar-backed run, turn, edge and agent attribution."""

from contextlib import contextmanager
from contextvars import ContextVar


_run = ContextVar("aciarena_run", default=None)
_turn = ContextVar("aciarena_turn", default=0)
_edge = ContextVar("aciarena_edge", default=None)
_agent = ContextVar("aciarena_agent", default=None)
_phase = ContextVar("aciarena_phase", default="bootstrap")
_round = ContextVar("aciarena_round", default=0)


class TraceState(dict):
    """One run's recorder state; result snapshots share it, never different runs."""

    def __deepcopy__(self, memo):
        return self


def set_run_context(**fields):
    fields.setdefault("_trace_state", TraceState(sequence=0, outputs={}, write_errors=[]))
    _run.set(dict(fields))
    _turn.set(0)
    _edge.set(None)
    _agent.set(None)
    set_execution(fields.get("phase", "bootstrap"), fields.get("round", 0))


def get_run_context():
    return _run.get()


def clear_run_context():
    _run.set(None)
    _turn.set(0)
    _edge.set(None)
    _agent.set(None)
    set_execution("bootstrap", 0)


def set_execution(phase, round_number):
    if phase not in ("bootstrap", "step", "conclude", "evaluation"):
        raise ValueError(f"Unknown execution phase: {phase}")
    _phase.set(phase)
    _round.set(round_number)


def get_phase():
    return _phase.get()


def get_round():
    return _round.get()


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

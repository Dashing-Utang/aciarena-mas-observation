"""Immediately appended, run-isolated JSONL events.

This is an observational artifact, not a security boundary for untrusted users.
"""

import hashlib
import json
import os
import re
import threading
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .context import get_agent, get_edge, get_run_context, get_turn, get_phase, get_round

EVENT_TYPES = frozenset({
    "RUN_START", "ATTACK_INSTALLED", "ATTACK_APPLIED", "MESSAGE_TRANSFER",
    "LLM_REQUEST", "AGENT_OUTPUT", "HANDOFF_START", "HANDOFF_TRANSFORM",
    "RUNNER_INPUT", "RUNNER_OUTPUT", "TOOL_CALL", "TOOL_RESULT", "TERMINATION",
    "FINAL_RESPONSE", "OFFICIAL_ATTACK_VERIFY", "OFFICIAL_TASK_VERIFY",
    "EXTENDED_EVAL", "ANSWER_RELEASE", "AGRAIL_PUBLICATION", "ERROR", "RUN_END",
})


_SECRET = re.compile(
    r"(?i)(?:Incorrect API key provided:\s*)[^\s,;\"']+|"
    r"(?i:(?:Bearer\s+)[A-Za-z0-9._~-]+)|"
    r"\b(?:sk|rk|pk)-[A-Za-z0-9_-]{12,}\b|"
    r"(?i:(?:api[_ -]?key|authorization|access[_ -]?token|secret)\s*[:=]\s*)[^\s,;\"']+"
)
_PATH_PART = re.compile(r"^[A-Za-z0-9_.-]+$")
_lock = threading.Lock()
release_redactions = ContextVar("release_redactions", default=())


def sanitize(value):
    if isinstance(value, str):
        if any(v.casefold() in value.casefold() for v in release_redactions.get()):
            return "[REDACTED]"
        value = _SECRET.sub("[REDACTED]", value)
        for env_name, env_value in os.environ.items():
            if ("KEY" in env_name or "TOKEN" in env_name or "SECRET" in env_name) and len(env_value) >= 8:
                value = value.replace(env_value, "[REDACTED]")
        return value
    if isinstance(value, dict):
        return {str(k): ("[REDACTED]" if re.search(r"(?i)(api.?key|authorization|secret|access.?token)", str(k)) else sanitize(v)) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [sanitize(v) for v in value]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return sanitize(str(value))


def _part(value):
    value = str(value)
    if not _PATH_PART.fullmatch(value) or value in (".", ".."):
        raise ValueError("Unsafe trace path component")
    return value


def trace_path(context=None):
    ctx = context or get_run_context()
    if not ctx:
        return None
    return Path(ctx["trace_dir"]) / _part(ctx["session_id"]) / _part(ctx["mas_name"]) / _part(ctx["task_id"]) / (_part(ctx["run_id"]) + ".jsonl")


def new_event_id():
    return "V" + uuid4().hex


def new_edge_id():
    return "E" + uuid4().hex


def fingerprint(value):
    text = str(value)
    return {"sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(), "length": len(text)}


def emit(event_type, *, agent=None, sender=None, receiver=None, edge_id=None, **data):
    ctx = get_run_context()
    if not ctx or not ctx.get("trace", False):
        return None
    state = ctx["_trace_state"]
    record = {
        "schema_version": "1.1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_id": new_event_id(),
        "session_id": ctx["session_id"],
        "run_id": ctx["run_id"],
        "task_id": ctx["task_id"],
        "dataset_index": ctx.get("dataset_index"),
        "task_name": ctx.get("task_name"),
        "mas": ctx["mas_name"],
        "suite": ctx["suite"],
        "task_domain": ctx["task_domain"],
        "attack_id": ctx.get("attack_id"),
        "attack_name": ctx["attack_name"],
        "attack_surface": ctx.get("attack_surface"),
        "turn": get_turn(),
        "phase": get_phase(),
        "round": get_round(),
        "edge_id": edge_id if edge_id is not None else get_edge(),
        "event_type": event_type,
        "agent": agent if agent is not None else get_agent(),
        "sender": sender,
        "receiver": receiver,
        "data": None,
    }
    try:
        if event_type not in EVENT_TYPES:
            raise ValueError("Unsupported trace event type")
        record["data"] = sanitize(data)
        path = trace_path(ctx)
        with _lock:
            state["sequence"] += 1
            record["sequence"] = state["sequence"]
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as stream:
                stream.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
            if event_type == "AGENT_OUTPUT":
                state["outputs"][record["agent"]] = record["event_id"]
    except Exception as exc:
        # Recording failure must not alter an agent's input, response or control flow.
        state["write_errors"].append({"error_type": type(exc).__name__})
        return None
    return record["event_id"]


def last_output_event_id(agent):
    ctx = get_run_context()
    return ctx["_trace_state"]["outputs"].get(agent) if ctx else None


def record_llm_request(model, messages, *, agent=None, **data):
    return emit("LLM_REQUEST", agent=agent, model=model, messages=messages,
                messages_sha256=fingerprint(messages)["sha256"], **data)


def response_metadata(response):
    """Read observed ChatCompletion fields only; no estimates or SDK mutation.

    This optional AGENT_OUTPUT data does not change the event envelope/schema.
    Scalar choice fields describe choice 0; choices preserves multi-choice data.
    Missing metadata (including unsupported streaming responses) remains null.
    """
    missing = object()

    def field(value, name, default=None):
        try:
            return value.get(name, default) if isinstance(value, dict) else getattr(value, name, default)
        except Exception:
            # Observation failures must not affect the model's return/control flow.
            return default

    def choice_fields(choice):
        message = field(choice, "message")
        content, tools = field(message, "content", missing), field(message, "tool_calls", missing)
        empty = content is None or not content.strip() if isinstance(content, str) or content is None else None
        return {"index": field(choice, "index"), "finish_reason": field(choice, "finish_reason"),
                "content_empty": empty,
                "has_tool_calls": bool(tools) if isinstance(tools, (list, tuple)) or tools is None else None}

    raw_choices = field(response, "choices")
    choices = [choice_fields(choice) for choice in raw_choices] if isinstance(raw_choices, (list, tuple)) else None
    first = choices[0] if choices else {}
    usage = field(response, "usage")
    return {"response_id": field(response, "id"),
            "finish_reason": first.get("finish_reason"),
            "input_tokens": field(usage, "prompt_tokens"),
            "output_tokens": field(usage, "completion_tokens"),
            "total_tokens": field(usage, "total_tokens"),
            "content_empty": first.get("content_empty"),
            "choice_count": len(choices) if choices is not None else None,
            "has_tool_calls": first.get("has_tool_calls"),
            "choices": choices}


def record_agent_output(output, request_event_id=None, *, agent=None, **data):
    return emit("AGENT_OUTPUT", agent=agent, output=output,
                request_event_id=request_event_id, output_sha256=fingerprint(output)["sha256"], **data)


def read_trace(context):
    path = trace_path(context)
    if not path or not path.exists():
        return []
    with path.open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]

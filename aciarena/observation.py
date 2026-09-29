"""Structured observation hooks for ACIArena multi-agent runs."""

from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


INTERACTION_EVENTS = {
    "message_transfer",
    "agent_turn",
    "agent_start",
    "agent_end",
    "handoff",
    "tool_start",
    "tool_end",
}


class NullObserver:
    """Drop-in observer used when observation was not requested."""

    attack = None
    observed_events = 0

    def emit(self, event: Dict[str, Any]) -> None:
        return None

    def record_verification(self, success: bool) -> Dict[str, Any]:
        return {}


class ObservationSink:
    """Thread-safe console and JSONL sink shared by benchmark runs."""

    def __init__(self, jsonl_path: str | Path):
        self.path = Path(jsonl_path)
        self.summary_path = self.path.with_name("summary.jsonl")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text("", encoding="utf-8")
        self.summary_path.write_text("", encoding="utf-8")
        self._lock = threading.Lock()
        self._sequence = 0

    def __deepcopy__(self, memo):
        return self

    def start_run(self, team: str, attack: str) -> "RunObserver":
        return RunObserver(
            sink=self,
            team=team,
            attack=attack,
            run_id=uuid.uuid4().hex,
        )

    def write(self, event: Dict[str, Any], *, summary: bool = False) -> None:
        with self._lock:
            self._sequence += 1
            event.setdefault("sequence", self._sequence)
            line = json.dumps(event, ensure_ascii=False, default=str)
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(line + "\n")
            if summary:
                with self.summary_path.open("a", encoding="utf-8") as stream:
                    stream.write(line + "\n")
            print(f"[observer] {line}", flush=True)


class RunObserver:
    """Observer bound to one MAS/attack execution."""

    def __init__(self, sink: ObservationSink, team: str, attack: str, run_id: str):
        self.sink = sink
        self.team = team
        self.attack = attack
        self.run_id = run_id
        self.observed_events = 0

    def __deepcopy__(self, memo):
        return self

    def emit(self, event: Dict[str, Any]) -> None:
        payload = dict(event)
        payload.setdefault("team", self.team)
        payload.setdefault("attack", self.attack)
        payload.setdefault("run_id", self.run_id)
        payload.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        if payload.get("event") in INTERACTION_EVENTS:
            self.observed_events += 1
        self.sink.write(payload)

    def record_verification(self, success: bool) -> Dict[str, Any]:
        result = {
            "team": self.team,
            "attack": self.attack,
            "run_id": self.run_id,
            "event": "attack_verify",
            "observed_events": self.observed_events,
            "attack_success": bool(success),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.sink.write(result, summary=True)
        return result


def build_observation_sink(path: Optional[str]) -> Optional[ObservationSink]:
    return ObservationSink(path) if path else None

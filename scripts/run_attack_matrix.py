#!/usr/bin/env python3
"""Run every registered ACIArena attack against the selected MAS adapters.

Each unique CLI-selectable attack name is launched in an isolated benchmark
process. Duplicate registry entries are intentionally preserved: selecting the
name makes ACIArena execute every matching registered class, and the matrix
checks that a verification callback was produced for each one.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import aciarena.attacks  # noqa: E402,F401 - populates the attack registry
from aciarena.utils.factory import ATTACK_CLASS_REGISTRY  # noqa: E402


TEAM_TARGETS = {
    "metagpt": "engineer",
    "camel": "assistant",
    "cai": "codeagent",
}


@dataclass(frozen=True)
class AttackSpec:
    suite: str
    domain: str
    name: str
    registry_count: int
    registry_goal: str


def attack_specs() -> list[AttackSpec]:
    counts: Counter[tuple[str, str, str, str]] = Counter()
    for goal, classes in ATTACK_CLASS_REGISTRY.items():
        if goal == "none":
            continue
        if goal.endswith("_code"):
            suite, domain = goal.removesuffix("_code"), "code"
        elif goal.endswith("_math"):
            suite, domain = goal.removesuffix("_math"), "math"
        else:
            suite, domain = goal, "code"
        for attack_class in classes:
            counts[(suite, domain, attack_class.__name__, goal)] += 1

    return [
        AttackSpec(suite, domain, name, count, goal)
        for (suite, domain, name, goal), count in sorted(counts.items())
    ]


def load_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except FileNotFoundError:
        return []


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


def unsupported_row(team: str, spec: AttackSpec) -> dict[str, Any]:
    return {
        "team": team,
        "suite": spec.suite,
        "domain": spec.domain,
        "attack": spec.name,
        "registry_goal": spec.registry_goal,
        "registry_count": spec.registry_count,
        "execution_status": "unsupported",
        "reason": "Upstream ACIArena rejects the MetaGPT math domain.",
        "exit_code": None,
        "duration_seconds": 0.0,
        "verification_complete": False,
        "verify_event_count": 0,
        "attack_success_count": 0,
        "attack_failure_count": 0,
        "interaction_trace_available": False,
        "observed_events": [],
        "attack_success_rate": None,
        "utility_under_attack": None,
        "log": None,
    }


def run_one(
    team: str,
    spec: AttackSpec,
    run_root: Path,
    task_limit: int,
    timeout: int,
    env: dict[str, str],
) -> dict[str, Any]:
    case_dir = (
        run_root
        / "runs"
        / team
        / spec.suite
        / spec.domain
        / safe_name(spec.name)
    )
    benchmark_dir = case_dir / "benchmark"
    observation_path = case_dir / "observations" / "events.jsonl"
    log_path = case_dir / "run.log"
    benchmark_dir.mkdir(parents=True, exist_ok=True)
    observation_path.parent.mkdir(parents=True, exist_ok=True)

    command = [
        sys.executable,
        str(PROJECT_ROOT / "benchmark.py"),
        "--mas",
        team,
        "--suite",
        spec.suite,
        "--attack",
        spec.name,
        "--task_domain",
        spec.domain,
        "--malicious_agents",
        TEAM_TARGETS[team],
        "--max_workers",
        "1",
        "--task_limit",
        str(task_limit),
        "--observer_jsonl",
        str(observation_path),
        "--output_dir",
        str(benchmark_dir),
    ]

    print(
        f"START {team:8s} {spec.suite:10s} {spec.domain:4s} "
        f"{spec.name} x{spec.registry_count}",
        flush=True,
    )
    started = time.monotonic()
    timed_out = False
    with log_path.open("w", encoding="utf-8") as log_stream:
        try:
            completed = subprocess.run(
                command,
                cwd=PROJECT_ROOT,
                env=env,
                stdout=log_stream,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
                check=False,
            )
            exit_code = completed.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            exit_code = 124
            log_stream.write(f"\nMATRIX TIMEOUT after {timeout} seconds\n")
    duration = round(time.monotonic() - started, 3)

    summary_rows = load_jsonl(observation_path.with_name("summary.jsonl"))
    verify_rows = [row for row in summary_rows if row.get("event") == "attack_verify"]
    observed_events = [int(row.get("observed_events", 0)) for row in verify_rows]
    success_count = sum(bool(row.get("attack_success")) for row in verify_rows)

    model_name = env["ACI_ARENA_MODEL_NAME"].replace("/", "_")
    result_path = (
        benchmark_dir
        / model_name
        / spec.domain
        / team
        / spec.suite
        / "result.json"
    )
    result_rows = load_json(result_path, [])
    aggregate = result_rows[-1].get("result", {}) if result_rows else {}

    if timed_out:
        status = "timeout"
    elif exit_code != 0:
        status = "runtime_failed"
    elif len(verify_rows) != spec.registry_count:
        status = "verification_incomplete"
    else:
        status = "completed"

    row = {
        "team": team,
        "suite": spec.suite,
        "domain": spec.domain,
        "attack": spec.name,
        "registry_goal": spec.registry_goal,
        "registry_count": spec.registry_count,
        "execution_status": status,
        "reason": None,
        "exit_code": exit_code,
        "duration_seconds": duration,
        "verification_complete": len(verify_rows) == spec.registry_count,
        "verify_event_count": len(verify_rows),
        "attack_success_count": success_count,
        "attack_failure_count": len(verify_rows) - success_count,
        "interaction_trace_available": bool(verify_rows)
        and all(count > 0 for count in observed_events),
        "observed_events": observed_events,
        "attack_success_rate": aggregate.get("Attack Success Rate"),
        "utility_under_attack": aggregate.get("Utility under Attack"),
        "log": str(log_path.relative_to(PROJECT_ROOT)),
    }
    print(
        f"DONE  {team:8s} {spec.name:32s} status={status} "
        f"verify={success_count}/{len(verify_rows)} events={observed_events} "
        f"{duration:.1f}s",
        flush=True,
    )
    return row


def write_outputs(run_root: Path, rows: list[dict[str, Any]]) -> None:
    jsonl_path = run_root / "runs.jsonl"
    with jsonl_path.open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")

    csv_path = run_root / "summary.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=list(rows[0]),
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(rows)

    failures = [
        row
        for row in rows
        if row["execution_status"] not in {"completed", "unsupported"}
    ]
    with (run_root / "failures.jsonl").open("w", encoding="utf-8") as stream:
        for row in failures:
            stream.write(json.dumps(row, ensure_ascii=False) + "\n")

    aggregate_sources = {
        "events.jsonl": "events.jsonl",
        "verify.jsonl": "summary.jsonl",
    }
    for aggregate_name, source_name in aggregate_sources.items():
        source_paths = sorted(
            (run_root / "runs").glob(f"**/observations/{source_name}")
        )
        with (run_root / aggregate_name).open("w", encoding="utf-8") as stream:
            for source_path in source_paths:
                source_text = source_path.read_text(encoding="utf-8")
                stream.write(source_text)
                if source_text and not source_text.endswith("\n"):
                    stream.write("\n")

    runnable = [row for row in rows if row["execution_status"] != "unsupported"]
    completed = [row for row in runnable if row["execution_status"] == "completed"]
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model": os.environ.get("ACI_ARENA_MODEL_NAME", "llama3.2:latest"),
        "matrix_rows": len(rows),
        "registered_attack_instances": sum(row["registry_count"] for row in rows),
        "runnable_attack_instances": sum(
            row["registry_count"] for row in runnable
        ),
        "unsupported_attack_instances": sum(
            row["registry_count"]
            for row in rows
            if row["execution_status"] == "unsupported"
        ),
        "runnable_rows": len(runnable),
        "unsupported_rows": len(rows) - len(runnable),
        "completed_rows": len(completed),
        "failed_rows": len(failures),
        "verified_attack_instances": sum(
            row["verify_event_count"] for row in runnable
        ),
        "successful_attack_instances": sum(
            row["attack_success_count"] for row in runnable
        ),
        "failed_attack_instances": sum(
            row["attack_failure_count"] for row in runnable
        ),
        "rows_with_interaction_trace": sum(
            bool(row["interaction_trace_available"]) for row in runnable
        ),
        "teams": {
            team: {
                "runnable_attack_instances": sum(
                    row["registry_count"]
                    for row in runnable
                    if row["team"] == team
                ),
                "verified_attack_instances": sum(
                    row["verify_event_count"]
                    for row in runnable
                    if row["team"] == team
                ),
                "successful_attack_instances": sum(
                    row["attack_success_count"]
                    for row in runnable
                    if row["team"] == team
                ),
            }
            for team in TEAM_TARGETS
            if any(row["team"] == team for row in rows)
        },
    }
    (run_root / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--teams",
        nargs="+",
        choices=tuple(TEAM_TARGETS),
        default=list(TEAM_TARGETS),
    )
    parser.add_argument("--task-limit", type=int, default=1)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--output-dir", default="results/matrix")
    args = parser.parse_args()

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_root = PROJECT_ROOT / args.output_dir / timestamp
    run_root.mkdir(parents=True, exist_ok=False)

    env = os.environ.copy()
    env.setdefault("ACI_ARENA_API_KEY", "ollama")
    env.setdefault("ACI_ARENA_BASE_URL", "http://127.0.0.1:11434/v1")
    env.setdefault("ACI_ARENA_MODEL_NAME", "llama3.2:latest")
    env.setdefault("ACI_ARENA_MAX_TOKENS", "512")

    specs = attack_specs()
    rows: list[dict[str, Any]] = []
    try:
        for team in args.teams:
            for spec in specs:
                if team == "metagpt" and spec.domain == "math":
                    row = unsupported_row(team, spec)
                    print(
                        f"SKIP  {team:8s} {spec.name:32s} "
                        "unsupported math domain",
                        flush=True,
                    )
                else:
                    row = run_one(
                        team,
                        spec,
                        run_root,
                        args.task_limit,
                        args.timeout,
                        env,
                    )
                rows.append(row)
                write_outputs(run_root, rows)
    except KeyboardInterrupt:
        write_outputs(run_root, rows)
        print(f"Interrupted; partial results saved in {run_root}", file=sys.stderr)
        return 130

    print(f"Matrix complete: {run_root}", flush=True)
    print((run_root / "summary.json").read_text(encoding="utf-8"), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

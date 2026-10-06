"""Run each CAI attack in a fresh process, in either order. No process reuse."""

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def commands(order, offline, artifact_dir, model="gpt-5-nano"):
    attacks = ["SafetyCheckInstruction", "MaliciousReportInstruction"]
    if order == "reverse":
        attacks.reverse()
    result = []
    for index, attack in enumerate(attacks):
        if offline:
            command = [sys.executable, str(ROOT / "scripts/offline_smoke.py"), "--mas", "cai", "--attack_names", attack,
                       "--artifact_dir", str(Path(artifact_dir) / order / str(index))]
        else:
            command = [sys.executable, str(ROOT / "benchmark.py"), "--mas", "cai", "--suite", "hijacking",
                       "--task_domain", "code", "--task_ids", "0", "--attack_names", attack,
                       "--malicious_agents", "codeagent", "--trace", "--max_workers", "1",
                       "--model", model, "--judge_model", model, "--run_tag", f"isolation_{order}_{index}"]
        result.append(command)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--order", choices=("forward", "reverse", "both"), default="both")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--artifact_dir", default="logs/isolation")
    parser.add_argument("--model", default="gpt-5-nano")
    args = parser.parse_args()
    orders = ("forward", "reverse") if args.order == "both" else (args.order,)
    for order in orders:
        for command in commands(order, args.offline, args.artifact_dir, args.model):
            print(json.dumps({"order": order, "command": command}), flush=True)
            subprocess.run(command, cwd=ROOT, check=True, timeout=300)

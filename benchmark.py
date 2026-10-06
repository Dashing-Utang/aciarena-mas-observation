import argparse
import json
import os
from pathlib import Path
from datetime import datetime, timezone
from uuid import uuid4
import subprocess
from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env", override=False)

from aciarena.utils import build_suite, load_llm_config

def main(args):
    args.session_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S") + "_" + uuid4().hex[:8]
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=PROJECT_ROOT,
                              capture_output=True, text=True, check=False)
    args.commit_sha = revision.stdout.strip() if revision.returncode == 0 else None
    state = subprocess.run(["git", "status", "--porcelain"], cwd=PROJECT_ROOT,
                           capture_output=True, text=True, check=False)
    args.worktree_dirty = bool(state.stdout.strip()) if state.returncode == 0 else None
    model_config = load_llm_config(PROJECT_ROOT / "configs/model.yaml")
    model_name = (args.model or model_config.get("model_name", "unknown")).replace("/", "_")

    save_dir = f"logs/{model_name}/{args.task_domain}/{args.mas}/{args.suite}"
    os.makedirs(save_dir, exist_ok=True)

    suite = build_suite(args)
    result = suite.eval()
    print("Evaluation Results:", result)
    extended_summary = Path("results_extended") / args.session_id / "summary.json"
    if extended_summary.exists():
        summary = json.loads(extended_summary.read_text(encoding="utf-8"))
        if summary["valid_runs"] < summary["run_count"]:
            print(f"WARNING: {summary['run_count'] - summary['valid_runs']} invalid run(s); "
                  "do not interpret official percentages without checking extended run_validity")

    save_path = os.path.join(save_dir, "result.json")

    # 如果文件已存在，先加载内容
    if os.path.exists(save_path):
        with open(save_path, "r") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = []  # 如果文件损坏/为空，初始化为空列表
    else:
        data = []

    # 追加新的结果
    data.append({
        "meta_data": vars(args),
        "result": result
    })

    # 写回文件
    with open(save_path, "w") as f:
        json.dump(data, f, indent=4)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="aciarena Configuration")
    parser.add_argument(
        "--mas",
        type=str,
        default="autogen",
        help="The structure of the multi-agent system. Options typically include 'linear', 'tree', or custom topologies."
    )
    parser.add_argument(
        "--suite",
        type=str,
        default="hijacking",
        help="Specifies the evaluation suite."
    )
    parser.add_argument(
        "--attack_mode",
        type=str,
        default="continuous",
        help="Specifies how the attack is executed."
    )
    parser.add_argument(
        "--defense",
        type=str,
        default="none",
        help="Specifies the defense."
    )
    parser.add_argument(
        "--task_domain",
        type=str,
        default="code",
        choices=("math", "code", "sci", "medicine"),
        help="Benign task domain."
    )
    parser.add_argument(
        "--max_workers",
        type=int,
        default=4,
        help="The max workers for evaluation."
    )
    parser.add_argument(
        "--output_dir",
        type=str,
        default="logs",
        help="Directory to save output files such as logs, results, or checkpoints."
    )
    parser.add_argument(
        "--malicious_agents",
        nargs='+',
        type=str,
        default=[],
        help="A list of agent names to target in the attack (e.g., 'agent_1', 'agent_2'). You can specify multiple agents separated by space."
    )
    parser.add_argument("--task_ids", help="Zero-based dataset indices, comma-separated (e.g. 0,2,7). Default: all")
    parser.add_argument("--attack_names", help="Optional comma-separated attack class names for focused smoke tests")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--trace", action="store_true", help="Write per-run JSONL trace")
    parser.add_argument("--trace_dir", default="logs/traces")
    parser.add_argument("--guard_mode", choices=("off", "observe", "enforce"), default="off")
    parser.add_argument("--guard", choices=("noop", "marker"), default="noop")
    parser.add_argument("--run_tag", default="")
    parser.add_argument("--model", help="Override model.yaml model_name for this run")
    parser.add_argument("--judge_model", help="Override judge.yaml model_name for this run")
    args = parser.parse_args()
    if args.repeat < 1:
        parser.error("--repeat must be >= 1")
    if args.guard_mode != "off" and not args.trace:
        parser.error("--guard_mode observe/enforce requires --trace")
    if args.guard_mode != "off" and args.mas != "metagpt":
        parser.error("v1 guard hook is implemented only for MetaGPT engineer→qa_engineer")
    if args.run_tag and not all(char.isalnum() or char in "_.-" for char in args.run_tag):
        parser.error("--run_tag may contain only letters, digits, underscores, dots and hyphens")
    main(args)

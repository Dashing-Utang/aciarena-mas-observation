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
    shield_policy = getattr(args, "shield_policy", None)
    release_config = getattr(args, "shield_release_config", None)
    if release_config and not shield_policy:
        raise ValueError("--shield-release-config requires a Shield policy")
    if shield_policy:
        from subagentshield.adapters.aciarena import ACIArenaAdapter, workflow_jobs

        framework = args.mas.lower()
        if framework not in ("camel", "metagpt"):
            raise ValueError("ACIArena Shield binding supports CAMEL and MetaGPT")
        if not getattr(suite.executor, "supports_mas_runtime", False):
            raise ValueError("The selected executor does not support a MAS runtime binding")
        policy = Path(shield_policy).read_bytes()
        output = Path(args.shield_output) / args.session_id
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
        scope = {"tools": [], "jobs": workflow_jobs(framework)}
        release_values, reviewer, final = None, None, {"id": "aciarena-runtime"}
        if release_config:
            from subagentshield.core.jev import JevClient

            path = Path(release_config)
            release = json.loads(path.read_text())
            release_values = release["protected_values"]
            if not isinstance(release_values, list) or not release_values or not all(
                isinstance(v, str) and v for v in release_values
            ):
                raise ValueError("expected nonempty protected values")
            flow = json.loads((path.parent / release["flow_config"]).read_text())
            final = flow["final"]
            if not 0 <= final["allow_below"] < final["deny_at_or_above"] <= 1:
                raise ValueError("invalid final thresholds")
            cfg = flow["jev"]
            questions = release.get(
                "review_questions", release.get("review_question", cfg["question"])
            )
            reviewer = JevClient(cfg["model"], cfg["timeout_seconds"], questions)
            scope["tools"] = ["publish_final_response"]
            scope["arguments"] = {"publish_final_response": {"recipient": "requester"}}
            suite.mas_config["release_values"] = tuple(release_values)
            if release.get("public_code_dataset_sha256"):
                from aciarena.evaluation.answer_release import load_public_code_tasks
                suite.mas_config["public_code_tasks"] = load_public_code_tasks(
                    PROJECT_ROOT / "aciarena/evaluation/datasets/aciarena_code.json",
                    release["public_code_dataset_sha256"],
                ) if args.task_domain == "code" else {}

        def bind_runtime(mas, context, purpose):
            if release_config and release.get("publication_authorization"):
                purpose = release["publication_authorization"] + "\n\nTask:\n" + purpose
            return ACIArenaAdapter(
                mas,
                run_id=context["run_id"],
                task_id=context["task_id"],
                purpose=purpose,
                framework=framework,
                policy=policy,
                scope=scope,
                final_policy=final,
                reviewer=reviewer,
                release_values=release_values,
                source="live_mas",
                output=output,
                enforce=args.shield_mode == "enforce",
            )

        suite.mas_config["bind_runtime"] = bind_runtime
        print("SubAgentShield traces:", output)
    result = suite.eval()
    print("Evaluation Results:", result)
    extended_summary = Path("results_extended") / args.session_id / "summary.json"
    if extended_summary.exists():
        try:
            summary = json.loads(extended_summary.read_text(encoding="utf-8"))
            if summary["runs"]["invalid"]:
                print(f"WARNING: {summary['runs']['invalid']} invalid run(s); "
                      "do not interpret official percentages without checking extended run_validity")
        except (OSError, ValueError, KeyError):
            print("WARNING: extended summary unreadable; official result is preserved")

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
        help="Attack target names. Extended v1 with --trace requires exactly one target."
    )
    parser.add_argument("--task_ids", help="Zero-based dataset indices, comma-separated (e.g. 0,2,7). Default: all")
    parser.add_argument("--attack_names", help="Optional comma-separated attack class names for focused smoke tests")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--trace", action="store_true", help="Write per-run JSONL trace")
    parser.add_argument("--trace_dir", default="logs/traces")
    parser.add_argument("--run_tag", default="")
    parser.add_argument("--model", help="Override model.yaml model_name for this run")
    parser.add_argument("--judge_model", help="Override judge.yaml model_name for this run")
    parser.add_argument("--shield-policy", help="Opt in to Shield with a host policy bundle JSON")
    parser.add_argument("--shield-mode", choices=("observe", "enforce"), default="observe")
    parser.add_argument("--shield-output", default="results_shield", help="Directory for Shield run traces")
    parser.add_argument("--shield-release-config", help="Host config for the final response gate")
    parser.add_argument("--answer-recovery", action="store_true", help="Allow one task-only final-answer recovery")
    args = parser.parse_args()
    if args.repeat < 1:
        parser.error("--repeat must be >= 1")
    if args.shield_mode == "enforce" and not args.shield_policy:
        parser.error("--shield-mode enforce requires --shield-policy")
    if args.trace and args.suite != "benign" and len(args.malicious_agents) != 1:
        parser.error("v1 trace/evaluation requires exactly one --malicious_agents target")
    if args.run_tag and not all(char.isalnum() or char in "_.-" for char in args.run_tag):
        parser.error("--run_tag may contain only letters, digits, underscores, dots and hyphens")
    main(args)

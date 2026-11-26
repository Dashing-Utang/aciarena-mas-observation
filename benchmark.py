import argparse
from copy import copy
from hashlib import sha256
import json
from pathlib import Path
from datetime import datetime, timezone
from uuid import uuid4
import subprocess
from tempfile import NamedTemporaryFile
from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent
load_dotenv(PROJECT_ROOT / ".env", override=False)

from aciarena.utils import build_suite
from aciarena.evaluation.answer_release import DATASET_NAMES, load_public_tasks


def session_id():
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S") + "_" + uuid4().hex[:8]


def write_result(path, result):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        try:
            json.dump(result, stream, indent=2, ensure_ascii=False)
        except BaseException:
            temporary.unlink()
            raise
    temporary.replace(path)


def preflight_defense(defense):
    if defense == "agrail":
        from aciarena.defenses.agrail import core_code, source_path

        core_code(source_path())
    elif defense == "bert_detector":
        from aciarena.defenses.bert_detector import BertDetector

        BertDetector()("This is a benign benchmark preflight.")


def release_settings(args, *, probe=False):
    from subagentshield.core.jev import JevClient

    path = Path(args.shield_release_config)
    release = json.loads(path.read_text(encoding="utf-8"))
    release_values = release["protected_values"]
    if not isinstance(release_values, list) or not release_values or not all(
        isinstance(v, str) and v for v in release_values
    ):
        raise ValueError("expected nonempty protected values")
    flow = json.loads((path.parent / release["flow_config"]).read_text(encoding="utf-8"))
    final = flow["final"]
    if not 0 <= final["allow_below"] < final["deny_at_or_above"] <= 1:
        raise ValueError("invalid final thresholds")
    cfg = flow["jev"]
    questions = release.get("review_questions", release.get("review_question", cfg["question"]))
    reviewer = JevClient(cfg["model"], cfg["timeout_seconds"], questions)
    if not reviewer.will_attempt_network():
        raise ValueError("Shield Release requires TYPESAFE_API_KEY")

    fingerprints = release.get("public_dataset_sha256", {})
    expected = fingerprints.get(args.task_domain)
    if args.task_domain == "code" and not expected:
        expected = release.get("public_code_dataset_sha256")
    catalog = {}
    if expected:
        dataset = PROJECT_ROOT / "aciarena/evaluation/datasets" / f"aciarena_{DATASET_NAMES[args.task_domain]}.json"
        catalog = load_public_tasks(dataset, expected, domain=args.task_domain, shuffle_seed=args.qa_shuffle_seed)
    if args.answer_recovery and not catalog:
        raise ValueError(f"No approved public recovery dataset configured for {args.task_domain}")
    if probe:
        reviewer.review(reviewer.payload(
            {"purpose": "Return the result of 1 + 1 to the requester.", "scope": {}},
            {"tool": "publish_final_response", "args": {"recipient": "requester", "body": "2"}},
        ))
    return release, release_values, final, reviewer, catalog


def main(args, *, preflight=True, code_verify=None):
    args.session_id = session_id()
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=PROJECT_ROOT,
                              capture_output=True, text=True, check=False)
    args.commit_sha = revision.stdout.strip() if revision.returncode == 0 else None
    state = subprocess.run(["git", "status", "--porcelain"], cwd=PROJECT_ROOT,
                           capture_output=True, text=True, check=False)
    args.worktree_dirty = bool(state.stdout.strip()) if state.returncode == 0 else None
    if preflight:
        preflight_defense(args.defense)
    args.dataset_sha256 = sha256((
        PROJECT_ROOT / "aciarena/evaluation/datasets" / f"aciarena_{DATASET_NAMES[args.task_domain]}.json"
    ).read_bytes()).hexdigest()
    shield_policy = getattr(args, "shield_policy", None)
    release_config = getattr(args, "shield_release_config", None)
    if release_config and not shield_policy:
        raise ValueError("--shield-release-config requires a Shield policy")
    settings = release_settings(args) if release_config else None
    suite = build_suite(args)
    suite.code_verify = code_verify
    args.model = suite.llm_config["model_name"]
    args.judge_model = suite.judge_config["model_name"]
    if shield_policy:
        from subagentshield.adapters.aciarena import ACIArenaAdapter, workflow_jobs

        framework = args.mas.lower()
        if framework not in ("camel", "metagpt"):
            raise ValueError("ACIArena Shield binding supports CAMEL and MetaGPT")
        if not getattr(suite.executor, "supports_mas_runtime", False):
            raise ValueError("The selected executor does not support a MAS runtime binding")
        policy = Path(shield_policy).read_bytes()
        args.shield_policy_sha256 = sha256(policy).hexdigest()
        if release_config:
            args.shield_release_config_sha256 = sha256(Path(release_config).read_bytes()).hexdigest()
        output = Path(args.shield_output) / args.session_id
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
        scope = {"tools": [], "jobs": workflow_jobs(framework)}
        release_values, reviewer, final = None, None, {"id": "aciarena-runtime"}
        if settings:
            release, release_values, final, reviewer, catalog = settings
            scope["tools"] = ["publish_final_response"]
            scope["arguments"] = {"publish_final_response": {"recipient": "requester"}}
            suite.mas_config["release_values"] = tuple(release_values)
            suite.mas_config["public_tasks"] = catalog

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
    directory = Path(getattr(args, "results_output", "results_extended")) / args.session_id
    extended_summary = directory / "summary.json"
    summary = None
    if args.trace and extended_summary.exists():
        try:
            summary = json.loads(extended_summary.read_text(encoding="utf-8"))
            if summary["runs"]["invalid"]:
                print(f"WARNING: {summary['runs']['invalid']} invalid run(s); "
                      "do not interpret official percentages without checking extended run_validity")
        except (OSError, ValueError, KeyError):
            print("WARNING: extended summary unreadable; official result is preserved")

    result_path = directory / "result.json"
    write_result(result_path, {"meta_data": vars(args), "result": result})
    print("Official result:", result_path)
    return result_path, result, summary


def comparison_arms(args):
    for condition in ("none", "bert_detector", "aci_sentinel", "agrail", "shield_release", "shield_release_recovery"):
        recovery = condition == "shield_release_recovery"
        if recovery and not args.answer_recovery:
            continue
        shield = condition.startswith("shield_")
        arm = copy(args)
        arm.defense = "none" if shield else condition
        arm.shield_policy = args.shield_policy if shield else None
        arm.shield_release_config = args.shield_release_config if shield else None
        arm.shield_mode = "enforce" if shield else "observe"
        arm.answer_recovery = recovery
        arm.trace = True
        yield condition, arm


def compare(args):
    if not args.shield_policy or not args.shield_release_config:
        raise ValueError("--compare requires --shield-policy and --shield-release-config")
    if args.mas.lower() not in {"camel", "metagpt"}:
        raise ValueError("--compare supports CAMEL and MetaGPT")
    if args.defense != "none":
        raise ValueError("--compare selects all defenses itself")
    if args.suite != "benign" and len(args.malicious_agents) != 1:
        raise ValueError("--compare on an attack suite requires exactly one target")
    arms = list(comparison_arms(args))
    config = json.loads(Path(args.shield_policy).read_bytes())
    if "publish_final_response" not in config.get("roles", {}).get("host_publisher", ()):
        raise ValueError("--compare requires a policy that authorizes host publication")
    # Validate suite selection (including unsupported suite/domain pairs) before services are called.
    build_suite(copy(args))
    preflight_defense("agrail")
    preflight_defense("bert_detector")
    code_verify = None
    if args.task_domain == "code":
        from scripts.live_smoke import isolated_verify, preflight as preflight_isolated_scorer

        preflight_isolated_scorer()
        code_verify = isolated_verify
    release_settings(arms[-1][1], probe=True)
    directory = Path(args.results_output) / "comparisons" / session_id()
    directory.mkdir(parents=True, mode=0o700)
    summary_path = directory / "summary.json"
    report = {"settings": vars(args), "arms": {}}
    for name, arm in arms:
        arm.results_output = str(directory / name)
        arm.output_dir = str(directory / name / "logs")
        path, official, extended = main(arm, preflight=False, code_verify=code_verify)
        report["arms"][name] = {"result": str(path), "official": official, "extended": extended}
        write_result(summary_path, report)
        if extended is None:
            raise RuntimeError(f"Missing per-run metrics for {name}: {path}")
    print("Comparison:", summary_path)
    return summary_path

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
    parser.add_argument("--compare", action="store_true", help="Run the selected suite once per guardrail with tracing")
    parser.add_argument("--qa-shuffle-seed", type=int, help="Run a separate QA variant with deterministically shuffled choices")
    parser.add_argument("--results-output", default="results_extended", help="Directory for session and comparison results")
    args = parser.parse_args()
    if args.repeat < 1:
        parser.error("--repeat must be >= 1")
    if args.qa_shuffle_seed is not None and args.task_domain not in {"sci", "medicine"}:
        parser.error("--qa-shuffle-seed requires sci or medicine")
    if args.shield_mode == "enforce" and not args.shield_policy:
        parser.error("--shield-mode enforce requires --shield-policy")
    if args.trace and args.suite != "benign" and len(args.malicious_agents) != 1:
        parser.error("v1 trace/evaluation requires exactly one --malicious_agents target")
    if args.run_tag and not all(char.isalnum() or char in "_.-" for char in args.run_tag):
        parser.error("--run_tag may contain only letters, digits, underscores, dots and hyphens")
    if args.compare:
        compare(args)
    else:
        main(args)

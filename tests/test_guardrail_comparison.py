"""Offline regressions for comparison accounting, QA, and publication recovery."""

import json
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import benchmark
from aciarena.agent_components.llms.openai_llm import OpenAILLM
from aciarena.defenses.bert_detector import BertDetector
from aciarena.evaluation.answer_release import DATASET_NAMES, load_public_tasks, release_task_answer
from aciarena.evaluation.extended_evaluator import evaluate
from aciarena.evaluation.qa_options import explicit_answer, shuffle_options
from aciarena.observability.trace import record_agent_output, record_llm_request
import pytest


DATASETS = Path(__file__).resolve().parents[1] / "aciarena/evaluation/datasets"


def test_option_shuffle_preserves_answers_and_rejects_prose():
    rows = json.loads((DATASETS / "aciarena_sci.json").read_text())
    grades = set()
    for index, row in enumerate(rows):
        assert row["answer"] == "A"
        query, gold = shuffle_options(row["problem"], row["answer"], 37, index)
        assert shuffle_options(row["problem"], row["answer"], 37, index) == (query, gold)
        assert f"({gold}) {row['problem'].split('(A) ')[-1].splitlines()[0]}" in query
        assert explicit_answer(f"ANSWER: {gold}", query) == gold
        assert explicit_answer("I cannot answer this question.", query) is None
        assert explicit_answer("ANSWER: Another answer", query) is None
        assert explicit_answer("ANSWER: A\nANSWER: B", query) is None
        grades.add(gold)
    assert grades == {"A", "B", "C", "D"}


@pytest.mark.parametrize("domain", DATASET_NAMES)
def test_protected_recovery_uses_approved_query_for_each_domain(domain):
    path = DATASETS / f"aciarena_{DATASET_NAMES[domain]}.json"
    seed = 37 if domain in {"sci", "medicine"} else None
    catalog = load_public_tasks(path, sha256(path.read_bytes()).hexdigest(), domain=domain, shuffle_seed=seed)
    task_id = f"{domain}_T01"
    query = catalog[task_id]
    gate = Mock(side_effect=[
        SimpleNamespace(status="blocked", reason="protected_output", value=None, request_id="1"),
        SimpleNamespace(status="executed", reason="allowed", value="new answer", request_id="2"),
    ])
    generate = Mock(return_value="new answer")
    result = release_task_answer(
        "fixture private draft", binding=SimpleNamespace(enforce=True, release_outcome=gate),
        defense="none", original=query, task_id=task_id, catalog=catalog,
        protected_values=["fixture private"], generate=generate, record=Mock(),
    )
    assert result == "new answer"
    generate.assert_called_once_with(query)
    assert gate.call_count == 2


def test_bert_inference_error_is_propagated(monkeypatch):
    detector = object.__new__(BertDetector)
    monkeypatch.setattr(detector, "pipeline", Mock(side_effect=ValueError("bad inference")), raising=False)
    with pytest.raises(RuntimeError, match="BERT classification failed"):
        detector._detect("fixture")


def test_known_empty_defense_block_is_a_valid_result(monkeypatch):
    events = [
        {"event_id": str(i), "event_type": event, "data": {"terminal": True},
         "sequence": i, "run_id": "r"}
        for i, event in enumerate(
            ("RUN_START", "TERMINATION", "FINAL_RESPONSE", "OFFICIAL_TASK_VERIFY", "OFFICIAL_ATTACK_VERIFY"), 1
        )
    ]
    monkeypatch.setattr("aciarena.evaluation.extended_evaluator.read_trace", lambda _: events)
    result = evaluate({"run_id": "r", "mas_name": "metagpt"}, SimpleNamespace(attack_surface="none"),
                      "", 0, defense_blocked=True)
    assert (result["run_validity"], result["run_outcome"]) == ("VALID", "DEFENSE_BLOCKED")


def test_comparison_runs_each_arm_and_isolates_artifacts(tmp_path, monkeypatch):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"roles": {"host_publisher": ["publish_final_response"]}}))
    args = SimpleNamespace(
        mas="metagpt", task_domain="sci", suite="benign", defense="none",
        shield_policy=str(policy), shield_release_config="host-config.json", answer_recovery=True,
        malicious_agents=[], task_ids="0,1", repeat=2, results_output=str(tmp_path),
    )
    monkeypatch.setattr(benchmark, "preflight_defense", Mock())
    monkeypatch.setattr(benchmark, "release_settings", Mock())
    monkeypatch.setattr(benchmark, "build_suite", Mock())
    settings = []

    def fixture_main(arm, **kwargs):
        settings.append(arm)
        result = Path(arm.results_output) / "result.json"
        benchmark.write_result(result, {})
        return result, {"Benign Utility": "100.0000"}, {"runs": {"invalid": 0}}

    monkeypatch.setattr(benchmark, "main", fixture_main)
    path = benchmark.compare(args)
    report = json.loads(path.read_text())
    assert list(report["arms"]) == [
        "none", "bert_detector", "aci_sentinel", "agrail", "shield_release", "shield_release_recovery",
    ]
    assert len({arm.results_output for arm in settings}) == 6
    assert all(arm.task_ids == "0,1" and arm.repeat == 2 and arm.trace for arm in settings)
    assert [arm.shield_mode for arm in settings] == ["observe"] * 4 + ["enforce"] * 2
    assert [arm.answer_recovery for arm in settings] == [False] * 5 + [True]


def test_metagpt_math_uses_real_loader_scheduler_and_grader(tmp_path, monkeypatch):
    config = {"model_name": "fixture", "provider": "openai"}
    monkeypatch.setattr("aciarena.evaluation.evaluation_suite.load_llm_config", lambda _: config.copy())
    monkeypatch.setattr(OpenAILLM, "from_config", lambda self, _: self)
    gold = json.loads((DATASETS / "aciarena_math.json").read_text())[0]["answer"]
    final = r"$\boxed{" + gold + "}$"
    seen_profiles = []

    def respond(self, messages, *args, **kwargs):
        profile = messages[0]["content"]
        seen_profiles.append(profile)
        req = record_llm_request(self.model_name, messages)
        reply = final if "final answer alone" in profile else "intermediate work"
        record_agent_output(reply, req)
        return reply

    monkeypatch.setattr(OpenAILLM, "call_llm", respond)
    args = SimpleNamespace(
        mas="metagpt", task_domain="math", suite="benign", attack_mode="continuous",
        defense="none", malicious_agents=[], max_workers=1, repeat=1,
        task_ids="0", trace=True, trace_dir=str(tmp_path / "traces"),
        output_dir=str(tmp_path / "logs"), results_output=str(tmp_path / "results"),
        model=None, judge_model=None,
    )
    path, official, extended = benchmark.main(args)
    assert official["Benign Utility"] == "100.0000"
    assert extended["execution_counts"] == {"correct": 1}
    assert len(seen_profiles) == 5
    row = json.loads(path.with_name("runs.jsonl").read_text())
    assert row["task_profile"] == "metagpt_math_v1"

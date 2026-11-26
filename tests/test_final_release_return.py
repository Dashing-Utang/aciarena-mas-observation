from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import Mock, patch
import unittest

from aciarena.evaluation.task_executor import ContinuousAttackExecutor
from aciarena.evaluation.answer_release import (approved_public_query, code_only_publication, generate_task_answer,
                                               load_public_code_tasks, recoverable_answer, release_task_answer)
from aciarena.observability.trace import EVENT_TYPES


class ReturnBoundaryTests(unittest.TestCase):
    def test_public_catalog_requires_exact_original_and_host_fingerprint(self):
        from hashlib import sha256
        from pathlib import Path
        from tempfile import TemporaryDirectory
        with TemporaryDirectory() as tmp:
            p = Path(tmp) / "dataset.json"
            p.write_bytes(b'[{"problem":"public task","answer":"not passed to model"}]')
            with self.assertRaises(ValueError):
                load_public_code_tasks(p, "wrong")
            catalog = load_public_code_tasks(p, sha256(p.read_bytes()).hexdigest())
        self.assertEqual(approved_public_query(catalog, "code_T01", "public task", ("SECRET",)), "public task")
        for task, original, secrets in [("x", "public task", ("SECRET",)), ("code_T01", "public task edited", ("SECRET",)),
                                        ("code_T01", "public task", ("PUBLIC",)), ("code_T01", "public task", ())]:
            self.assertIsNone(approved_public_query(catalog, task, original, secrets))

    def test_protected_recovery_is_task_only_gated_and_bounded(self):
        blocked = SimpleNamespace(status="blocked", reason="protected_output", value=None, request_id="one")
        allowed = SimpleNamespace(status="executed", reason="ok", value="published", request_id="two")
        grant_denied = SimpleNamespace(status="blocked", reason="grant_missing_or_invalid", value=None, request_id="no")
        for public, decisions, count, expected in [
            ("public", [blocked, allowed], 1, "published"), ("public", [blocked, blocked], 1, ""),
            (None, [blocked], 0, ""), ("public", [grant_denied], 0, ""),
        ]:
            llm = Mock()
            llm.call_llm.return_value = "new candidate"
            gate = Mock(side_effect=decisions)
            result = release_task_answer("private draft", binding=SimpleNamespace(enforce=True, release_outcome=gate),
                       defense="none", original="public", task_id="code_T01",
                       catalog={"code_T01":public}, protected_values=("private",),
                       generate=lambda query: generate_task_answer(llm, query, "none"), record=Mock())
            self.assertEqual(result, expected)
            self.assertEqual(len(gate.call_args_list), 1+count)
            self.assertEqual(llm.call_llm.call_count, count)
            if count:
                messages, = llm.call_llm.call_args.args
                self.assertEqual([m["role"] for m in messages], ["system", "user"])
                self.assertEqual(messages[1]["content"], "public")
                self.assertNotIn("private draft", str(messages))
                self.assertEqual(gate.call_args.args, ("new candidate",))

    def test_only_unambiguous_python_submission_is_formatted(self):
        code = "```python\ndef solve():\n    return 1\n```"
        self.assertEqual(code_only_publication("Solution:\n"+code+"\nNext request."), code)
        for draft in [code+"\n"+code, "no fence", "```python\nunfinished"]:
            self.assertEqual(code_only_publication(draft), draft)

    def test_executor_recovers_from_original_public_prompt_only(self):
        config = SimpleNamespace(trace=False, suite="benign", mas="camel", task_domain="code",
                                 defense="none", malicious_agents=[], max_workers=1, shield_mode="enforce",
                                 answer_recovery=True)
        task = SimpleNamespace(task_id="code_T01", get_query=Mock(side_effect=["public task"]), get_gt=lambda: {})
        attack = Mock(attack_surface="none")
        mas = Mock()
        mas.bootstrap.return_value = ({"response": "private value", "conversation": ["private history"]}, True)
        mas.conclude.side_effect = lambda a: a
        mas.get_token_usage.return_value = {"input_tokens": 0, "output_tokens": 0}
        runtime = Mock(enforce=True)
        runtime.release_outcome.side_effect = [
            SimpleNamespace(status="blocked", reason="protected_output", value=None, request_id="one"),
            SimpleNamespace(status="executed", reason="allowed", value="approved", request_id="two"),
        ]
        llm = Mock(input_tokens=7, output_tokens=1)
        llm.call_llm.return_value = "new"
        with patch("aciarena.evaluation.task_executor.build_mas", return_value=mas), \
             patch("aciarena.agent_components.get_llm", return_value=llm):
            result = ContinuousAttackExecutor([attack]).execute(
                dict(args=config, logger=None, llm_config={"model_name":"fixture"}, release_values=("private value",),
                     public_code_tasks={"code_T01":"public task"}, bind_runtime=lambda *a: nullcontext(runtime)), task)
        answer, = result["utility"]
        self.assertEqual(answer["response"], "approved")
        self.assertIsNone(answer["_error"])
        self.assertEqual(answer["token_usage"]["total_tokens"], 8)
        messages, = llm.call_llm.call_args.args
        self.assertEqual(messages[1], {"role":"user", "content":"public task"})
        self.assertNotIn("private", str(messages))
        self.assertNotIn("conversation", answer)
        self.assertEqual([call.args[0] for call in runtime.release_outcome.call_args_list], ["private value", "new"])

    def test_only_soft_hold_and_blanked_baseline_recover(self):
        self.assertIn("ANSWER_RELEASE", EVENT_TYPES)
        def reply(status, reason, value=None):
            return SimpleNamespace(status=status, reason=reason, value=value, request_id="r")
        for decisions, expected, generations, gate_calls in (
            ([reply("held", "probability_in_review_range"),
              reply("held", "probability_in_review_range"),
              reply("executed", "allowed", "safe")], "safe", 1, 3),
            ([reply("held", "probability_in_review_range"),
              reply("executed", "allowed", "draft")], "draft", 0, 2),
            ([reply("held", "task_abandonment_at_or_above_deny_threshold"),
              reply("held", "task_abandonment_in_review_range"),
              reply("executed", "allowed", "safe")], "safe", 1, 3),
            ([reply("blocked", "protected_output")], "", 0, 1),
            ([reply("executed", "allowed", "ordinary answer")], "ordinary answer", 0, 1),
        ):
            gate = Mock(side_effect=decisions)
            generate = Mock(return_value="safe")
            audit = Mock()
            self.assertEqual(recoverable_answer("draft", gate=gate, defense="none", regenerate=generate,
                                                record=audit), expected)
            self.assertEqual(generate.call_count, generations)
            self.assertEqual(gate.call_count, gate_calls)
            self.assertEqual(audit.call_count, generations+1)
            first_record = audit.call_args_list[0].kwargs
            self.assertEqual(first_record["review_attempts"], min(gate_calls, 2))
            self.assertEqual(
                len(first_record["review_history"]), first_record["review_attempts"]
            )
        self.assertEqual(recoverable_answer("", gate=None, defense="none", regenerate=lambda:"fixed",
                                            record=Mock()), "fixed")
        generate = Mock()
        with self.assertRaises(RuntimeError):
            recoverable_answer("draft", gate=Mock(return_value=reply("held", "jev_error")), defense="none",
                               regenerate=generate, record=Mock())
        generate.assert_not_called()

    def run_case(self, fail=False):
        config = SimpleNamespace(trace=False, suite="benign", mas="camel", task_domain="code",
                                 defense="none", malicious_agents=[], max_workers=1, shield_mode="enforce")
        attack = Mock()
        attack.attack_surface = "none"
        task = SimpleNamespace(task_id="code_T01", get_query=lambda: "original task", get_gt=lambda: {})
        mas = Mock()
        mas.bootstrap.return_value = ({"response": "private draft", "conversation": ["internal"]}, True)
        mas.conclude.side_effect = RuntimeError("private draft") if fail else lambda a: a
        runtime = Mock()
        runtime.release_response.return_value = "returned by gate"
        executor = ContinuousAttackExecutor([attack])
        with patch("aciarena.evaluation.task_executor.build_mas", return_value=mas):
            answer = executor.execute(dict(args=config, llm_config={"model_name": "fixture"},
                                           logger=None, release_values=("private draft",),
                                           bind_runtime=lambda *a: nullcontext(runtime)), task)["utility"][0]
        self.assertNotIn("conversation", answer)
        return runtime, answer

    def test_delivered_value_is_the_scored_response(self):
        runtime, answer = self.run_case()
        runtime.release_response.assert_called_once_with("private draft")
        self.assertEqual(answer["response"], "returned by gate")

    def test_exception_never_publishes_previous_turn(self):
        runtime, answer = self.run_case(fail=True)
        runtime.release_response.assert_not_called()
        self.assertEqual(answer["response"], "")
        self.assertEqual(answer["_error"]["message"], "RuntimeError")

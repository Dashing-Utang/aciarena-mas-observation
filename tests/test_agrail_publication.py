"""Offline contracts for fail-closed publication and the pinned AGrail core."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from aciarena.defenses.agrail import AGrailPublicationGuard, core_code, source_path
from aciarena.evaluation.answer_release import release_task_answer
from aciarena.evaluation.task_executor import ContinuousAttackExecutor


class AGrailPublicationTests(unittest.TestCase):
    def test_verify_source_before_loading(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "guardrail.py"
            path.write_text("raise RuntimeError('unverified source')")
            with self.assertRaisesRegex(ValueError, "fingerprint"):
                core_code(path)

    def test_prior_policy_denial_does_not_send_draft_to_external_review(self):
        guard = Mock()
        local = Mock(enforce=True)
        local.release_outcome.return_value = SimpleNamespace(status="blocked", value=None, reason="not_authorized", request_id="r")
        answer = release_task_answer("private", binding=local, original="task", task_id="t", catalog=None,
                                     protected_values=[], defense="agrail", generate=None, record=Mock(), publication_guard=guard)
        self.assertEqual(answer, "")
        guard.review.assert_not_called()

    def test_executor_discards_draft_on_guard_error_without_recovery(self):
        cfg = SimpleNamespace(trace=False, suite="benign", mas="camel", task_domain="code", defense="agrail",
                              malicious_agents=[], max_workers=1, answer_recovery=False)
        task = SimpleNamespace(task_id="code_T01", get_query=lambda: "public", get_gt=lambda: {})
        mas = Mock()
        mas.bootstrap.return_value = ({"response": "private draft", "conversation": ["private history"]}, True)
        mas.conclude.side_effect = lambda state: state
        mas.get_token_usage.return_value = {"input_tokens": 0, "output_tokens": 0}
        with patch("aciarena.evaluation.task_executor.build_mas", return_value=mas), \
             patch("aciarena.defenses.aci_sentinel.defense_reviewer"), \
             patch("aciarena.defenses.agrail.AGrailPublicationGuard") as factory:
            factory.return_value.review.side_effect = ValueError("draft details")
            result = ContinuousAttackExecutor([Mock(attack_surface="none")]).execute(
                {"args": cfg, "logger": None, "llm_config": {"model_name":"fixture"}}, task)["utility"][0]
        self.assertEqual(result["response"], "")
        self.assertNotIn("conversation", result)
        self.assertEqual(result["_error"]["message"], "ValueError")

    @unittest.skipUnless(source_path().is_file(), "requires optional pinned AGrail source")
    def test_authors_executor_and_verdict_round_trip(self):
        for value, allowed in [("True", True), ("False", False)]:
            with self.subTest(value=value):
                llm = Mock(model_name="fixture")
                steps = [{"Check Item":"scope [scope]", "Thinking":"test [ ]", "Delete":"False", "Tool Call":"False", "Result":value}]
                executor = {"steps":steps, "selected_checklist":{"Action":"publish", "groups":[
                    {"category":"Integrity", "items":[{"name":"scope","definition":"literal [ ]"}]}]}}
                llm.call_llm.side_effect = [json.dumps({"Action":"publish","Integrity":{"scope":"check task"}}), json.dumps(executor)]
                decision = AGrailPublicationGuard(llm).review("task", "candidate")
                self.assertEqual(decision["allowed"], allowed)
                self.assertEqual(decision["checks"], 1)
                self.assertTrue(llm.call_llm.call_args.kwargs["json_schema"]["strict"])


if __name__ == "__main__":
    unittest.main()

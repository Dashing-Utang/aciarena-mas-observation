import unittest
from types import SimpleNamespace
from unittest.mock import patch

from aciarena.evaluation.task import CodeTask
from aciarena.evaluation.task_executor import ContinuousAttackExecutor


def guarded(name):
    agent = SimpleNamespace()
    mas = SimpleNamespace(agents={"actor": agent}, get_agent=lambda key: agent)
    ContinuousAttackExecutor([]).load_defense(SimpleNamespace(defense=name), "sum", mas)
    return agent.post_step


class TextGuardContract(unittest.TestCase):
    def test_delimiter_preserves_scalar_and_choice_boundaries(self):
        guard = guarded("delimiter")
        self.assertEqual(guard([]), [])
        self.assertIsInstance(guard("alpha"), str)
        self.assertIn("alpha", guard("alpha"))
        self.assertEqual(guard(["alpha", "beta"]), [guard("alpha"), guard("beta")])

    def test_bert_can_block_one_choice_and_keep_its_neighbor(self):
        from aciarena.defenses.bert_detector import BertDetector

        def classify(_, text):
            self.assertIsInstance(text, str)
            return text == "marked", 0.5

        with (
            patch.object(BertDetector, "__init__", return_value=None),
            patch.object(BertDetector, "__call__", classify),
        ):
            guard = guarded("bert_detector")
            block = "<Message blocked because a prompt injection attack was detected>"
            self.assertEqual(guard(["marked", "okay"]), [block, "okay"])
            self.assertEqual(guard("marked"), block)
            self.assertEqual(guard([]), [])

    def test_sentinel_keeps_an_intentionally_empty_choice(self):
        with patch(
            "aciarena.evaluation.task_executor.ACISentinel",
            return_value=lambda text: "" if text == "omit" else text,
        ):
            guard = guarded("aci_sentinel")
            self.assertEqual(guard(["omit", "keep"]), ["", "keep"])
            self.assertEqual(guard("omit"), "")
            self.assertEqual(guard([]), [])

    def test_humaneval_extraction_preserves_input_without_a_signature(self):
        task = CodeTask("sum", {})
        for answer in ("", "<", "    return 1", "bare text"):
            self.assertEqual(task.extract_answer(answer), answer)
        code = "def example():\n    return 1\n"
        self.assertEqual(
            task.extract_answer("```python\n" + code + "```"), "    return 1\n"
        )
        self.assertEqual(task.extract_answer(code, mbpp=True), code)


if __name__ == "__main__":
    unittest.main()

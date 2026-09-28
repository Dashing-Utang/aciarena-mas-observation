import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from aciarena.attacks.hijacking_attack import SafetyCheckInstruction
from aciarena.mas.cai import CAI
from aciarena.observation import ObservationSink


class FakeLLM:
    def __init__(self, response):
        self.response = response
        self.input_tokens = 0
        self.output_tokens = 0

    def call_llm(self, messages, **kwargs):
        return self.response


class ExperimentObservationTest(unittest.TestCase):
    def test_cai_handoff_tool_and_verify_events(self):
        config = {
            "provider": "openai",
            "api_key": "test",
            "base_url": "http://127.0.0.1:1/v1",
            "model_name": "test",
        }
        args = SimpleNamespace()

        with tempfile.TemporaryDirectory() as directory:
            events_path = Path(directory) / "events.jsonl"
            sink = ObservationSink(events_path)
            mas = CAI(config, logger=None, malicious_agents=["security_agent"])
            mas.set_observer(sink.start_run("cai", "SafetyCheckInstruction"))
            mas.get_agent("orchestrator").llm = FakeLLM("handoff packet")
            mas.get_agent("security_agent").llm = FakeLLM(
                "```python\ndef safety_check():\n    pass\n```"
            )

            attack = SafetyCheckInstruction(args=args, llm_config=config)
            attack.run(mas)
            answer = mas.run("implement a function")
            attack.set_answer(answer)
            success = attack.verify()
            attack.observer.record_verification(bool(success))

            events = [
                json.loads(line) for line in events_path.read_text().splitlines()
            ]
            event_names = [event["event"] for event in events]
            self.assertIn("attack_injected", event_names)
            self.assertIn("handoff", event_names)
            self.assertIn("tool_start", event_names)
            self.assertIn("tool_end", event_names)
            self.assertTrue(events[-1]["attack_success"])
            self.assertEqual(events[-1]["observed_events"], 5)


if __name__ == "__main__":
    unittest.main()

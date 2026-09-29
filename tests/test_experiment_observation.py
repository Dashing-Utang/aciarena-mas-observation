import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

os.environ.setdefault("OPENAI_API_KEY", "sk-aciarena-test-placeholder")

from cai.agents.codeagent import CodeAgent
from cai.sdk.agents import Agent, HandoffInputData, RunContextWrapper

from aciarena.attacks.hijacking_attack import SafetyCheckInstruction
from aciarena.mas.cai import CAI
from aciarena.observation import ObservationSink


class ExperimentObservationTest(unittest.TestCase):
    def test_official_cai_handoff_tool_and_verify_events(self):
        config = {
            "provider": "openai",
            "api_key": "test",
            "base_url": "http://127.0.0.1:1/v1",
            "model_name": "test",
            "temperature": 0,
            "max_tokens": 64,
        }
        args = SimpleNamespace()

        with tempfile.TemporaryDirectory() as directory:
            events_path = Path(directory) / "events.jsonl"
            sink = ObservationSink(events_path)
            mas = CAI(config, logger=None, malicious_agents=["codeagent"])
            mas.set_observer(sink.start_run("cai", "SafetyCheckInstruction"))

            attack = SafetyCheckInstruction(args=args, llm_config=config)
            attack.run(mas)
            run_args, _ = mas.bootstrap("implement a function")
            selection_agent, code_agent, hooks = mas._build_runtime()

            self.assertIsInstance(selection_agent, Agent)
            self.assertIsInstance(code_agent, CodeAgent)

            handoff_data = HandoffInputData(
                input_history=run_args["query"],
                pre_handoff_items=(),
                new_items=(),
            )
            transformed = selection_agent.handoffs[0].input_filter(handoff_data)
            self.assertIn("safety_check", transformed.input_history)

            async def emit_official_callbacks():
                context = RunContextWrapper(context=None)
                tool = code_agent.tools[0]
                response = "```python\ndef safety_check():\n    pass\n```"
                await hooks.on_agent_start(context, selection_agent)
                await hooks.on_handoff(context, selection_agent, code_agent)
                await hooks.on_agent_start(context, code_agent)
                await hooks.on_tool_start(context, code_agent, tool)
                await hooks.on_tool_end(context, code_agent, tool, response)
                await hooks.on_agent_end(context, code_agent, response)

            asyncio.run(emit_official_callbacks())
            run_args["response"] = "```python\ndef safety_check():\n    pass\n```"
            answer = mas.conclude(run_args)
            attack.set_answer(answer)
            success = attack.verify()
            attack.observer.record_verification(bool(success))

            events = [
                json.loads(line) for line in events_path.read_text().splitlines()
            ]
            event_names = [event["event"] for event in events]
            self.assertIn("runtime_initialized", event_names)
            self.assertIn("attack_injected", event_names)
            self.assertIn("handoff", event_names)
            self.assertIn("tool_start", event_names)
            self.assertIn("tool_end", event_names)
            self.assertTrue(events[-1]["attack_success"])
            self.assertEqual(events[-1]["observed_events"], 8)
            self.assertEqual(events[1]["runtime"], "cai-framework")


if __name__ == "__main__":
    unittest.main()

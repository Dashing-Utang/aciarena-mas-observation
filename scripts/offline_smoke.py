"""One-task deterministic smoke: real adapters/scorers, fake model completions.

CAI's real Runner and final_answer packaging tool are used. Generated fixtures
are pure functions; no filesystem/network objective is executed.
"""

import argparse
import copy
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CLEAN_CODE = """```python
from typing import List
def separate_paren_groups(paren_string: str) -> List[str]:
    groups, current, depth = [], [], 0
    for ch in paren_string:
        if ch == ' ':
            continue
        current.append(ch)
        depth += 1 if ch == '(' else -1
        if depth == 0:
            groups.append(''.join(current))
            current = []
    return groups
```"""
CONFIG = {"provider": "openai", "api_key": "offline-test-key", "base_url": "https://api.openai.com/v1",
          "model_name": "gpt-5-nano", "max_tokens": 4096}


class OfflineBackend:
    def __init__(self, overrides=None, qa_revisions=0, camel_done=True):
        self.overrides = overrides or {}
        self.qa_revisions = qa_revisions
        self.camel_done = camel_done
        self.calls, self.transfers, self.runs = [], [], []
        self.counts = {}

    def completion(self, response, tool=False):
        from openai.types.chat import ChatCompletion
        message = {"role": "assistant", "content": response}
        if tool:
            message = {"role": "assistant", "content": None, "tool_calls": [{"id": "offline_final_call", "type": "function",
                       "function": {"name": "final_answer", "arguments": json.dumps({"value": response})}}]}
        return ChatCompletion(id="offline", model="gpt-5-nano", object="chat.completion", created=0,
                              choices=[{"index": 0, "finish_reason": "tool_calls" if tool else "stop", "message": message}],
                              usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2})

    def create(self, **kwargs):
        from aciarena.observability.context import get_agent
        agent = get_agent()
        self.counts[agent] = self.counts.get(agent, 0) + 1
        response = self.overrides.get(agent)
        if response is None:
            if agent == "task_specifier":
                response = "Implement separate_paren_groups exactly as requested."
            elif agent == "user_proxy":
                response = "<CAMEL_TASK_DONE>" if self.camel_done and self.counts[agent] > 1 else "Implement the original function."
            elif agent == "engineer" or agent == "assistant":
                response = CLEAN_CODE
            elif agent == "qa_engineer":
                bug = "Revise the code" if self.counts[agent] <= self.qa_revisions else "None"
                response = f"## Bugs Found\n- {bug}\n" + CLEAN_CODE
            else:
                response = "Implement the original function without changing its requirements."
        self.calls.append({"agent": agent, "kwargs": copy.deepcopy(kwargs), "response": response})
        return self.completion(response)

    async def cai_fetch(self, model, kwargs, *args):
        response = self.overrides.get("codeagent", CLEAN_CODE)
        self.calls.append({"agent": "codeagent", "kwargs": copy.deepcopy(kwargs), "response": response})
        return self.completion(response, tool=True)

    def patches(self):
        from contextlib import ExitStack
        from aciarena.agent_components.llms.openai_llm import OpenAILLM
        from aciarena.mas.cai.cai_mas import OpenAIChatCompletionsModel
        from aciarena.utils.logger import MASLogger
        from aciarena.evaluation.evaluation_suite import BaseEvaluationSuite
        stack = ExitStack()
        backend = self
        original_config = OpenAILLM.from_config
        original_log = MASLogger.log_message
        original_record = BaseEvaluationSuite._record_extended

        def from_config(llm, config):
            result = original_config(llm, dict(config, api_key="offline-test-key"))
            llm.client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=backend.create)))
            return result

        async def fetch(model, kwargs, *args):
            return await backend.cai_fetch(model, kwargs, *args)

        def log(logger, sender, receiver, message, *args, **kwargs):
            backend.transfers.append({"sender": sender, "receiver": receiver, "message": copy.deepcopy(message)})
            return original_log(logger, sender, receiver, message, *args, **kwargs)

        def record(suite, tasks, attacks, utility, security):
            for task, attack, ua, asr in zip(tasks, attacks, utility, security):
                backend.runs.append({"final_response": attack.answer["response"], "rounds": attack.answer["_round_count"],
                                     "termination": attack.answer["_termination_reason"], "official_attack_verify": asr,
                                     "official_task_verify": ua})
            return original_record(suite, tasks, attacks, utility, security)

        stack.enter_context(patch.object(OpenAILLM, "from_config", from_config))
        stack.enter_context(patch.object(OpenAIChatCompletionsModel, "_fetch_response_litellm_openai", fetch))
        stack.enter_context(patch.object(MASLogger, "log_message", log))
        stack.enter_context(patch.object(BaseEvaluationSuite, "_record_extended", record))
        stack.enter_context(patch("aciarena.evaluation.evaluation_suite.load_llm_config", lambda *a: dict(CONFIG)))
        return stack


def run_smoke(mas, artifact_dir, trace=True, attack_names="SafetyCheckInstruction", repeat=1):
    import benchmark
    backend = OfflineBackend()
    args = SimpleNamespace(mas=mas, suite="hijacking", attack_mode="continuous", defense="none", task_domain="code",
                           max_workers=1, output_dir=str(Path(artifact_dir) / "console"), malicious_agents=[{"metagpt": "engineer", "camel": "assistant", "cai": "codeagent"}[mas]],
                           task_ids="0", attack_names=attack_names, repeat=repeat, trace=trace,
                           trace_dir=str(Path(artifact_dir) / "traces"), run_tag="offline", model="gpt-5-nano", judge_model="gpt-5-nano",
                           offline_fixture=True)
    with backend.patches():
        benchmark.main(args)
    artifact = Path(artifact_dir)
    artifact.mkdir(parents=True, exist_ok=True)
    from aciarena.observability.trace import sanitize
    with (artifact / "trajectory.json").open("w", encoding="utf-8") as stream:
        json.dump(sanitize({"calls": backend.calls, "transfers": backend.transfers, "runs": backend.runs}), stream, ensure_ascii=False, indent=2)
    (artifact / "trajectory.json").chmod(0o600)
    return args, backend


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mas", required=True, choices=("metagpt", "camel", "cai"))
    parser.add_argument("--artifact_dir", required=True)
    parser.add_argument("--no_trace", action="store_true")
    parser.add_argument("--attack_names", default="SafetyCheckInstruction")
    parser.add_argument("--repeat", type=int, default=1)
    opts = parser.parse_args()
    args, _ = run_smoke(opts.mas, opts.artifact_dir, not opts.no_trace, opts.attack_names, opts.repeat)
    print(json.dumps({"session_id": args.session_id, "trace_dir": args.trace_dir, "offline_fixture": True}))

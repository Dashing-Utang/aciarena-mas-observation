"""Official CAI Framework adapter for ACIArena.

The adapter preserves ACIArena's BaseMAS and attack contracts while executing the
workflow with Alias Robotics CAI's Agent, CodeAgent, Runner, handoff, function-tool,
and RunHooks implementations.
"""

from __future__ import annotations

import asyncio
import json
import os
from importlib.metadata import version
from typing import Any

from openai import AsyncOpenAI

# The official CAI package constructs some built-in agents during imports. Its own
# documentation permits a placeholder key for local providers; CAI.__init__ replaces
# this value with the benchmark configuration before any model call is made.
os.environ.setdefault("OPENAI_API_KEY", "sk-aciarena-local-placeholder")

from cai.sdk.agents import (
    Agent,
    HandoffInputData,
    ModelSettings,
    OpenAIChatCompletionsModel,
    RunConfig,
    RunContextWrapper,
    RunHooks,
    Runner,
    Tool,
    function_tool,
    handoff,
)

from aciarena.mas import BaseMAS
from aciarena.mas.cai.agents import CodeAgentSurface, SelectionAgentSurface
from aciarena.utils.factory import register_mas


OFFICIAL_CAI_VERSION = version("cai-framework")
OFFICIAL_CAI_COMMIT = "6dc79257777f5f1c9500b4d2319935d34a47412e"


@function_tool
def final_answer(value: str) -> str:
    """Submit the complete code solution as the final answer.

    Args:
        value: Complete final response, including the Python implementation.
    """

    return value


class ACIArenaCAIHooks(RunHooks):
    """Map official CAI lifecycle callbacks to the common ACIArena observer."""

    def __init__(self, mas: "CAI"):
        self.mas = mas

    async def on_agent_start(self, context, agent: Agent) -> None:
        self.mas._observe(
            "cai_runner",
            agent.name,
            "agent_start",
            self.mas.latest_runtime_message,
        )

    async def on_agent_end(self, context, agent: Agent, output: Any) -> None:
        message = str(output)
        self.mas.latest_runtime_message = message
        self.mas._observe(agent.name, "cai_runner", "agent_end", message)

    async def on_handoff(self, context, from_agent: Agent, to_agent: Agent) -> None:
        self.mas._observe(
            from_agent.name,
            to_agent.name,
            "handoff",
            self.mas.latest_runtime_message,
            handoff=f"transfer_to_{to_agent.name.lower().replace(' ', '_')}",
        )

    async def on_tool_start(self, context, agent: Agent, tool: Tool) -> None:
        self.mas._observe(
            agent.name,
            tool.name,
            "tool_start",
            self.mas.latest_runtime_message,
            tool=tool.name,
            invocation_mode=self.mas.tool_invocation_mode,
        )

    async def on_tool_end(
        self,
        context,
        agent: Agent,
        tool: Tool,
        result: str,
    ) -> None:
        self.mas.latest_runtime_message = str(result)
        self.mas._observe(
            tool.name,
            agent.name,
            "tool_end",
            str(result),
            tool=tool.name,
            invocation_mode=self.mas.tool_invocation_mode,
        )


@register_mas("cai")
class CAI(BaseMAS):
    """Run an ACIArena task through the official CAI Framework runtime."""

    def __init__(
        self,
        llm_config,
        logger=None,
        malicious_agents=("codeagent",),
        max_turn=1,
    ):
        self.runtime_max_turns = int(os.getenv("ACI_ARENA_CAI_MAX_TURNS", "4"))
        self.latest_runtime_message = ""
        self.runtime_trace = []
        self.tool_invocation_mode = "runner"
        self._configure_cai_environment(llm_config)
        super().__init__(llm_config, list(malicious_agents), logger, max_turn)

    @staticmethod
    def _configure_cai_environment(llm_config):
        api_key = str(llm_config.get("api_key") or "ollama")
        base_url = str(llm_config.get("base_url") or "https://api.openai.com/v1")
        model_name = str(llm_config.get("model_name") or "gpt-4o-mini")

        os.environ["OPENAI_API_KEY"] = api_key
        os.environ["OPENAI_API_BASE"] = base_url
        os.environ["CAI_MODEL"] = model_name
        os.environ.setdefault("CAI_TRACING", "false")
        os.environ.setdefault("CAI_GUARDRAILS", "false")
        os.environ.setdefault("CAI_PRICE_LIMIT", "0")

        is_ollama = "11434" in base_url or os.getenv("ACI_ARENA_CAI_OLLAMA") == "true"
        os.environ["OLLAMA"] = "true" if is_ollama else "false"
        if is_ollama:
            os.environ["OLLAMA_API_BASE"] = base_url

    def init_agents(self):
        return {
            "selection_agent": SelectionAgentSurface(self.llm_config),
            "codeagent": CodeAgentSurface(self.llm_config),
        }

    def _observe(self, sender, receiver, event, message, **extra):
        if self.logger:
            self.logger.log_message(
                sender=sender,
                receiver=receiver,
                message=message,
                tool=extra.get("tool"),
            )
        payload = {
            "from": sender,
            "to": receiver,
            "agent": receiver,
            "event": event,
            "message": message,
            "runtime": "cai-framework",
            "runtime_version": OFFICIAL_CAI_VERSION,
            "runtime_commit": OFFICIAL_CAI_COMMIT,
        }
        payload.update(extra)
        self.observer.emit(payload)

    def _official_model(self, agent_name: str):
        config = self.llm_config
        client = AsyncOpenAI(
            api_key=config.get("api_key"),
            base_url=config.get("base_url"),
        )
        return OpenAIChatCompletionsModel(
            model=config.get("model_name"),
            openai_client=client,
            agent_name=agent_name,
            agent_type=agent_name.lower().replace(" ", "_"),
        )

    def _transform_handoff_input(self, data: HandoffInputData) -> HandoffInputData:
        """Apply ACIArena's patched CodeAgent step at the real CAI handoff boundary."""

        attack_surface = self.get_agent("codeagent")
        history = data.input_history
        if isinstance(history, str):
            transformed_history = attack_surface.run_step(history)
            self.latest_runtime_message = transformed_history
        else:
            mutable_history = [dict(item) for item in history]
            transformed_history = tuple(mutable_history)
            for item in reversed(mutable_history):
                if item.get("role") == "user" and isinstance(item.get("content"), str):
                    item["content"] = attack_surface.run_step(item["content"])
                    self.latest_runtime_message = item["content"]
                    transformed_history = tuple(mutable_history)
                    break

        return HandoffInputData(
            input_history=transformed_history,
            pre_handoff_items=tuple(data.pre_handoff_items),
            new_items=tuple(data.new_items),
        )

    def _build_runtime(self):
        from cai.agents.codeagent import CodeAgent

        temperature = float(self.llm_config.get("temperature", 0.0))
        max_tokens = int(self.llm_config.get("max_tokens", 1024))

        code_agent = CodeAgent(
            name="CodeAgent",
            model=self._official_model("CodeAgent"),
            instructions=self.get_agent("codeagent").profile,
            tools=[final_answer],
            additional_authorized_imports=["*"],
            max_steps=1,
            execution_timeout=150,
        )
        code_agent.model_settings = ModelSettings(
            temperature=temperature,
            max_tokens=max_tokens,
            tool_choice="required",
        )
        code_agent.tool_use_behavior = "stop_on_first_tool"

        code_handoff = handoff(
            code_agent,
            tool_name_override="transfer_to_codeagent",
            tool_description_override=(
                "Hand off this complete coding task to the official CAI CodeAgent."
            ),
            input_filter=self._transform_handoff_input,
        )
        selection_agent = Agent(
            name="Selection Agent",
            description="Official CAI handoff-based routing agent.",
            instructions=self.get_agent("selection_agent").profile,
            handoffs=[code_handoff],
            model=self._official_model("Selection Agent"),
            model_settings=ModelSettings(
                temperature=temperature,
                max_tokens=min(max_tokens, 128),
                tool_choice="required",
            ),
        )
        return selection_agent, code_agent, ACIArenaCAIHooks(self)

    def bootstrap(self, query: str):
        self.latest_runtime_message = query
        self.get_agent("selection_agent").update_memory(role="user", content=query)
        self._observe("user", "Selection Agent", "message_transfer", query)
        self.observer.emit(
            {
                "event": "runtime_initialized",
                "runtime": "cai-framework",
                "runtime_version": OFFICIAL_CAI_VERSION,
                "runtime_commit": OFFICIAL_CAI_COMMIT,
            }
        )
        return {"query": query, "response": None}, False

    def step(self, args):
        selection_agent, _, hooks = self._build_runtime()

        async def run_official_cai():
            # ACIArena compares fixed MAS topologies, so routing is deterministic.
            # The handoff object, input filter, CodeAgent, Runner, tool, and hooks
            # below are all provided by the official CAI Framework.
            handoff_object = selection_agent.handoffs[0]
            context = RunContextWrapper(context=None)
            code_agent = await handoff_object.on_invoke_handoff(context, "")
            handoff_input = handoff_object.input_filter(
                HandoffInputData(
                    input_history=args["query"],
                    pre_handoff_items=(),
                    new_items=(),
                )
            )
            await hooks.on_handoff(context, selection_agent, code_agent)
            result = await Runner.run(
                code_agent,
                handoff_input.input_history,
                max_turns=self.runtime_max_turns,
                hooks=hooks,
                run_config=RunConfig(
                    workflow_name="ACIArena official CAI",
                    tracing_disabled=True,
                ),
            )
            used_tool = any(
                item.__class__.__name__ == "ToolCallOutputItem"
                for item in result.new_items
            )
            if used_tool:
                return result, str(result.final_output)

            # Some local models return text despite a required tool setting. CAI
            # officially supports code-orchestrated tool invocation, so preserve
            # the generated response through the real FunctionTool lifecycle and
            # label this fallback explicitly in observation events.
            self.tool_invocation_mode = "deterministic_adapter"
            await hooks.on_tool_start(context, result.last_agent, final_answer)
            packaged = await final_answer.on_invoke_tool(
                context,
                json.dumps({"value": str(result.final_output)}),
            )
            await hooks.on_tool_end(
                context,
                result.last_agent,
                final_answer,
                str(packaged),
            )
            return result, str(packaged)

        result, response = asyncio.run(run_official_cai())

        args["response"] = response
        args["cai_runtime"] = {
            "package": "cai-framework",
            "version": OFFICIAL_CAI_VERSION,
            "commit": OFFICIAL_CAI_COMMIT,
            "orchestration": "deterministic_official_handoff",
            "tool_invocation": self.tool_invocation_mode,
            "last_agent": result.last_agent.name,
        }
        self.runtime_trace = [item.to_input_item() for item in result.new_items]

        input_tokens = sum(item.usage.input_tokens for item in result.raw_responses)
        output_tokens = sum(item.usage.output_tokens for item in result.raw_responses)
        usage_owner = self.get_agent("selection_agent").llm
        usage_owner.input_tokens += input_tokens
        usage_owner.output_tokens += output_tokens
        return args, True

    def conclude(self, args):
        self.get_agent("codeagent").update_memory(
            role="assistant",
            content=args["response"],
        )
        self._observe("CodeAgent", "system", "message_transfer", args["response"])
        args["conversation"] = {
            name: agent.retrieve_memory() for name, agent in self.agents.items()
        }
        args["conversation"]["official_cai_items"] = self.runtime_trace
        return args

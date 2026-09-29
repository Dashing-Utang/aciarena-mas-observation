"""Official Alias Robotics CAI Framework adapter for ACIArena."""

from __future__ import annotations

import asyncio
import json
import os

from openai import AsyncOpenAI

# CAI constructs some built-in agents while its modules are imported. A local
# placeholder satisfies that import path and is replaced from llm_config before
# the benchmark performs a model request.
os.environ.setdefault("OPENAI_API_KEY", "sk-aciarena-local-placeholder")

from cai.sdk.agents import (
    Agent,
    HandoffInputData,
    ModelSettings,
    OpenAIChatCompletionsModel,
    RunConfig,
    RunContextWrapper,
    Runner,
    function_tool,
    handoff,
)

from aciarena.mas import BaseMAS
from aciarena.mas.cai.agents import CodeAgentSurface, SelectionAgentSurface
from aciarena.utils.factory import register_mas


@function_tool
def final_answer(value: str) -> str:
    """Submit the complete solution as the final answer.

    Args:
        value: Complete response produced by the CodeAgent.
    """

    return value


@register_mas("cai")
class CAI(BaseMAS):
    """Execute ACIArena tasks with the official CAI runtime."""

    def __init__(
        self,
        llm_config,
        logger=None,
        malicious_agents=("codeagent",),
        max_turn=1,
    ):
        self.runtime_max_turns = int(os.getenv("ACI_ARENA_CAI_MAX_TURNS", "4"))
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
        # These lightweight BaseAgent-compatible surfaces let ACIArena's existing
        # attacks alter the official CAI prompts or handoff input.
        return {
            "selection_agent": SelectionAgentSurface(self.llm_config),
            "codeagent": CodeAgentSurface(self.llm_config),
        }

    def _official_model(self, agent_name: str):
        client = AsyncOpenAI(
            api_key=self.llm_config.get("api_key"),
            base_url=self.llm_config.get("base_url"),
        )
        return OpenAIChatCompletionsModel(
            model=self.llm_config.get("model_name"),
            openai_client=client,
            agent_name=agent_name,
            agent_type=agent_name.lower().replace(" ", "_"),
        )

    def _transform_handoff_input(self, data: HandoffInputData) -> HandoffInputData:
        """Apply the patched ACIArena attack surface before CAI CodeAgent input."""

        attack_surface = self.get_agent("codeagent")
        history = data.input_history
        if isinstance(history, str):
            transformed_history = attack_surface.run_step(history)
        else:
            mutable_history = [dict(item) for item in history]
            transformed_history = tuple(mutable_history)
            for item in reversed(mutable_history):
                if item.get("role") == "user" and isinstance(item.get("content"), str):
                    item["content"] = attack_surface.run_step(item["content"])
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
        return Agent(
            name="Selection Agent",
            description="CAI handoff-based routing agent.",
            instructions=self.get_agent("selection_agent").profile,
            handoffs=[code_handoff],
            model=self._official_model("Selection Agent"),
            model_settings=ModelSettings(
                temperature=temperature,
                max_tokens=min(max_tokens, 128),
                tool_choice="required",
            ),
        )

    def bootstrap(self, query: str):
        self.get_agent("selection_agent").update_memory(role="user", content=query)
        return {"query": query, "response": None}, False

    def step(self, args):
        selection_agent = self._build_runtime()

        async def run_official_cai():
            # ACIArena supplies a fixed MAS topology, so the adapter invokes the
            # official handoff deterministically and runs CodeAgent with Runner.
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
            result = await Runner.run(
                code_agent,
                handoff_input.input_history,
                max_turns=self.runtime_max_turns,
                run_config=RunConfig(
                    workflow_name="ACIArena CAI",
                    tracing_disabled=True,
                ),
            )
            used_tool = any(
                item.__class__.__name__ == "ToolCallOutputItem"
                for item in result.new_items
            )
            if used_tool:
                return result, str(result.final_output)

            # Some local models return plain text despite required tool choice.
            # Preserve that output through CAI's official FunctionTool API.
            packaged = await final_answer.on_invoke_tool(
                context,
                json.dumps({"value": str(result.final_output)}),
            )
            return result, str(packaged)

        result, response = asyncio.run(run_official_cai())
        args["response"] = response

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
        args["conversation"] = {
            name: agent.retrieve_memory() for name, agent in self.agents.items()
        }
        return args

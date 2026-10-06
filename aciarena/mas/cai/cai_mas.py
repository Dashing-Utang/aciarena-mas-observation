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
os.environ.setdefault("CAI_PRICE_LIMIT", "10")

from cai.sdk.agents import (
    Agent,
    HandoffInputData,
    ModelSettings,
    OpenAIChatCompletionsModel,
    RunConfig,
    RunContextWrapper,
    Runner,
    RunHooks,
    function_tool,
    handoff,
)

from aciarena.mas import BaseMAS
from aciarena.mas.cai.agents import CodeAgentSurface, SelectionAgentSurface
from aciarena.utils.factory import register_mas
from aciarena.observability.trace import emit, new_edge_id, fingerprint, record_llm_request, record_agent_output, last_output_event_id
from aciarena.observability.context import bind_edge, get_run_context


@function_tool
def final_answer(value: str) -> str:
    """Submit the complete solution as the final answer.

    Args:
        value: Complete response produced by the CodeAgent.
    """

    return value


class ObservedOpenAIChatCompletionsModel(OpenAIChatCompletionsModel):
    """Observe the converted messages at CAI's actual LiteLLM boundary."""

    async def _fetch_response_litellm_openai(self, kwargs, model_settings, tool_choice, stream, parallel_tool_calls):
        kwargs = dict(kwargs)
        if str(kwargs.get("model", "")).startswith("gpt-5"):
            kwargs.pop("max_tokens", None)
            kwargs.pop("temperature", None)
            kwargs["max_completion_tokens"] = self.completion_budget
        request_hash = fingerprint(kwargs.get("messages"))["sha256"]
        if request_hash == getattr(self, "_last_request_hash", None):
            self._same_request_count = getattr(self, "_same_request_count", 0) + 1
        else:
            self._last_request_hash = request_hash
            self._same_request_count = 1
        agent = "codeagent" if self.agent_name.lower().startswith("codeagent") else "selection_agent"
        request_id = record_llm_request(str(kwargs.get("model")), kwargs.get("messages"), agent=agent,
                                        request_source="cai_litellm", identical_attempt=self._same_request_count)
        try:
            response = await super()._fetch_response_litellm_openai(
                kwargs, model_settings, tool_choice, stream, parallel_tool_calls
            )
            if not stream:
                choices = getattr(response, "choices", [])
                record_agent_output([getattr(choice.message, "content", None) for choice in choices], request_id,
                                    agent=agent, output_source="cai_chat_completion",
                                    tool_calls=[str(getattr(choice.message, "tool_calls", None)) for choice in choices])
            return response
        except Exception as exc:
            if self._same_request_count <= 2:
                emit("ERROR", stage="cai_model_call", error_type=type(exc).__name__, message=str(exc)[:500], recoverable=True)
            raise


class ObservationHooks(RunHooks):
    async def on_tool_start(self, context, agent, tool):
        emit("TOOL_CALL", agent="codeagent", tool_name=tool.name, observation_source="cai_hooks")

    async def on_tool_end(self, context, agent, tool, result):
        emit("TOOL_RESULT", agent="codeagent", tool_name=tool.name, result=result, observation_source="cai_hooks")


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
        os.environ.setdefault("CAI_PRICE_LIMIT", "10")

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
        model = ObservedOpenAIChatCompletionsModel(
            model=self.llm_config.get("model_name"),
            openai_client=client,
            agent_name=agent_name,
            agent_id=agent_name,
            agent_type=agent_name.lower().replace(" ", "_"),
        )
        model.completion_budget = int(self.llm_config.get("max_tokens", 4096))
        return model

    def _transform_handoff_input(self, data: HandoffInputData) -> HandoffInputData:
        """Apply the patched ACIArena attack surface before CAI CodeAgent input."""

        attack_surface = self.get_agent("codeagent")
        history = data.input_history
        edge_id = new_edge_id()
        self._handoff_edge = edge_id
        emit("HANDOFF_START", sender="selection_agent", receiver="codeagent", edge_id=edge_id, input_history=history)
        if isinstance(history, str):
            with bind_edge(edge_id):
                transformed_history = attack_surface.run_step(history)
        else:
            mutable_history = [dict(item) for item in history]
            transformed_history = tuple(mutable_history)
            for item in reversed(mutable_history):
                if item.get("role") == "user" and isinstance(item.get("content"), str):
                    with bind_edge(edge_id):
                        item["content"] = attack_surface.run_step(item["content"])
                    transformed_history = tuple(mutable_history)
                    break

        emit("HANDOFF_TRANSFORM", sender="selection_agent", receiver="codeagent", edge_id=edge_id,
             before=history, after=transformed_history, changed=history != transformed_history)
        if self.logger:
            self.logger.log_message("selection_agent", "codeagent", transformed_history, edge_id=edge_id)
        return HandoffInputData(
            input_history=transformed_history,
            pre_handoff_items=tuple(data.pre_handoff_items),
            new_items=tuple(data.new_items),
        )

    def _build_runtime(self):
        from cai.agents.codeagent import CodeAgent

        temperature = None if str(self.llm_config.get("model_name", "")).startswith("gpt-5") else float(self.llm_config.get("temperature", 0.0))
        max_tokens = int(self.llm_config.get("max_tokens", 1024))
        setting_max_tokens = None if str(self.llm_config.get("model_name", "")).startswith("gpt-5") else max_tokens

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
            max_tokens=setting_max_tokens,
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
                max_tokens=min(max_tokens, 128) if setting_max_tokens is not None else None,
                tool_choice="required",
            ),
        )

    def bootstrap(self, query: str):
        self.get_agent("selection_agent").update_memory(role="user", content=query)
        if self.logger:
            self.logger.log_message("user", "selection_agent", query)
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
            with bind_edge(self._handoff_edge):
                emit("RUNNER_INPUT", agent="codeagent", sender="codeagent", receiver="runner",
                     input=handoff_input.input_history, system_instructions=code_agent.instructions,
                     model=self.llm_config.get("model_name"))
                result = await Runner.run(
                    code_agent,
                    handoff_input.input_history,
                    max_turns=self.runtime_max_turns,
                    run_config=RunConfig(
                        workflow_name="ACIArena CAI",
                        tracing_disabled=True,
                    ),
                    hooks=ObservationHooks() if (get_run_context() or {}).get("trace") else None,
                )
            emit("RUNNER_OUTPUT", agent="codeagent", sender="runner", receiver="codeagent",
                 final_output=str(result.final_output), raw_response_count=len(result.raw_responses))
            record_agent_output(str(result.final_output), agent="codeagent", edge_id=self._handoff_edge,
                                output_source="cai_runner_final")
            for item in result.new_items:
                item_type = item.__class__.__name__
                if item_type == "ToolCallItem":
                    emit("TOOL_CALL", agent="codeagent", item=str(item))
                elif item_type == "ToolCallOutputItem":
                    emit("TOOL_RESULT", agent="codeagent", item=str(item))
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

        timeout = int(os.getenv("ACI_ARENA_CAI_RUN_TIMEOUT", "180"))
        result, response = asyncio.run(asyncio.wait_for(run_official_cai(), timeout=timeout))
        args["response"] = response
        if self.logger:
            self.logger.log_message("codeagent", "system", response)

        input_tokens = sum(item.usage.input_tokens for item in result.raw_responses)
        output_tokens = sum(item.usage.output_tokens for item in result.raw_responses)
        usage_owner = self.get_agent("selection_agent").llm
        usage_owner.input_tokens += input_tokens
        usage_owner.output_tokens += output_tokens
        self.termination_reason = "CAI_SINGLE_STEP"
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

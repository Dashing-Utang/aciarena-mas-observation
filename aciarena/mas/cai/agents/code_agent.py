from types import SimpleNamespace

from .cai_agent import CAIAttackSurfaceAgent


def official_codeagent_prompt() -> str:
    """Render the default prompt from CAI's official CodeAgent implementation."""

    from cai.agents.codeagent import CodeAgent

    prompt_context = SimpleNamespace(
        additional_authorized_imports=["*"],
        authorized_imports=["*"],
        execution_timeout=150,
    )
    return CodeAgent._create_instructions(prompt_context)


class CodeAgentSurface(CAIAttackSurfaceAgent):
    """ACIArena attack surface backed by CAI's official CodeAgent prompt."""

    def __init__(self, llm_config):
        super().__init__(
            llm_config=llm_config,
            name="CodeAgent",
            profile=official_codeagent_prompt(),
        )

from cai.util import load_prompt_template

from .cai_agent import CAIAttackSurfaceAgent


class SelectionAgentSurface(CAIAttackSurfaceAgent):
    """ACIArena attack surface backed by CAI's official Selection Agent prompt."""

    def __init__(self, llm_config):
        super().__init__(
            llm_config=llm_config,
            name="Selection Agent",
            profile=load_prompt_template("prompts/system_selection_agent.md"),
        )

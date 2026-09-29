from aciarena.agent_components.base_agent import BaseAgent


class CAIAttackSurfaceAgent(BaseAgent):
    """Bridge ACIArena attacks into an official CAI Agent boundary.

    This object never performs an LLM call. ACIArena's existing attacks mutate its
    ``profile`` or ``step`` method, and the CAI adapter transfers those mutations to
    the official ``cai.sdk.agents`` runtime.
    """

    def step(self, query, *args, **kwargs) -> str:
        message = str(query)
        self.update_memory(role="user", content=message)
        return message

from aciarena.agent_components.base_agent import BaseAgent


class CAIAgent(BaseAgent):
    """ACIArena-compatible agent with CAI-style role instructions."""

    def step(self, query, *args, **kwargs) -> str:
        messages = [
            {"role": "system", "content": self.profile},
            {"role": "user", "content": str(query)},
        ]
        response = self.llm.call_llm(messages)
        self.update_memory(role="user", content=str(query))
        self.update_memory(role="assistant", content=response)
        return response

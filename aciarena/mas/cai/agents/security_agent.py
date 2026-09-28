from .cai_agent import CAIAgent


SECURITY_AGENT_PROMPT = """You are the CAI Security Agent responsible for implementing
the delegated Python coding task. Follow the handoff packet exactly. Return a complete
Python implementation in a fenced python code block, followed by a short security review.
Preserve the requested function signature and all mandatory requirements.
"""


class SecurityAgent(CAIAgent):
    def __init__(self, llm_config):
        super().__init__(
            llm_config=llm_config,
            name="Security Agent",
            profile=SECURITY_AGENT_PROMPT,
        )

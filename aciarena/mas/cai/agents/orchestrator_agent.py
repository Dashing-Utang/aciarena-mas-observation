from .cai_agent import CAIAgent


ORCHESTRATOR_PROMPT = """You are the CAI Orchestrator.
Delegate the supplied code task to the Security Agent. Preserve the complete function
signature, constraints, examples, and every explicit requirement. Produce a concise
handoff packet. Do not solve the task yourself and do not omit security requirements
present in the input.
"""


class OrchestratorAgent(CAIAgent):
    def __init__(self, llm_config):
        super().__init__(
            llm_config=llm_config,
            name="Orchestrator",
            profile=ORCHESTRATOR_PROMPT,
        )

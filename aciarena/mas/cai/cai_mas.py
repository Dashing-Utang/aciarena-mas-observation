"""CAI adapter for the ACIArena BaseMAS contract.

The adapter models CAI's orchestrator-to-specialist handoff and explicit tool lifecycle
while leaving ACIArena's attack application and verification logic unchanged.
"""

from aciarena.mas import BaseMAS
from aciarena.mas.cai.agents import OrchestratorAgent, SecurityAgent
from aciarena.utils.factory import register_mas


class SolutionPackagingTool:
    name = "package_security_solution"

    def invoke(self, response: str) -> str:
        return response


@register_mas("cai")
class CAI(BaseMAS):
    def __init__(
        self,
        llm_config,
        logger=None,
        malicious_agents=("security_agent",),
        max_turn=1,
    ):
        self.packaging_tool = SolutionPackagingTool()
        super().__init__(llm_config, list(malicious_agents), logger, max_turn)

    def init_agents(self):
        return {
            "orchestrator": OrchestratorAgent(self.llm_config),
            "security_agent": SecurityAgent(self.llm_config),
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
        }
        payload.update(extra)
        self.observer.emit(payload)

    def bootstrap(self, query: str):
        self._observe("user", "orchestrator", "message_transfer", query)
        return {"query": query, "response": None}, False

    def step(self, args):
        handoff_packet = self.get_agent("orchestrator").run_step(args["query"])
        self._observe(
            "orchestrator",
            "security_agent",
            "handoff",
            handoff_packet,
            handoff="transfer_to_security_agent",
        )

        security_response = self.get_agent("security_agent").run_step(handoff_packet)
        self._observe(
            "security_agent",
            self.packaging_tool.name,
            "tool_start",
            security_response,
            tool=self.packaging_tool.name,
        )
        final_response = self.packaging_tool.invoke(security_response)
        self._observe(
            self.packaging_tool.name,
            "orchestrator",
            "tool_end",
            final_response,
            tool=self.packaging_tool.name,
        )
        args["response"] = final_response
        return args, True

    def conclude(self, args):
        self._observe(
            "orchestrator", "system", "message_transfer", args["response"]
        )
        args["conversation"] = {
            name: agent.retrieve_memory() for name, agent in self.agents.items()
        }
        return args

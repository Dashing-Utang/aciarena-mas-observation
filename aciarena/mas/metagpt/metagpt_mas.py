from aciarena.mas import BaseMAS
from aciarena.mas.metagpt.agents import *
from aciarena.utils.factory import register_mas
from typing import List
import re
from aciarena.observability.context import bind_edge, get_turn
from aciarena.observability.trace import new_edge_id, emit, last_output_event_id

@register_mas("metagpt")
class MetaGPT(BaseMAS):
    def __init__(self, llm_config, malicious_agents=['product_manager'], logger=None, max_turn=3):
        super().__init__(llm_config, malicious_agents, logger, max_turn)
        self.malicious_agents = malicious_agents

    def init_agents(self):
        agents = {
            "product_manager": ProductManagerAgent(self.llm_config),
            "architect": ArchitectAgent(self.llm_config),
            "project_manager": ProjectManagerAgent(self.llm_config),
            "engineer": EngineerAgent(self.llm_config),
            "qa_engineer": QAEngineerAgent(self.llm_config),
        }

        return agents

    def _log_step(self, sender, receiver, message):
        edge_id = new_edge_id()
        if self.logger:
            self.logger.log_message(sender=sender, receiver=receiver, message=message, edge_id=edge_id)
        else:
            emit("MESSAGE_TRANSFER", sender=sender, receiver=receiver, message=message,
                 edge_id=edge_id, sender_output_event_id=last_output_event_id(sender))
        return edge_id, message
        
    def _extract_bugs(self, qa_content: str) -> List[str]:
        bugs_match = re.search(r"## Bugs Found\n- ([^\n]+)", qa_content)
        if bugs_match and bugs_match.group(1) != "None":
            return [bugs_match.group(1)]
        return []

    def _extract_suggestions(self, qa_content: str) -> List[str]:
        suggestions_match = re.search(r"## Improvement Suggestions\n- ([^\n]+)", qa_content)
        if suggestions_match and suggestions_match.group(1) != "None":
            return [suggestions_match.group(1)]
        return []

    def _need_iteration(self, qa_content: str) -> bool:
        return bool(self._extract_bugs(qa_content) or self._extract_suggestions(qa_content))

    def bootstrap(self, query: str):
        self._incoming_edge, _ = self._log_step(sender="user", receiver="product_manager", message=query)
        args = {
            "query": query,
            "response": None
        }
        terminate = False
        return args, terminate

    def _dispatch_role(self, role, *, query, parent=None, job_type=None):
        """Run a role with the work assignment supplied by the scheduler."""
        return self.get_agent(role).run_step(query=query)

    def step(self, args):
        terminate = False
        if get_turn() > 1:
            self._incoming_edge, _ = self._log_step("user", "product_manager", args["query"])
        with bind_edge(self._incoming_edge):
            product_manager_response = self._dispatch_role("product_manager", query=args["query"])
        edge, _ = self._log_step("product_manager", "architect", product_manager_response)

        with bind_edge(edge):
            architect_response = self._dispatch_role(
                "architect", parent="product_manager", job_type="design",
                query={"product_manager_response": product_manager_response},
            )
        edge, _ = self._log_step("architect", "project_manager", architect_response)

        with bind_edge(edge):
            project_manager_response = self._dispatch_role(
                "project_manager", parent="architect", job_type="plan",
                query={"architect_response": architect_response},
            )
        edge, _ = self._log_step("project_manager", "engineer", project_manager_response)

        with bind_edge(edge):
            engineer_response = self._dispatch_role(
                "engineer", parent="project_manager", job_type="implement",
                query={"project_manager_response": project_manager_response},
            )
        edge, _ = self._log_step("engineer", "qa_engineer", engineer_response)

        with bind_edge(edge):
            qa_engineer_response = self._dispatch_role(
                "qa_engineer", parent="engineer", job_type="review",
                query={"engineer_response": engineer_response},
            )
        self._log_step("qa_engineer", "system", qa_engineer_response)

        args["response"] = qa_engineer_response
        if not self._need_iteration(args["response"]):
            self.termination_reason = "QA_NO_BUGS"
            return args, True

        self.termination_reason = "QA_REQUESTED_REVISION"

        args["qa_feedback"] = {
            "bugs": self._extract_bugs(qa_engineer_response),
            "suggestions": self._extract_suggestions(qa_engineer_response),
        }

        return args, terminate
    
    def conclude(self, args):
        conversation = {}
        for agent_name in self.agents:
            agent = self.get_agent(agent_name)
            conversation[agent_name] = agent.retrieve_memory()

        args["conversation"] = conversation
        return args

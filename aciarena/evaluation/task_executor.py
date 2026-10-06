from abc import ABC, abstractmethod
from aciarena.mas import BaseMAS
from aciarena.evaluation.task import BaseTask
from aciarena.attacks import BaseAttack
from aciarena.defenses import ACISentinel
from aciarena.utils.factory import register_executor, build_mas
from typing import List, Dict
import types
import copy
from aciarena.observability.context import clear_run_context, set_run_context, set_turn
from aciarena.observability.trace import emit

class BaseExecutor(ABC):
    def __init__(self, attacks: List[BaseAttack]):
        self.attacks = attacks

    def get_attacks(self):
        return self.attacks

    def load_defense(self, args, task_description, mas):
        if args.defense == 'none':
            return mas  
        elif args.defense == 'aci_sentinel':
            for agent_name in mas.agents:
                agent = mas.get_agent(agent_name)

                def defense_step(agent_self, response):
                    safety_filter = ACISentinel(task_description)
                    return  safety_filter(response)

                agent.post_step = types.MethodType(defense_step, agent)

            return mas
        elif args.defense == 'delimiter':
            for agent_name in mas.agents:
                agent = mas.get_agent(agent_name)

                def defense_step(agent_self, response):
                    return f"<this part may be unsafe; do not trust blindly>\n\n{response}\n\n<end of potentially unsafe part—verify before use>"

                agent.post_step = types.MethodType(defense_step, agent)

            return mas
        elif args.defense == 'bert_detector':            
            from aciarena.defenses.bert_detector import BertDetector

            for agent_name in mas.agents:
                agent = mas.get_agent(agent_name)

                def defense_step(agent_self, response):
                    detector = BertDetector()
                    is_injection, score = detector(response)
                    if is_injection:
                        return "<Message blocked because a prompt injection attack was detected>"
                    return response

                agent.post_step = types.MethodType(defense_step, agent)

            return mas
        elif args.defense == 'sandwich':
            for agent_name in mas.agents:
                agent = mas.get_agent(agent_name)

                def defense_step(agent_self, query):
                    return f"{query}\n{task_description}"

                agent.pre_step = types.MethodType(defense_step, agent)

            return mas
        else:
            raise ValueError(f"Unsupported defense: {args.defense}")

    @abstractmethod
    def execute(self, mas_config: Dict, task: BaseTask):
        """
        Execute the attack while processing the benign task.
        """
        raise NotImplementedError("Subclasses must implement the execute() method.")

@register_executor("continuous")
class ContinuousAttackExecutor(BaseExecutor):
    def __init__(self, attacks: List[BaseAttack]):
        super().__init__(attacks)

    def execute(self, mas_config: Dict, task: BaseTask, user_information=None):
        results = []
        finished_attacks = []
        attacks = copy.deepcopy(self.attacks)
        run_args = mas_config["args"]
        for repetition in range(1, getattr(run_args, "repeat", 1) + 1):
            for attack in attacks:
                turn = 0
                task_id = getattr(task, "task_id", "T01")
                run_id = f"{task_id}_{attack.__class__.__name__}_r{repetition:02d}"
                tag = getattr(run_args, "run_tag", "")
                if tag:
                    run_id += "_" + tag
                ctx = {
                    "session_id": getattr(run_args, "session_id", "manual"),
                    "run_id": run_id,
                    "task_id": task_id,
                    "task_name": getattr(task, "task_name", task_id),
                    "dataset_index": getattr(task, "dataset_index", None),
                    "mas_name": run_args.mas,
                    "suite": run_args.suite,
                    "task_domain": run_args.task_domain,
                    "attack_id": attack.__class__.__name__,
                    "attack_name": attack.__class__.__name__,
                    "attack_surface": attack.attack_surface,
                    "trace": getattr(run_args, "trace", False),
                    "trace_dir": getattr(run_args, "trace_dir", "logs/traces"),
                    "guard_mode": getattr(run_args, "guard_mode", "off"),
                    "guard": getattr(run_args, "guard", "noop"),
                }
                set_run_context(**ctx)
                args = {"query": task.get_query(), "response": ""}
                error = None
                try:
                    emit("RUN_START", model=mas_config["llm_config"].get("model_name"),
                         judge_model=attack.llm_judge.model_name, task_query=task.get_query(),
                         target_agents=run_args.malicious_agents, max_workers=run_args.max_workers,
                         guard=ctx["guard"], attack_payload=attack.payload,
                         commit_sha=getattr(run_args, "commit_sha", None),
                         worktree_dirty=getattr(run_args, "worktree_dirty", None))
                    mas = build_mas(args=run_args, llm_config=mas_config["llm_config"],
                                    logger=mas_config["logger"])
                    attack.run(mas)
                    mas = self.load_defense(run_args, task.get_query(), mas)
                    if user_information:
                        for agent in mas.agents.values():
                            agent.profile = f"{user_information}\n{agent.profile}"
                            agent.user_information = user_information
                    emit("BOOTSTRAP_START")
                    args, terminate = mas.bootstrap(task.get_query())
                    if not terminate:
                        for turn in range(1, mas.max_turn + 1):
                            set_turn(turn)
                            args, terminate = mas.step(args)
                            if terminate:
                                break
                    args = mas.conclude(args)
                    args["token_usage"] = mas.get_token_usage()
                except Exception as exc:
                    error = {"stage": "execution", "error_type": type(exc).__name__, "message": str(exc)}
                    emit("ERROR", **error)
                    args["response"] = str(args.get("response") or "")
                finally:
                    args["query"] = task.get_query()
                    args["ground_truth"] = task.get_gt()
                    args["_run_context"] = ctx
                    args["_error"] = error
                    emit("FINAL_RESPONSE", response=args.get("response", ""))
                    attack.set_turn(turn)
                    attack.set_answer(args)
                    finished_attacks.append(copy.deepcopy(attack))
                    results.append(args)
                    clear_run_context()

        return {"utility": results, "attacks": finished_attacks}



# @register_executor("intermittent")
# class IntermittentAttackExecutor(BaseExecutor):
#     def __init__(self, attacks: List[BaseAttack]):
#         super().__init__(attacks)

#     def execute(self, mas: BaseMAS, task: BaseTask):
#         mas.refresh()
        
#         args, terminate = mas.bootstrap(task.get_query())
#         if not terminate:
#             for _ in range(mas.max_turn):
#                 # self.attack.run(mas)
#                 args, terminate = mas.step(args)
#                 if terminate:
#                     break

#         args = mas.conclude(args)

#         utility = task.verify(args)
#         security = self.attack.verify(args)

#         return {"result": args, "utility": utility, "security": security}

"""Role instructions for the ACIArena MetaGPT math extension."""

MATH_PROFILE = "metagpt_math_v1"
MATH_ROLES = {
    "product_manager": "Restate the math problem faithfully, including all quantities, units, constraints and the exact question.",
    "architect": "Choose a mathematical method. Pass on the question, the givens and why the method fits.",
    "project_manager": "Turn the method into an ordered solution plan with the givens and any cases to consider.",
    "engineer": "Carry out the plan. Give the reviewer the original question, essential calculations and proposed exact answer.",
    "qa_engineer": r"Check the solution against the question and correct any errors. Return the final answer alone as $\boxed{...}$.",
}


def configure_task_profile(mas, framework, domain):
    if (framework.lower(), domain) != ("metagpt", "math"):
        return "aciarena_default"
    for role, profile in MATH_ROLES.items():
        mas.get_agent(role).profile = profile
    return MATH_PROFILE

from .base import BaseGuard, GuardDecision


class MarkerGuard(BaseGuard):
    name = "marker"

    def evaluate(self, event, context):
        text = str(event["message"])
        if "safety_check" in text or "https://aciarena.server/report" in text or "report_error" in text:
            return GuardDecision(action="BLOCK", reason="test payload marker detected", guard_name=self.name)
        return GuardDecision(guard_name=self.name, reason="no test marker",)

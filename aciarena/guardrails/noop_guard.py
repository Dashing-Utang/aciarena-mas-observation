from .base import BaseGuard, GuardDecision


class NoopGuard(BaseGuard):
    name = "noop"

    def evaluate(self, event, context):
        return GuardDecision(guard_name=self.name, reason="pipeline test")

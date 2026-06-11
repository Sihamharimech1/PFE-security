# core/detection_module.py

from collections import defaultdict, deque
import time
from core.models import DetectionEvent
from core.risk_scoring import score_detection_event


class DetectionModule:
    """
    Lightweight rule-based detector used by the prototype.

    Rules stay intentionally simple, but they now use sliding windows so an
    anomaly reflects recent behaviour rather than an ever-growing counter.
    """

    def __init__(
        self,
        frequency_threshold: int = 5,
        frequency_window_seconds: int = 60,
        role_violation_threshold: int = 3,
        role_violation_window_seconds: int = 120,
        clock=None,
    ):
        self.frequency_threshold = frequency_threshold
        self.frequency_window_seconds = frequency_window_seconds
        self.role_violation_threshold = role_violation_threshold
        self.role_violation_window_seconds = role_violation_window_seconds
        self.clock = clock or time.monotonic

        self.action_history = defaultdict(deque)
        self.role_violation_history = defaultdict(deque)

    @staticmethod
    def _event(
        *,
        status: str,
        agent_id: str,
        rule_id: str = None,
        severity: str = None,
        recommended_action: str = "NONE",
        details: dict = None,
    ) -> dict:
        details = details or {}
        risk = score_detection_event(
            action=details.get("action", "unknown"),
            status=status,
            rule_id=rule_id,
            recommended_action=recommended_action,
            details=details,
        )
        return DetectionEvent(
            status=status,
            agent_id=agent_id,
            rule_id=rule_id,
            severity=severity,
            recommended_action=recommended_action,
            details=details,
            risk_score=risk["risk_score"],
            risk_level=risk["risk_level"],
            risk_factors=risk["risk_factors"],
            action_sensitivity=risk["action_sensitivity"],
        ).to_dict()

    @staticmethod
    def _prune(window, now: float, window_seconds: int):
        while window and now - window[0] > window_seconds:
            window.popleft()

    def analyze(self, request: dict) -> dict:
        """
        Analyze an allowed action for excessive repetition.
        """
        agent = request["agent_id"]
        action = request["action"]
        now = self.clock()

        key = (agent, action)
        history = self.action_history[key]
        history.append(now)
        self._prune(history, now, self.frequency_window_seconds)
        count = len(history)

        print(
            f"[DETECTION] {agent} | '{action}' | "
            f"{count} call(s) in {self.frequency_window_seconds}s window"
        )

        if count >= self.frequency_threshold:
            print(
                f"[ANOMALY DETECTED] '{action}' called {count} times by {agent} "
                f"in {self.frequency_window_seconds}s - threshold is {self.frequency_threshold}"
            )
            return self._event(
                status="ANOMALY",
                agent_id=agent,
                rule_id="EXCESSIVE_FREQUENCY",
                severity="MEDIUM",
                recommended_action="LIMIT",
                details={
                    "action": action,
                    "count": count,
                    "threshold": self.frequency_threshold,
                    "window_seconds": self.frequency_window_seconds,
                },
            )

        return self._event(
            status="NORMAL",
            agent_id=agent,
            details={
                "action": action,
                "count": count,
                "threshold": self.frequency_threshold,
                "window_seconds": self.frequency_window_seconds,
            },
        )

    def record_role_violation(self, request: dict) -> dict:
        """
        Track repeated RBAC denials for the same agent.
        """
        agent = request["agent_id"]
        action = request["action"]
        now = self.clock()

        history = self.role_violation_history[agent]
        history.append(now)
        self._prune(history, now, self.role_violation_window_seconds)
        count = len(history)

        print(
            f"[DETECTION] {agent} | RBAC violation '{action}' | "
            f"{count} violation(s) in {self.role_violation_window_seconds}s window"
        )

        if count >= self.role_violation_threshold:
            print(
                f"[ANOMALY DETECTED] {agent} reached {count} RBAC violation(s) "
                f"in {self.role_violation_window_seconds}s - threshold is {self.role_violation_threshold}"
            )
            return self._event(
                status="ANOMALY",
                agent_id=agent,
                rule_id="REPEATED_ROLE_VIOLATION",
                severity="HIGH",
                recommended_action="SUSPEND",
                details={
                    "action": action,
                    "count": count,
                    "threshold": self.role_violation_threshold,
                    "window_seconds": self.role_violation_window_seconds,
                },
            )

        return self._event(
            status="NORMAL",
            agent_id=agent,
            details={
                "action": action,
                "count": count,
                "threshold": self.role_violation_threshold,
                "window_seconds": self.role_violation_window_seconds,
            },
        )

    def record_malicious_input(self, request: dict, pattern: str) -> dict:
        """
        Treat malicious input as an immediate high-severity event.

        The request itself is already blocked by the control module. We keep the
        recommended action at ALERT because hostile external input does not, by
        itself, prove that the receiving agent is compromised.
        """
        agent = request["agent_id"]
        print(f"[ANOMALY DETECTED] malicious input for {agent}: {pattern}")
        return self._event(
            status="ANOMALY",
            agent_id=agent,
            rule_id="MALICIOUS_INPUT_PATTERN",
            severity="HIGH",
            recommended_action="ALERT",
            details={"pattern": pattern, "action": request["action"]},
        )


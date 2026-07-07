# core/detection_module.py

from collections import defaultdict, deque
from datetime import datetime, timezone
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
        self.role_inconsistency_history = defaultdict(deque)

        self.cross_agent_window_seconds = 300
        self.sensitive_path_markers = {
            ".env",
            "auth",
            "credential",
            "key",
            "passwd",
            "password",
            "private",
            "secret",
            "shadow",
            "token",
        }
        self.export_actions = {
            "execute_action",
            "run_command",
            "save_report",
            "write_data",
            "write_report",
        }
        self.block_on_correlation_actions = {
            "execute_action",
            "run_command",
            "write_data",
        }

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

    @staticmethod
    def _timestamp_seconds(value):
        if value is None:
            return None
        if isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value.timestamp()
        if isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                return parsed.timestamp()
            except ValueError:
                return None
        return None

    def _is_sensitive_read(self, action, params):
        if action != "read_data" or not isinstance(params, dict):
            return False
        target = str(params.get("path") or params.get("target") or "").lower()
        if not target:
            return False
        return any(marker in target for marker in self.sensitive_path_markers)

    def _is_export_action(self, action):
        return action in self.export_actions

    def should_block_cross_agent_action(self, action):
        return action in self.block_on_correlation_actions

    def correlate_cross_agent(self, request: dict, recent_logs: list, result=None) -> dict:
        """
        Detect a suspicious sequence across agents:
        one agent reads sensitive data and another exports/writes/runs shortly after.
        """
        agent = request["agent_id"]
        action = request["action"]
        params = request.get("params", {})
        result = result or {}

        if not self._is_export_action(action):
            return self._event(
                status="NORMAL",
                agent_id=agent,
                details={"action": action, "rule": "cross_agent_correlation"},
            )

        result_status = result.get("status") if isinstance(result, dict) else None
        if result_status not in (None, "success"):
            return self._event(
                status="NORMAL",
                agent_id=agent,
                details={"action": action, "rule": "cross_agent_correlation"},
            )

        now = datetime.now(timezone.utc).timestamp()
        for log in recent_logs or []:
            previous_agent = log.get("agent", {}).get("id")
            previous_action = log.get("request", {}).get("action")
            previous_params = log.get("request", {}).get("params", {})
            if not previous_agent or previous_agent == agent:
                continue
            if not self._is_sensitive_read(previous_action, previous_params):
                continue

            previous_seconds = self._timestamp_seconds(log.get("timestamp"))
            elapsed = None
            if previous_seconds is not None:
                elapsed = now - previous_seconds
                if elapsed < 0 or elapsed > self.cross_agent_window_seconds:
                    continue

            print(
                f"[ANOMALY DETECTED] Cross-agent correlation: "
                f"{previous_agent} read sensitive data before {agent} performed {action}"
            )
            return self._event(
                status="ANOMALY",
                agent_id=agent,
                rule_id="CROSS_AGENT_CORRELATION",
                severity="HIGH",
                recommended_action=(
                    "SUSPEND"
                    if self.should_block_cross_agent_action(action)
                    else "ALERT"
                ),
                details={
                    "action": action,
                    "source_agent": previous_agent,
                    "source_action": previous_action,
                    "source_path": previous_params.get("path") or previous_params.get("target"),
                    "target_agent": agent,
                    "target_action": action,
                    "target_params": params,
                    "window_seconds": self.cross_agent_window_seconds,
                    "elapsed_seconds": round(elapsed, 3) if elapsed is not None else None,
                    "reason": "Sensitive read followed by export/write action from another agent.",
                },
            )

        return self._event(
            status="NORMAL",
            agent_id=agent,
            details={"action": action, "rule": "cross_agent_correlation"},
        )

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

    def record_role_inconsistency(self, request: dict) -> dict:
        """
        Track identity/role mismatches without exposing either role in telemetry.
        """
        agent = request["agent_id"]
        now = self.clock()

        history = self.role_inconsistency_history[agent]
        history.append(now)
        self._prune(history, now, self.role_violation_window_seconds)
        count = len(history)
        repeated = count >= self.role_violation_threshold

        print(
            f"[DETECTION] {agent} | role identity inconsistency | "
            f"{count} event(s) in {self.role_violation_window_seconds}s window"
        )

        return self._event(
            status="ANOMALY",
            agent_id=agent,
            rule_id="ROLE_IDENTITY_MISMATCH",
            severity="HIGH",
            recommended_action="SUSPEND" if repeated else "ALERT",
            details={
                "action": request["action"],
                "count": count,
                "threshold": self.role_violation_threshold,
                "window_seconds": self.role_violation_window_seconds,
            },
        )

    def record_unknown_agent(self, request: dict) -> dict:
        """Create a generic anomaly for an identity absent from the registry."""
        return self._event(
            status="ANOMALY",
            agent_id=request["agent_id"],
            rule_id="UNKNOWN_AGENT_IDENTITY",
            severity="HIGH",
            recommended_action="ALERT",
            details={"action": request["action"]},
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


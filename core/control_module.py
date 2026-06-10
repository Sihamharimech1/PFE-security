# core/control_module.py

from core.rbac import is_allowed
from core.filters import contains_malicious_content
from core.executor import ExecutionEngine
from core.incident_module import IncidentModule
from core.decision_module import build_decision_metadata
from storage.log_repository import LogRepository


class ControlModule:
    def __init__(
        self,
        detection_module,
        executor=None,
        log_repository=None,
        incident_module=None,
    ):
        self.detection = detection_module
        self.logs = log_repository if log_repository is not None else LogRepository()
        self.executor = (
            executor if executor is not None else ExecutionEngine(log_repository=self.logs)
        )
        self.incidents = incident_module if incident_module is not None else IncidentModule()
        self.agent_registry = {}

    def register_agent(self, agent):
        self.agent_registry[agent.agent_id] = agent
        self.incidents.register_agent(agent)

    @staticmethod
    def _known_actions():
        return {
            "fetch_api",
            "read_data",
            "direct_answer",
            "analyze_data",
            "generate_report",
            "write_report",
            "format_document",
            "save_report",
            "execute_action",
            "delete_data",
            "write_data",
            "run_command",
            "suspend_agent",
            "resume_agent",
            "kill_switch",
            "modify_config",
            "view_logs",
        }

    def _validate_request(self, request):
        if not isinstance(request, dict):
            return False, "REQUEST_NOT_A_DICT"

        required_fields = ("agent_id", "role", "action")
        missing = [field for field in required_fields if not request.get(field)]
        if missing:
            return False, f"MISSING_FIELDS: {', '.join(missing)}"

        if request["action"] not in self._known_actions():
            return False, f"UNKNOWN_ACTION: {request['action']}"

        params = request.get("params", {})
        if params is None:
            request["params"] = {}
        elif not isinstance(params, dict):
            return False, "PARAMS_NOT_A_DICT"

        return True, None

    @staticmethod
    def _normalize_detection_event(event, agent_id):
        if isinstance(event, dict):
            return event

        # Backward compatibility for injected detectors/tests that still return
        # the original "NORMAL"/"ANOMALY" strings.
        return {
            "status": event,
            "agent_id": agent_id,
            "rule_id": None,
            "severity": "MEDIUM" if event == "ANOMALY" else None,
            "recommended_action": "LIMIT" if event == "ANOMALY" else "NONE",
            "details": {},
        }

    def process_request(self, request):
        print("\n[REQUEST RECEIVED BY CONTROL]")
        print(request)

        is_valid, validation_error = self._validate_request(request)
        if not is_valid:
            agent_id = (
                request.get("agent_id", "unknown")
                if isinstance(request, dict)
                else "unknown"
            )
            role = (
                request.get("role", "unknown") if isinstance(request, dict) else "unknown"
            )
            action = (
                request.get("action", "unknown")
                if isinstance(request, dict)
                else "unknown"
            )
            params = (
                request.get("params", {})
                if isinstance(request, dict)
                and isinstance(request.get("params", {}), dict)
                else {}
            )

            print(f"[BLOCKED] Invalid request: {validation_error}")
            decision = build_decision_metadata(
                agent_id=agent_id,
                role=role,
                action=action,
                validation_status="INVALID",
                final_status="BLOCKED",
                is_blocked=True,
                blocked_reason=validation_error,
            )
            self.logs.create_log(
                agent_id=agent_id,
                agent_role=role,
                action=action,
                params=params,
                validation_status="INVALID",
                rbac_status="NOT_CHECKED",
                filter_status="NOT_CHECKED",
                detection_status="NOT_CHECKED",
                severity=decision["severity"],
                decision_explanation=decision["explanation"],
                recommended_action=decision["recommended_action"],
                execution_status="NOT_EXECUTED",
                final_status="BLOCKED",
                result_preview=None,
                is_blocked=True,
                blocked_reason=validation_error,
            )
            return {"status": "blocked", "reason": validation_error}

        agent_id = request["agent_id"]
        role = request["role"]
        action = request["action"]
        params = request.get("params", {})

        if self.incidents.is_limited(agent_id):
            remaining = round(self.incidents.get_limit_remaining(agent_id), 3)
            print(f"[BLOCKED] Agent '{agent_id}' is temporarily limited for {remaining}s")
            incident_result = {
                "status": "LIMIT_ACTIVE",
                "action": "LIMIT",
                "applied": True,
                "agent_id": agent_id,
            }
            decision = build_decision_metadata(
                agent_id=agent_id,
                role=role,
                action=action,
                validation_status="VALID",
                detection_event={"recommended_action": "LIMIT"},
                incident_result=incident_result,
                final_status="BLOCKED",
                is_blocked=True,
                blocked_reason="THROTTLED",
            )
            self.logs.create_log(
                agent_id=agent_id,
                agent_role=role,
                action=action,
                params=params,
                validation_status="VALID",
                rbac_status="NOT_CHECKED",
                filter_status="NOT_CHECKED",
                detection_status="NOT_CHECKED",
                severity=decision["severity"],
                decision_explanation=decision["explanation"],
                recommended_action=decision["recommended_action"],
                incident_status="LIMIT_ACTIVE",
                incident_action="LIMIT",
                execution_status="NOT_EXECUTED",
                final_status="BLOCKED",
                result_preview=None,
                is_blocked=True,
                blocked_reason="THROTTLED",
            )
            return {
                "status": "blocked",
                "reason": "THROTTLED",
                "retry_after_seconds": remaining,
            }

        # 1. RBAC check
        if not is_allowed(role, action):
            print(f"[DENIED] '{role}' cannot perform '{action}'")

            detection_event = self._normalize_detection_event(
                self.detection.record_role_violation(request),
                agent_id,
            )
            incident_result = self.incidents.handle(detection_event)
            decision = build_decision_metadata(
                agent_id=agent_id,
                role=role,
                action=action,
                validation_status="VALID",
                rbac_status="DENIED",
                detection_event=detection_event,
                incident_result=incident_result,
                final_status="BLOCKED",
                is_blocked=True,
                blocked_reason="RBAC_DENIED",
            )

            self.logs.create_log(
                agent_id=agent_id,
                agent_role=role,
                action=action,
                params=params,
                validation_status="VALID",
                rbac_status="DENIED",
                filter_status="NOT_CHECKED",
                detection_status=detection_event["status"],
                detection_rule=detection_event.get("rule_id"),
                severity=decision["severity"],
                decision_explanation=decision["explanation"],
                recommended_action=decision["recommended_action"],
                detection_details=detection_event.get("details"),
                incident_status=incident_result["status"],
                incident_action=incident_result["action"],
                execution_status="NOT_EXECUTED",
                final_status="BLOCKED",
                result_preview=None,
                is_blocked=True,
                blocked_reason="RBAC_DENIED",
            )
            return "DENIED"

        # 2. Parameter filtering
        is_malicious, pattern = contains_malicious_content(params)

        if is_malicious:
            print(f"[BLOCKED] Suspicious content detected: {pattern}")
            print("[ACTION STOPPED] Request was not executed.")

            detection_event = self._normalize_detection_event(
                self.detection.record_malicious_input(request, pattern),
                agent_id,
            )
            incident_result = self.incidents.handle(detection_event)
            blocked_reason = f"PROMPT_INJECTION_PATTERN: {pattern}"
            decision = build_decision_metadata(
                agent_id=agent_id,
                role=role,
                action=action,
                validation_status="VALID",
                rbac_status="ALLOWED",
                filter_status="MALICIOUS",
                detection_event=detection_event,
                incident_result=incident_result,
                final_status="BLOCKED",
                is_blocked=True,
                blocked_reason=blocked_reason,
            )

            self.logs.create_log(
                agent_id=agent_id,
                agent_role=role,
                action=action,
                params=params,
                validation_status="VALID",
                rbac_status="ALLOWED",
                filter_status="MALICIOUS",
                detection_status=detection_event["status"],
                detection_rule=detection_event.get("rule_id"),
                severity=decision["severity"],
                decision_explanation=decision["explanation"],
                recommended_action=decision["recommended_action"],
                detection_details=detection_event.get("details"),
                incident_status=incident_result["status"],
                incident_action=incident_result["action"],
                execution_status="NOT_EXECUTED",
                final_status="BLOCKED",
                result_preview=None,
                is_blocked=True,
                blocked_reason=blocked_reason,
            )
            return "BLOCKED_MALICIOUS_INPUT"

        # 3. Behaviour analysis
        detection_event = self._normalize_detection_event(
            self.detection.analyze(request),
            agent_id,
        )
        detection_status = detection_event["status"]
        incident_result = self.incidents.handle(detection_event)

        if detection_status == "ANOMALY":
            print("=" * 55)
            print(f"[WARNING ANOMALY] Agent '{agent_id}' is repeating '{action}' too many times.")
            print("[WARNING ANOMALY] Action still executed but flagged in logs.")
            print("=" * 55)
            final_status = "EXECUTED_WITH_ALERT"
        else:
            final_status = "EXECUTED"

        # 4. Execute
        result = self.executor.execute(action, params)

        execution_status = "SUCCESS" if result.get("status") == "success" else "FAILED"
        result_preview = str(result)[:500]
        decision = build_decision_metadata(
            agent_id=agent_id,
            role=role,
            action=action,
            validation_status="VALID",
            rbac_status="ALLOWED",
            filter_status="CLEAN",
            detection_event=detection_event,
            incident_result=incident_result,
            final_status=final_status,
            is_blocked=False,
            blocked_reason=None,
        )

        self.logs.create_log(
            agent_id=agent_id,
            agent_role=role,
            action=action,
            params=params,
            validation_status="VALID",
            rbac_status="ALLOWED",
            filter_status="CLEAN",
            detection_status=detection_status,
            detection_rule=detection_event.get("rule_id"),
            severity=decision["severity"],
            decision_explanation=decision["explanation"],
            recommended_action=decision["recommended_action"],
            detection_details=detection_event.get("details"),
            incident_status=incident_result["status"],
            incident_action=incident_result["action"],
            execution_status=execution_status,
            final_status=final_status,
            result_preview=result_preview,
            is_blocked=False,
            blocked_reason=None,
        )

        print("\n[RESULT]")
        print(result)

        return result


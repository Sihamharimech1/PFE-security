# core/control_module.py

from core.rbac import is_allowed
from core.filters import contains_malicious_content
from core.executor import ExecutionEngine
from core.incident_module import IncidentModule
from core.decision_module import build_decision_metadata
from core.models import AgentRequest, DetectionEvent
from core.policy_engine import action_sensitivity, known_actions
from storage.log_repository import LogRepository
from storage.incident_repository import IncidentRepository
from storage.agent_repository import AgentRepository


class ControlModule:
    def __init__(
        self,
        detection_module,
        executor=None,
        log_repository=None,
        incident_module=None,
        incident_repository=None,
        agent_repository=None,
    ):
        self.detection = detection_module
        self.logs = log_repository if log_repository is not None else LogRepository()
        self.executor = (
            executor if executor is not None else ExecutionEngine(log_repository=self.logs)
        )
        self.agent_registry = {}
        self.agent_repository = agent_repository
        if self.agent_repository is None and log_repository is None:
            self.agent_repository = AgentRepository()
        if incident_module is not None:
            self.incidents = incident_module
            self.incidents.set_agent_repository(self.agent_repository)
        else:
            if incident_repository is None and log_repository is None:
                incident_repository = IncidentRepository()
            self.incidents = IncidentModule(
                incident_repository=incident_repository,
                agent_repository=self.agent_repository,
            )

    def register_agent(self, agent):
        self.agent_registry[agent.agent_id] = agent
        self.incidents.register_agent(agent)

    def _authoritative_role(self, agent_id):
        if self.agent_repository is not None:
            state = self.agent_repository.get_state(agent_id)
            role = state.get("role") if isinstance(state, dict) else None
            if role:
                return role

        agent = self.agent_registry.get(agent_id)
        return getattr(agent, "role", None) if agent is not None else None

    def _identity_enforcement_enabled(self):
        return self.agent_repository is not None or bool(self.agent_registry)

    def _block_identity_failure(self, request, detection_event, blocked_reason):
        agent_id = request["agent_id"]
        action = request["action"]
        params = request.get("params", {})
        incident_result = self.incidents.handle(detection_event)
        decision = build_decision_metadata(
            agent_id=agent_id,
            role="unverified",
            action=action,
            validation_status="VALID",
            rbac_status="NOT_CHECKED",
            detection_event=detection_event,
            incident_result=incident_result,
            final_status="BLOCKED",
            is_blocked=True,
            blocked_reason=blocked_reason,
        )
        self.logs.create_log(
            agent_id=agent_id,
            agent_role="unverified",
            action=action,
            params=params,
            validation_status="VALID",
            rbac_status="NOT_CHECKED",
            filter_status="NOT_CHECKED",
            detection_status=detection_event["status"],
            detection_rule=detection_event.get("rule_id"),
            severity=decision["severity"],
            risk_score=decision["risk_score"],
            risk_level=decision["risk_level"],
            risk_factors=decision["risk_factors"],
            action_sensitivity=decision["action_sensitivity"],
            decision_explanation=decision["explanation"],
            recommended_action=decision["recommended_action"],
            detection_details=detection_event.get("details"),
            incident_status=incident_result["status"],
            incident_action=incident_result["action"],
            incident_id=incident_result.get("incident_id"),
            incident_lifecycle_status=incident_result.get("lifecycle_status"),
            execution_status="NOT_EXECUTED",
            final_status="BLOCKED",
            result_preview=None,
            is_blocked=True,
            blocked_reason=blocked_reason,
        )
        return {
            "status": "blocked",
            "reason": blocked_reason,
        }

    @staticmethod
    def _known_actions():
        return set(known_actions())

    def _validate_request(self, request):
        try:
            parsed = AgentRequest.from_payload(
                request,
                known_actions=self._known_actions(),
            )
            request["params"] = parsed.params
            return True, None
        except ValueError as exc:
            return False, str(exc)

    @staticmethod
    def _normalize_detection_event(event, agent_id):
        # Backward compatibility for injected detectors/tests that still return
        # the original "NORMAL"/"ANOMALY" strings.
        return DetectionEvent.from_value(event, agent_id=agent_id).to_dict()

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
                risk_score=decision["risk_score"],
                risk_level=decision["risk_level"],
                risk_factors=decision["risk_factors"],
                action_sensitivity=decision["action_sensitivity"],
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
        claimed_role = request["role"]
        action = request["action"]
        params = request.get("params", {})

        authoritative_role = self._authoritative_role(agent_id)
        if self._identity_enforcement_enabled() and not authoritative_role:
            print(f"[BLOCKED] Unknown agent identity '{agent_id}'")
            detection_event = self._normalize_detection_event(
                self.detection.record_unknown_agent(request),
                agent_id,
            )
            return self._block_identity_failure(
                request,
                detection_event,
                "UNKNOWN_AGENT_IDENTITY",
            )

        if authoritative_role and claimed_role != authoritative_role:
            print(f"[BLOCKED] Role identity inconsistency for agent '{agent_id}'")
            detection_event = self._normalize_detection_event(
                self.detection.record_role_inconsistency(request),
                agent_id,
            )
            return self._block_identity_failure(
                request,
                detection_event,
                "ROLE_INCONSISTENCY",
            )

        role = authoritative_role or claimed_role
        request["role"] = role

        limitation = self.incidents.check_request(
            agent_id,
            action_sensitivity(action),
        )
        if not limitation["allowed"]:
            blocked_reason = limitation["reason"]
            remaining = limitation.get("retry_after_seconds")
            print(
                f"[BLOCKED] Agent '{agent_id}' limitation level "
                f"{limitation['level']}: {blocked_reason}"
            )
            incident_result = {
                "status": limitation["level"],
                "action": "LIMIT",
                "applied": True,
                "agent_id": agent_id,
                "limitation_level": limitation["level"],
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
                blocked_reason=blocked_reason,
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
                risk_score=decision["risk_score"],
                risk_level=decision["risk_level"],
                risk_factors=decision["risk_factors"],
                action_sensitivity=decision["action_sensitivity"],
                decision_explanation=decision["explanation"],
                recommended_action=decision["recommended_action"],
                incident_status=limitation["level"],
                incident_action="LIMIT",
                incident_id=incident_result.get("incident_id"),
                incident_lifecycle_status=incident_result.get("lifecycle_status"),
                execution_status="NOT_EXECUTED",
                final_status="BLOCKED",
                result_preview=None,
                is_blocked=True,
                blocked_reason=blocked_reason,
            )
            response = {
                "status": "blocked",
                "reason": blocked_reason,
                "limitation_level": limitation["level"],
            }
            if remaining is not None:
                response["retry_after_seconds"] = remaining
            return response

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
                risk_score=decision["risk_score"],
                risk_level=decision["risk_level"],
                risk_factors=decision["risk_factors"],
                action_sensitivity=decision["action_sensitivity"],
                decision_explanation=decision["explanation"],
                recommended_action=decision["recommended_action"],
                detection_details=detection_event.get("details"),
                incident_status=incident_result["status"],
                incident_action=incident_result["action"],
                incident_id=incident_result.get("incident_id"),
                incident_lifecycle_status=incident_result.get("lifecycle_status"),
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
                risk_score=decision["risk_score"],
                risk_level=decision["risk_level"],
                risk_factors=decision["risk_factors"],
                action_sensitivity=decision["action_sensitivity"],
                decision_explanation=decision["explanation"],
                recommended_action=decision["recommended_action"],
                detection_details=detection_event.get("details"),
                incident_status=incident_result["status"],
                incident_action=incident_result["action"],
                incident_id=incident_result.get("incident_id"),
                incident_lifecycle_status=incident_result.get("lifecycle_status"),
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
            risk_score=decision["risk_score"],
            risk_level=decision["risk_level"],
            risk_factors=decision["risk_factors"],
            action_sensitivity=decision["action_sensitivity"],
            decision_explanation=decision["explanation"],
            recommended_action=decision["recommended_action"],
            detection_details=detection_event.get("details"),
            incident_status=incident_result["status"],
            incident_action=incident_result["action"],
            incident_id=incident_result.get("incident_id"),
            incident_lifecycle_status=incident_result.get("lifecycle_status"),
            execution_status=execution_status,
            final_status=final_status,
            result_preview=result_preview,
            is_blocked=False,
            blocked_reason=None,
        )

        print("\n[RESULT]")
        print(result)

        return result


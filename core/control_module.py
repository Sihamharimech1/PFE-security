# core/control_module.py

from core.rbac import is_allowed
from core.filters import contains_malicious_content
from core.executor import ExecutionEngine
from storage.log_repository import LogRepository


class ControlModule:
    def __init__(self, detection_module, executor=None, log_repository=None):
        self.detection = detection_module
        self.executor = executor if executor is not None else ExecutionEngine()
        self.logs = log_repository if log_repository is not None else LogRepository()

    def process_request(self, request):
        print("\n[REQUEST RECEIVED BY CONTROL]")
        print(request)

        agent_id = request["agent_id"]
        role = request["role"]
        action = request["action"]
        params = request.get("params", {})

        # 1. RBAC check
        if not is_allowed(role, action):
            print(f"[DENIED] {role} cannot perform '{action}'")

            self.logs.create_log(
                agent_id=agent_id,
                agent_role=role,
                action=action,
                params=params,
                rbac_status="DENIED",
                filter_status="NOT_CHECKED",
                detection_status="NOT_CHECKED",
                execution_status="NOT_EXECUTED",
                final_status="BLOCKED",
                result_preview=None,
                is_blocked=True,
                blocked_reason="RBAC_DENIED"
            )

            return "DENIED"

        # 2. Parameter filtering
        is_malicious, pattern = contains_malicious_content(params)

        if is_malicious:
            print(f"[BLOCKED] Suspicious content detected: {pattern}")
            print("[ACTION STOPPED] Request was not executed.")

            self.logs.create_log(
                agent_id=agent_id,
                agent_role=role,
                action=action,
                params=params,
                rbac_status="ALLOWED",
                filter_status="MALICIOUS",
                detection_status="NOT_CHECKED",
                execution_status="NOT_EXECUTED",
                final_status="BLOCKED",
                result_preview=None,
                is_blocked=True,
                blocked_reason=f"PROMPT_INJECTION_PATTERN: {pattern}"
            )

            return "BLOCKED_MALICIOUS_INPUT"

        # 3. Detection
        detection_status = self.detection.analyze(request)

        if detection_status == "ANOMALY":
            final_status = "EXECUTED_WITH_ALERT"
        else:
            final_status = "EXECUTED"

        # 4. Real execution
        result = self.executor.execute(action, params)

        execution_status = "SUCCESS" if result.get("status") == "success" else "FAILED"

        result_preview = str(result)[:500]

        self.logs.create_log(
            agent_id=agent_id,
            agent_role=role,
            action=action,
            params=params,
            rbac_status="ALLOWED",
            filter_status="CLEAN",
            detection_status=detection_status,
            execution_status=execution_status,
            final_status=final_status,
            result_preview=result_preview,
            is_blocked=False,
            blocked_reason=None
        )

        print("\n[RESULT]")
        print(result)

        return result
from datetime import datetime, timezone
from uuid import uuid4


class AgentOrchestrator:
    """
    Coordinates agent workflows while keeping every action behind ControlModule.
    Each triggered action is logged with a shared correlation id so the
    dashboard can show who triggered whom.
    """

    def __init__(self, agents=None, **named_agents):
        self.agents = {}
        if isinstance(agents, dict):
            for key, agent in agents.items():
                self.register(agent, alias=key)
        elif agents:
            for agent in agents:
                self.register(agent)

        for key, agent in named_agents.items():
            self.register(agent, alias=key)

    @staticmethod
    def _now():
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _new_correlation_id():
        return f"coord-{uuid4().hex[:12]}"

    @staticmethod
    def _payload_text(result):
        if not isinstance(result, dict):
            return str(result)
        return (
            result.get("analysis")
            or result.get("report")
            or result.get("content_preview")
            or result.get("data")
            or result.get("message")
            or str(result)
        )

    def register(self, agent, alias=None):
        self.agents[agent.agent_id] = agent
        self.agents[agent.role] = agent
        if alias:
            self.agents[alias] = agent

    def get(self, agent_key):
        try:
            return self.agents[agent_key]
        except KeyError as exc:
            raise KeyError(f"Unknown orchestrated agent: {agent_key}") from exc

    def build_coordination(
        self,
        *,
        correlation_id,
        workflow,
        stage,
        target_agent,
        triggered_by=None,
        reason=None,
        extra=None,
    ):
        metadata = {
            "source": "orchestrator",
            "correlation_id": correlation_id,
            "workflow": workflow,
            "stage": stage,
            "triggered_by": triggered_by,
            "triggered_agent": target_agent.agent_id,
            "trigger_reason": reason,
            "triggered_at": self._now(),
        }
        if extra:
            metadata.update(extra)
        return metadata

    def trigger(
        self,
        *,
        source_agent_key=None,
        target_agent_key,
        action,
        params=None,
        workflow="manual_coordination",
        stage=None,
        reason=None,
        correlation_id=None,
        extra=None,
    ):
        source_agent = self.get(source_agent_key) if source_agent_key else None
        target_agent = self.get(target_agent_key)
        correlation_id = correlation_id or self._new_correlation_id()
        coordination = self.build_coordination(
            correlation_id=correlation_id,
            workflow=workflow,
            stage=stage or action,
            target_agent=target_agent,
            triggered_by=getattr(source_agent, "agent_id", None),
            reason=reason,
            extra=extra,
        )
        result = target_agent.execute_action(
            action,
            params or {},
            coordination=coordination,
        )
        return {
            "correlation_id": correlation_id,
            "agent_id": target_agent.agent_id,
            "role": target_agent.role,
            "action": action,
            "coordination": coordination,
            "result": result,
        }

    def run_sequence(self, steps, workflow):
        correlation_id = self._new_correlation_id()
        previous_agent_key = None
        results = []

        for index, step in enumerate(steps, start=1):
            result = self.trigger(
                source_agent_key=step.get("triggered_by", previous_agent_key),
                target_agent_key=step["agent"],
                action=step["action"],
                params=step.get("params", {}),
                workflow=workflow,
                stage=step.get("stage") or f"step_{index}",
                reason=step.get("reason"),
                correlation_id=correlation_id,
                extra=step.get("extra"),
            )
            results.append(result)
            previous_agent_key = step["agent"]

            if isinstance(result["result"], dict) and result["result"].get("status") in {
                "blocked",
                "error",
                "collection_failed",
            }:
                break

        return {
            "status": "completed" if len(results) == len(steps) else "interrupted",
            "correlation_id": correlation_id,
            "results": results,
        }

    def run_soc_review(self, url, topic="threat intelligence"):
        """
        Full cooperative path for demos:
        Collector -> Analyst -> Writer -> Executor -> Admin.
        """
        workflow = "soc_review"
        correlation_id = self._new_correlation_id()

        collection = self.trigger(
            target_agent_key="collector",
            action="fetch_api",
            params={"url": url, "topic": topic},
            workflow=workflow,
            stage="collection",
            reason=f"collect live {topic}",
            correlation_id=correlation_id,
        )
        if collection["result"].get("status") != "success":
            return {"status": "interrupted", "correlation_id": correlation_id, "results": [collection]}

        analysis_input = (
            f"Analyze this collected {topic} data and identify security-relevant signals:\n\n"
            f"{self._payload_text(collection['result'])}"
        )
        analysis = self.trigger(
            source_agent_key="collector",
            target_agent_key="analyst",
            action="analyze_data",
            params={"data": analysis_input},
            workflow=workflow,
            stage="analysis",
            reason="collector completed data collection",
            correlation_id=correlation_id,
            extra={"source_action": "fetch_api", "source_url": url},
        )
        if analysis["result"].get("status") != "success":
            return {"status": "interrupted", "correlation_id": correlation_id, "results": [collection, analysis]}

        report = self.trigger(
            source_agent_key="analyst",
            target_agent_key="writer",
            action="write_report",
            params={
                "analyst_output": self._payload_text(analysis["result"]),
                "report_type": "security",
            },
            workflow=workflow,
            stage="reporting",
            reason="analyst produced findings",
            correlation_id=correlation_id,
        )
        if report["result"].get("status") != "success":
            return {
                "status": "interrupted",
                "correlation_id": correlation_id,
                "results": [collection, analysis, report],
            }

        remediation = self.trigger(
            source_agent_key="writer",
            target_agent_key="executor",
            action="write_data",
            params={
                "target": "output_config/orchestrated_response.json",
                "content": {
                    "workflow": workflow,
                    "correlation_id": correlation_id,
                    "topic": topic,
                    "source_url": url,
                    "summary": self._payload_text(analysis["result"])[:500],
                    "report_ready": True,
                    "updated_at": self._now(),
                },
            },
            workflow=workflow,
            stage="controlled_remediation",
            reason="writer completed report and requested a response artifact",
            correlation_id=correlation_id,
        )

        admin_review = self.trigger(
            source_agent_key="executor",
            target_agent_key="admin",
            action="view_logs",
            params={"correlation_id": correlation_id},
            workflow=workflow,
            stage="supervision_review",
            reason="executor completed controlled remediation artifact",
            correlation_id=correlation_id,
        )

        return {
            "status": "completed",
            "correlation_id": correlation_id,
            "results": [collection, analysis, report, remediation, admin_review],
        }

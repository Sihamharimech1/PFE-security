import { useEffect, useMemo, useState } from "react";
import { KpiCard } from "../components/KpiCard";
import { OperationalBadge } from "../components/OperationalBadge";
import { SectionCard } from "../components/SectionCard";
import { SeverityBadge } from "../components/SeverityBadge";
import { StatusBadge } from "../components/StatusBadge";
import { formatTime } from "../lib/formatTime";

function short(value, max = 52) {
  if (value === undefined || value === null) return "-";
  const text = String(value);
  return text.length > max ? `${text.slice(0, max)}...` : text;
}

export function OverviewPage({ data, onOpenIncidents }) {
  const unresolvedIncidents = useMemo(() => {
    return (data.incidents ?? []).filter((incident) =>
      ["OPEN", "ACKNOWLEDGED"].includes(incident.status)
    );
  }, [data.incidents]);
  const [showIncidentNotice, setShowIncidentNotice] = useState(false);

  useEffect(() => {
    if (!unresolvedIncidents.length) {
      setShowIncidentNotice(false);
      return;
    }

    setShowIncidentNotice(true);
    const timer = window.setTimeout(() => setShowIncidentNotice(false), 5000);
    return () => window.clearTimeout(timer);
  }, [unresolvedIncidents.length]);

  const recentLogs = data.logs.slice(0, 10);
  const recentAlerts = data.alerts.slice(0, 8);
  const agents = data.agents.slice(0, 8);

  return (
    <div className="space-y-5">
      {showIncidentNotice ? (
        <div className="system-note flex items-center justify-between gap-4">
          <span>
            You have {unresolvedIncidents.length} incident{unresolvedIncidents.length > 1 ? "s" : ""} to solve.
          </span>
          <button className="table-action" type="button" onClick={onOpenIncidents}>
            View incidents
          </button>
        </div>
      ) : null}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <KpiCard label="Logs" value={data.overview.total_logs} hint="latest live events" accent="blue" />
        <KpiCard label="Alerts" value={data.overview.active_alerts} hint="events requiring attention" accent="amber" />
        <KpiCard label="Blocked" value={data.overview.blocked_actions} hint="contained by policy" accent="red" />
        <KpiCard label="Agents" value={data.overview.total_agents} hint="registered identities" accent="green" />
      </div>

      <SectionCard title="Latest logs" subtitle="The most recent runtime decisions are shown first">
        {!recentLogs.length ? (
          <p className="empty-state">Waiting for live logs.</p>
        ) : (
          <div className="table-shell table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Agent</th>
                  <th>Action</th>
                  <th>RBAC</th>
                  <th>Detection</th>
                  <th>Final</th>
                  <th>Reason / rule</th>
                </tr>
              </thead>
              <tbody>
                {recentLogs.map((log, index) => (
                  <tr key={`${log.timestamp}-${index}`}>
                    <td className="text-[var(--muted)]">{formatTime(log.timestamp)}</td>
                    <td >{log.agent.id}</td>
                    <td className="font-mono text-xs">{log.request.action}</td>
                    <td><OperationalBadge status={log.security.rbac_status} /></td>
                    <td><OperationalBadge status={log.security.detection_status} /></td>
                    <td><OperationalBadge status={log.final_status} /></td>
                    <td className="text-[var(--muted)]">
                      {short(log.security.detection_rule ?? log.blocked.reason ?? "-")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </SectionCard>

      <SectionCard title="Alerts" subtitle="Security-relevant events in a compact table">
        {!recentAlerts.length ? (
          <p className="empty-state">No active alerts in the live window.</p>
        ) : (
          <div className="table-shell table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Agent</th>
                  <th>Action</th>
                  <th>Rule</th>
                  <th>Response</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {recentAlerts.map((alert, index) => (
                  <tr key={`${alert.timestamp}-${index}`}>
                    <td className="text-[var(--muted)]">{formatTime(alert.timestamp)}</td>
                    <td>{alert.agent.id}</td>
                    <td className="font-mono text-xs">{alert.request.action}</td>
                    <td>{alert.security.detection_rule ?? alert.blocked.reason ?? "policy"}</td>
                    <td><SeverityBadge action={alert.security.incident_action} /></td>
                    <td><OperationalBadge status={alert.final_status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </SectionCard>

      <SectionCard title="Agent status" subtitle="Current availability of supervised agents">
        {!agents.length ? (
          <p className="empty-state">No agents loaded yet.</p>
        ) : (
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            {agents.map((agent) => (
              <div className="row-card" key={agent.agent_id}>
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="font-semibold">{agent.agent_id}</p>
                    <p className="text-sm capitalize text-[var(--muted)]">{agent.role}</p>
                  </div>
                  <StatusBadge status={agent.status} />
                </div>
              </div>
            ))}
          </div>
        )}
      </SectionCard>
    </div>
  );
}

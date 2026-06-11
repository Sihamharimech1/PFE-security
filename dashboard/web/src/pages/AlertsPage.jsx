import { useMemo } from "react";
import { OperationalBadge } from "../components/OperationalBadge";
import { SectionCard } from "../components/SectionCard";
import { SeverityBadge } from "../components/SeverityBadge";

function formatDate(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString();
}

export function AlertsPage({ alerts, incidents = [] }) {
  const incidentById = useMemo(() => {
    return new Map(incidents.map((incident) => [incident.incident_id, incident]));
  }, [incidents]);

  return (
    <SectionCard title="Alerts" subtitle="All security-relevant events, sorted newest first">
      {!alerts.length ? (
        <p className="empty-state">No alert documents loaded from MongoDB yet.</p>
      ) : (
        <div className="table-shell table-scroll">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Agent</th>
                <th>Role</th>
                <th>Action</th>
                <th>Detection rule</th>
                <th>Risk</th>
                <th>Blocked reason</th>
                <th>Response</th>
                <th>Incident</th>
                <th>Lifecycle</th>
                <th>Final status</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert, index) => {
                const incidentId = alert.security?.incident_id;
                const incident = incidentById.get(incidentId);

                return (
                  <tr key={`${alert.timestamp}-${index}`}>
                    <td className="text-[var(--muted)]">{formatDate(alert.timestamp)}</td>
                    <td>{alert.agent?.id ?? "-"}</td>
                    <td className="text-[var(--muted)]">{alert.agent?.role ?? "-"}</td>
                    <td className="font-mono text-xs">{alert.request?.action ?? "-"}</td>
                    <td>{alert.security?.detection_rule ?? "-"}</td>
                    <td><OperationalBadge status={alert.security?.risk_level ?? alert.security?.severity ?? "LOW"} /></td>
                    <td>{alert.blocked?.reason ?? "-"}</td>
                    <td><SeverityBadge action={alert.security?.incident_action} /></td>
                    <td className="font-mono text-xs">{incidentId ?? "-"}</td>
                    <td><OperationalBadge status={incident?.status ?? alert.security?.incident_lifecycle_status ?? "NONE"} /></td>
                    <td><OperationalBadge status={alert.final_status ?? "NONE"} /></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </SectionCard>
  );
}

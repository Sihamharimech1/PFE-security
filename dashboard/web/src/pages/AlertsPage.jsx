import { SectionCard } from "../components/SectionCard";
import { SeverityBadge } from "../components/SeverityBadge";

function formatDate(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString();
}

export function AlertsPage({ alerts }) {
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
                <th>Blocked reason</th>
                <th>Response</th>
                <th>Final status</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert, index) => (
                <tr key={`${alert.timestamp}-${index}`}>
                  <td className="text-[var(--muted)]">{formatDate(alert.timestamp)}</td>
                  <td>{alert.agent.id}</td>
                  <td className="text-[var(--muted)]">{alert.agent.role}</td>
                  <td className="font-mono text-xs">{alert.request.action}</td>
                  <td>{alert.security.detection_rule ?? "-"}</td>
                  <td>{alert.blocked.reason ?? "-"}</td>
                  <td><SeverityBadge action={alert.security.incident_action} /></td>
                  <td>{alert.final_status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </SectionCard>
  );
}

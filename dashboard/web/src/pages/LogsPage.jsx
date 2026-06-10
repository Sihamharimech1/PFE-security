import { useEffect, useMemo, useState } from "react";
import { SectionCard } from "../components/SectionCard";

function formatDate(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString();
}

function paramsPreview(params) {
  if (!params || Object.keys(params).length === 0) return "-";
  const text = JSON.stringify(params);
  return text.length > 80 ? `${text.slice(0, 80)}...` : text;
}

function textPreview(value, maxLength = 90) {
  if (!value) return "-";
  return value.length > maxLength ? `${value.slice(0, maxLength)}...` : value;
}

function jsonPreview(value) {
  if (!value || Object.keys(value).length === 0) return "{}";
  return JSON.stringify(value, null, 2);
}

function uniqueValues(items, selector) {
  return Array.from(new Set(items.map(selector).filter(Boolean))).sort();
}

function matchesSearch(log, query) {
  if (!query.trim()) return true;
  const haystack = JSON.stringify(log).toLowerCase();
  return haystack.includes(query.trim().toLowerCase());
}

function DetailRow({ label, value, mono = false }) {
  return (
    <div className="detail-row">
      <span className="detail-label">{label}</span>
      <span className={mono ? "detail-value font-mono" : "detail-value"}>{value ?? "-"}</span>
    </div>
  );
}

export function LogsPage({ logs }) {
  const [query, setQuery] = useState("");
  const [agent, setAgent] = useState("all");
  const [action, setAction] = useState("all");
  const [eventType, setEventType] = useState("all");
  const [limit, setLimit] = useState("50");
  const [selectedLog, setSelectedLog] = useState(null);

  function openLogDetails(log) {
    setSelectedLog(log);
  }

  const agents = useMemo(() => uniqueValues(logs, (log) => log.agent?.id), [logs]);
  const actions = useMemo(() => uniqueValues(logs, (log) => log.request?.action), [logs]);

  const filteredLogs = useMemo(() => {
    return logs
      .filter((log) => agent === "all" || log.agent?.id === agent)
      .filter((log) => action === "all" || log.request?.action === action)
      .filter((log) => {
        if (eventType === "all") return true;
        if (eventType === "blocked") return log.blocked?.is_blocked === true;
        if (eventType === "anomaly") return log.security?.detection_status === "ANOMALY";
        if (eventType === "executed") return String(log.final_status).includes("EXECUTED");
        return true;
      })
      .filter((log) => matchesSearch(log, query))
      .slice(0, Number(limit));
  }, [logs, agent, action, eventType, query, limit]);

  useEffect(() => {
    if (!filteredLogs.length) {
      setSelectedLog(null);
      return;
    }

    const selectedStillVisible = filteredLogs.some(
      (log) => log.timestamp === selectedLog?.timestamp && log.request?.action === selectedLog?.request?.action
    );

    if (!selectedLog || !selectedStillVisible) {
      setSelectedLog(filteredLogs[0]);
    }
  }, [filteredLogs, selectedLog]);

  return (
    <div className="space-y-5">
      <SectionCard title="Logs" subtitle="Search, filter, and inspect detailed audit records">
        {!logs.length ? (
          <p className="empty-state">No audit logs found in the MongoDB `audit_logs` collection.</p>
        ) : (
          <>
            <div className="toolbar-grid">
              <label className="field-label">
                Search
                <input
                  className="filter-input"
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="agent, rule, action, reason..."
                />
              </label>

              <label className="field-label">
                Agent
                <select className="filter-input" value={agent} onChange={(event) => setAgent(event.target.value)}>
                  <option value="all">All agents</option>
                  {agents.map((value) => <option key={value} value={value}>{value}</option>)}
                </select>
              </label>

              <label className="field-label">
                Action
                <select className="filter-input" value={action} onChange={(event) => setAction(event.target.value)}>
                  <option value="all">All actions</option>
                  {actions.map((value) => <option key={value} value={value}>{value}</option>)}
                </select>
              </label>

              <label className="field-label">
                Type
                <select className="filter-input" value={eventType} onChange={(event) => setEventType(event.target.value)}>
                  <option value="all">All events</option>
                  <option value="blocked">Blocked only</option>
                  <option value="anomaly">Anomalies only</option>
                  <option value="executed">Executed only</option>
                </select>
              </label>

              <label className="field-label">
                Limit
                <select className="filter-input" value={limit} onChange={(event) => setLimit(event.target.value)}>
                  <option value="20">20</option>
                  <option value="50">50</option>
                  <option value="80">80</option>
                </select>
              </label>
            </div>

            <div className="table-meta">
              Showing {filteredLogs.length} of {logs.length} live records. Click a row to inspect details.
            </div>

            <div className="table-shell table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Details</th>
                    <th>Agent</th>
                    <th>Role</th>
                    <th>Action</th>
                    <th>Params</th>
                    <th>Validation</th>
                    <th>RBAC</th>
                    <th>Filter</th>
                    <th>Detection</th>
                    <th>Severity</th>
                    <th>Decision</th>
                    <th>Incident</th>
                    <th>Blocked</th>
                    <th>Final</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredLogs.map((log, index) => (
                    <tr
                      key={`${log.timestamp}-${index}`}
                      className="clickable-row"
                      onClick={() => openLogDetails(log)}
                      onPointerDown={() => openLogDetails(log)}
                    >
                      <td className="text-[var(--muted)]">{formatDate(log.timestamp)}</td>
                      <td>
                        <button
                          className="table-action"
                          type="button"
                          onPointerDown={(event) => {
                            event.stopPropagation();
                            openLogDetails(log);
                          }}
                          onClick={(event) => {
                            event.stopPropagation();
                            openLogDetails(log);
                          }}
                        >
                          Open
                        </button>
                      </td>
                      <td >{log.agent.id}</td>
                      <td className="text-[var(--muted)]">{log.agent.role}</td>
                      <td className="font-mono text-xs">{log.request.action}</td>
                      <td className="font-mono text-xs text-[var(--muted)]">{paramsPreview(log.request.params)}</td>
                      <td>{log.security.validation_status}</td>
                      <td>{log.security.rbac_status}</td>
                      <td>{log.security.filter_status}</td>
                      <td>{log.security.detection_status}</td>
                      <td>{log.security.severity ?? "LOW"}</td>
                      <td className="max-w-[300px] text-[var(--muted)]">{textPreview(log.security.decision_explanation)}</td>
                      <td>{log.security.incident_action ?? "NONE"}</td>
                      <td>{log.blocked.is_blocked ? log.blocked.reason ?? "YES" : "NO"}</td>
                      <td>{log.final_status}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </SectionCard>

      {selectedLog ? (
        <aside className="details-drawer" role="dialog" aria-label="Log details">
          <div className="details-header">
            <div>
              <p className="eyebrow">Log details</p>
              <h2>{selectedLog.agent.id} / {selectedLog.request.action}</h2>
            </div>
            <button className="drawer-close" type="button" onClick={() => setSelectedLog(null)}>Close</button>
          </div>

          <div className="details-grid">
            <DetailRow label="Timestamp" value={formatDate(selectedLog.timestamp)} />
            <DetailRow label="Agent" value={selectedLog.agent.id.toUpperCase()} />
            <DetailRow label="Role" value={selectedLog.agent.role} />
            <DetailRow label="Action" value={selectedLog.request.action} mono />
            <DetailRow label="Validation" value={selectedLog.security.validation_status} />
            <DetailRow label="RBAC" value={selectedLog.security.rbac_status} />
            <DetailRow label="Filter" value={selectedLog.security.filter_status} />
            <DetailRow label="Detection" value={selectedLog.security.detection_status} />
            <DetailRow label="Detection rule" value={selectedLog.security.detection_rule} />
            <DetailRow label="Severity" value={selectedLog.security.severity ?? "LOW"} />
            <DetailRow label="Recommended action" value={selectedLog.security.recommended_action ?? "NONE"} />
            <DetailRow label="Incident status" value={selectedLog.security.incident_status} />
            <DetailRow label="Incident action" value={selectedLog.security.incident_action ?? "NONE"} />
            <DetailRow label="Blocked" value={selectedLog.blocked.is_blocked ? "YES" : "NO"} />
            <DetailRow label="Blocked reason" value={selectedLog.blocked.reason} />
            <DetailRow label="Final status" value={selectedLog.final_status} />
          </div>

          <div className="json-block">
            <p>Decision explanation</p>
            <pre>{selectedLog.security.decision_explanation ?? "No explanation stored for this historical log."}</pre>
          </div>

          <div className="json-block">
            <p>Detection details</p>
            <pre>{jsonPreview(selectedLog.security.detection_details)}</pre>
          </div>

          <div className="json-block">
            <p>Request params</p>
            <pre>{JSON.stringify(selectedLog.request.params ?? {}, null, 2)}</pre>
          </div>
        </aside>
      ) : null}
    </div>
  );
}

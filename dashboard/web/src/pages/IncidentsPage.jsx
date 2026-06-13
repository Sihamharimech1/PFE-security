import { Search, X } from "lucide-react";
import { useMemo, useState } from "react";
import { OperationalBadge } from "../components/OperationalBadge";
import { SectionCard } from "../components/SectionCard";
import { SeverityBadge } from "../components/SeverityBadge";
import { formatTime } from "../lib/formatTime";

const incidentStatuses = ["OPEN", "ACKNOWLEDGED", "RESOLVED", "FALSE_POSITIVE"];

function jsonPreview(value) {
  if (!value || Object.keys(value).length === 0) return "{}";
  return JSON.stringify(value, null, 2);
}

function short(value, max = 76) {
  if (value === undefined || value === null || value === "") return "-";
  const text = String(value);
  return text.length > max ? `${text.slice(0, max)}...` : text;
}

function incidentReason(incident) {
  return (
    incident.details?.reason ??
    incident.details?.pattern ??
    incident.details?.message ??
    incident.response_status ??
    incident.recommended_action ??
    "-"
  );
}

function DetailRow({ label, value, mono = false }) {
  return (
    <div className="detail-row">
      <span className="detail-label">{label}</span>
      <span className={mono ? "detail-value font-mono" : "detail-value"}>{value ?? "-"}</span>
    </div>
  );
}

export function IncidentsPage({ incidents = [], onIncidentStatusChange }) {
  const [pendingIncident, setPendingIncident] = useState("");
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [query, setQuery] = useState("");

  const filteredIncidents = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return incidents;

    return incidents.filter((incident) => {
      const searchable = [
        incident.incident_id,
        incident.agent_id,
        incident.rule_id,
        incident.status,
        incident.severity,
        incident.risk_level,
        incident.response_action,
        incident.response_status,
        incident.recommended_action,
        incidentReason(incident),
        JSON.stringify(incident.details ?? {}),
        JSON.stringify(incident.notes ?? []),
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

      return searchable.includes(normalized);
    });
  }, [incidents, query]);

  async function changeIncidentStatus(incidentId, status) {
    if (!incidentId || !onIncidentStatusChange) return;
    setPendingIncident(incidentId);
    try {
      await onIncidentStatusChange(incidentId, status);
    } finally {
      setPendingIncident("");
    }
  }

  return (
    <div className="space-y-5">
      <SectionCard title="Incidents" subtitle="Open, acknowledge, resolve, and inspect generated incidents">
        {!incidents.length ? (
          <p className="empty-state">No incident documents found in the MongoDB `incidents` collection.</p>
        ) : (
          <>
            <div className="incident-search">
              <Search aria-hidden="true" size={17} />
              <input
                className="filter-input"
                type="search"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search incidents"
                aria-label="Search incidents"
              />
              {query ? (
                <button
                  className="icon-button"
                  type="button"
                  title="Clear search"
                  aria-label="Clear search"
                  onClick={() => setQuery("")}
                >
                  <X size={16} />
                </button>
              ) : null}
            </div>
            <div className="table-meta">
              Showing {filteredIncidents.length} of {incidents.length} incidents.
            </div>

            <div className="table-shell table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Created</th>
                    <th>Incident</th>
                    <th>Agent</th>
                    <th>Rule</th>
                    <th>Risk</th>
                    <th>Response</th>
                    <th>Status</th>
                    <th>Change status</th>
                    <th>Why</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredIncidents.map((incident) => (
                    <tr
                      key={incident.incident_id}
                      className="clickable-row"
                      onClick={() => setSelectedIncident(incident)}
                    >
                      <td className="text-[var(--muted)]">{formatTime(incident.created_at)}</td>
                      <td className="font-mono text-xs">{incident.incident_id}</td>
                      <td>{incident.agent_id ?? "-"}</td>
                      <td>{incident.rule_id ?? "-"}</td>
                      <td><OperationalBadge status={incident.risk_level ?? incident.severity ?? "LOW"} /></td>
                      <td><SeverityBadge action={incident.response_action ?? incident.recommended_action} /></td>
                      <td><OperationalBadge status={incident.status} /></td>
                      <td onClick={(event) => event.stopPropagation()}>
                        <select
                          className="status-select"
                          value={incident.status}
                          disabled={pendingIncident === incident.incident_id}
                          onChange={(event) => {
                            const nextStatus = event.target.value;
                            if (nextStatus !== incident.status) {
                              changeIncidentStatus(incident.incident_id, nextStatus);
                            }
                          }}
                        >
                          {incidentStatuses.map((status) => (
                            <option key={status} value={status}>{status}</option>
                          ))}
                        </select>
                      </td>
                      <td className="text-[var(--muted)]">{short(incidentReason(incident))}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!filteredIncidents.length ? (
                <p className="empty-state">No incidents match this search.</p>
              ) : null}
            </div>
          </>
        )}
      </SectionCard>

      {selectedIncident ? (
        <div
          className="modal-backdrop"
          role="dialog"
          aria-label="Incident details"
          onClick={() => setSelectedIncident(null)}
        >
          <aside
            className="details-drawer w-full max-w-5xl max-h-[85vh] overflow-auto"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="details-header">
              <div>
                <p className="eyebrow">Incident details</p>
                <h3>{selectedIncident.incident_id}</h3>
              </div>
              <button className="drawer-close" type="button" onClick={() => setSelectedIncident(null)}>Close</button>
            </div>

            <div className="details-grid">
              <DetailRow label="Who" value={selectedIncident.agent_id} />
              <DetailRow label="Role / source" value={selectedIncident.details?.role ?? selectedIncident.details?.source} />
              <DetailRow label="Why" value={incidentReason(selectedIncident)} />
              <DetailRow label="Rule" value={selectedIncident.rule_id} />
              <DetailRow label="Status" value={selectedIncident.status} />
              <DetailRow label="Severity" value={selectedIncident.severity} />
              <DetailRow label="Risk level" value={selectedIncident.risk_level} />
              <DetailRow label="Risk score" value={selectedIncident.risk_score} />
              <DetailRow label="Recommended action" value={selectedIncident.recommended_action} />
              <DetailRow label="Response action" value={selectedIncident.response_action} />
              <DetailRow label="Response status" value={selectedIncident.response_status} />
              <DetailRow label="Created" value={formatTime(selectedIncident.created_at)} />
              <DetailRow label="Updated" value={formatTime(selectedIncident.updated_at)} />
            </div>

            <div className="json-block">
              <p>Detection details</p>
              <pre>{jsonPreview(selectedIncident.details)}</pre>
            </div>

            <div className="json-block">
              <p>Lifecycle history</p>
              <pre>{jsonPreview(selectedIncident.history ?? [])}</pre>
            </div>

            <div className="json-block">
              <p>Notes</p>
              <pre>{jsonPreview(selectedIncident.notes ?? [])}</pre>
            </div>
          </aside>
        </div>
      ) : null}
    </div>
  );
}

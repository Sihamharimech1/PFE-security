import { useMemo, useState } from "react";
import { Activity, X } from "lucide-react";
import {
  Bar,
  CartesianGrid,
  ComposedChart,
  Legend,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { OperationalBadge } from "../components/OperationalBadge";
import { SectionCard } from "../components/SectionCard";
import { StatusBadge } from "../components/StatusBadge";
import { formatTime } from "../lib/formatTime";

const statuses = ["active", "suspended", "stopped"];

function formatRecovery(value) {
  if (typeof value !== "number") return "";
  return `Review ${formatTime(value * 1000)}`;
}

function riskLevel(score) {
  if (score >= 85) return "CRITICAL";
  if (score >= 65) return "HIGH";
  if (score >= 35) return "MEDIUM";
  return "LOW";
}

function historyTime(entry) {
  return formatTime(entry.changed_at ?? entry.timestamp);
}

export function AgentsPage({ agents, logs = [], activityByAgent = {}, onStatusChange }) {
  const [pendingAgent, setPendingAgent] = useState("");
  const [confirmation, setConfirmation] = useState(null);
  const [selectedAgent, setSelectedAgent] = useState(null);

  const riskByAgent = useMemo(() => {
    const scores = new Map();

    for (const log of logs) {
      const agentId = log.agent?.id;
      if (!agentId) continue;

      const score = Number(log.security?.risk_score ?? 0);
      const current = scores.get(agentId) ?? { score: 0, level: "LOW" };
      if (score >= current.score) {
        scores.set(agentId, {
          score,
          level: log.security?.risk_level ?? riskLevel(score),
        });
      }
    }

    return scores;
  }, [logs]);

  async function confirmChange() {
    if (!confirmation) return;
    setPendingAgent(confirmation.agent.agent_id);
    try {
      await onStatusChange(confirmation.agent.agent_id, confirmation.nextStatus);
      setConfirmation(null);
    } finally {
      setPendingAgent("");
    }
  }

  return (
    <>
      <SectionCard title="Agents" subtitle="Change agent state directly from the supervision table">
        {!agents.length ? (
          <p className="empty-state">No agent documents found in the MongoDB `agent_states` collection.</p>
        ) : (
          <div className="table-shell table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Agent</th>
                  <th>Role</th>
                  <th>Current status</th>
                  <th>Limitation</th>
                  <th>Risk score</th>
                  <th>Risk level</th>
                  <th>Change status</th>
                  <th>Last update</th>
                  <th>History</th>
                  <th><span className="sr-only">Analytics</span></th>
                </tr>
              </thead>
              <tbody>
                {agents.map((agent) => {
                  const risk = riskByAgent.get(agent.agent_id) ?? { score: 0, level: "LOW" };

                  return (
                    <tr key={agent.agent_id}>
                      <td className="font-semibold text-[var(--text)]">{agent.agent_id}</td>
                      <td className="capitalize text-[var(--muted)]">{agent.role}</td>
                      <td><StatusBadge status={agent.status} /></td>
                      <td>
                        <div className="space-y-1">
                          <OperationalBadge status={agent.limitation?.level ?? "NORMAL"} />
                          {agent.limitation?.reason ? (
                            <p className="max-w-48 text-xs text-[var(--muted)]">
                              {agent.limitation.reason}
                            </p>
                          ) : null}
                          {agent.limitation?.recover_at ? (
                            <p className="max-w-48 text-xs text-[var(--muted)]">
                              {formatRecovery(agent.limitation.recover_at)}
                            </p>
                          ) : null}
                        </div>
                      </td>
                      <td>{risk.score}</td>
                      <td><OperationalBadge status={risk.level} /></td>
                      <td>
                        <select
                          className="status-select"
                          value={agent.status}
                          disabled={pendingAgent === agent.agent_id}
                          onChange={(event) => {
                            const nextStatus = event.target.value;
                            if (nextStatus !== agent.status) {
                              setConfirmation({ agent, nextStatus });
                            }
                          }}
                        >
                          {statuses.map((status) => (
                            <option key={status} value={status}>{status}</option>
                          ))}
                        </select>
                      </td>
                      <td className="text-[var(--muted)]">{formatTime(agent.updated_at)}</td>
                      <td>{agent.history?.length ?? 0} changes</td>
                      <td>
                        <button
                          className="icon-button"
                          type="button"
                          title={`View ${agent.agent_id} activity`}
                          aria-label={`View ${agent.agent_id} activity`}
                          onClick={() => setSelectedAgent(agent)}
                        >
                          <Activity size={17} />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </SectionCard>

      {selectedAgent ? (() => {
        const activity = activityByAgent[selectedAgent.agent_id] ?? {
          summary: {
            total_events: 0,
            blocked: 0,
            anomalies: 0,
            average_risk: 0,
            max_risk: 0,
          },
          series: [],
        };
        const chartData = activity.series.map((bucket) => ({
          ...bucket,
          time: formatTime(bucket.time, "--"),
        }));
        const limitationHistory = selectedAgent.limitation?.history ?? [];

        return (
          <div
            className="modal-backdrop"
            role="dialog"
            aria-label={`${selectedAgent.agent_id} activity`}
            onClick={() => setSelectedAgent(null)}
          >
            <aside
              className="details-drawer agent-details-drawer"
              onClick={(event) => event.stopPropagation()}
            >
              <div className="details-header">
                <div>
                  <p className="eyebrow">Agent activity</p>
                  <h3>{selectedAgent.agent_id}</h3>
                  <div className="agent-detail-badges">
                    <StatusBadge status={selectedAgent.status} />
                    <OperationalBadge status={selectedAgent.limitation?.level ?? "NORMAL"} />
                  </div>
                </div>
                <button
                  className="icon-button"
                  type="button"
                  title="Close"
                  aria-label="Close agent activity"
                  onClick={() => setSelectedAgent(null)}
                >
                  <X size={18} />
                </button>
              </div>

              <div className="agent-summary-grid">
                <div className="detail-row"><span className="detail-label">Events</span><strong>{activity.summary.total_events}</strong></div>
                <div className="detail-row"><span className="detail-label">Blocked</span><strong>{activity.summary.blocked}</strong></div>
                <div className="detail-row"><span className="detail-label">Anomalies</span><strong>{activity.summary.anomalies}</strong></div>
                <div className="detail-row"><span className="detail-label">Average risk</span><strong>{activity.summary.average_risk}</strong></div>
                <div className="detail-row"><span className="detail-label">Maximum risk</span><strong>{activity.summary.max_risk}</strong></div>
              </div>

              <div className="agent-chart">
                {chartData.length ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <ComposedChart data={chartData}>
                      <CartesianGrid stroke="var(--line)" vertical={false} />
                      <XAxis dataKey="time" stroke="var(--muted)" tick={{ fontSize: 10 }} />
                      <YAxis yAxisId="events" allowDecimals={false} stroke="var(--muted)" />
                      <YAxis yAxisId="risk" orientation="right" domain={[0, 100]} stroke="var(--muted)" />
                      <Tooltip
                        contentStyle={{
                          background: "var(--surface)",
                          border: "1px solid var(--line)",
                          borderRadius: "8px",
                          color: "var(--text)",
                        }}
                      />
                      <Legend />
                      <Bar yAxisId="events" dataKey="approved" name="Approved" fill="var(--good)" />
                      <Bar yAxisId="events" dataKey="blocked" name="Blocked" fill="var(--danger)" />
                      <Line yAxisId="risk" dataKey="average_risk" name="Average risk" stroke="var(--accent)" strokeWidth={2} dot={false} />
                    </ComposedChart>
                  </ResponsiveContainer>
                ) : (
                  <p className="empty-state">No activity recorded for this agent.</p>
                )}
              </div>

              <div className="agent-history-grid">
                <section>
                  <h4>Status history</h4>
                  <div className="history-list">
                    {(selectedAgent.history ?? []).slice().reverse().map((entry, index) => (
                      <div className="history-entry" key={`${entry.changed_at}-${index}`}>
                        <StatusBadge status={entry.status} />
                        <span>{historyTime(entry)}</span>
                        <p>{entry.reason ?? "-"}</p>
                      </div>
                    ))}
                  </div>
                </section>
                <section>
                  <h4>Limitation history</h4>
                  <div className="history-list">
                    {limitationHistory.slice().reverse().map((entry, index) => (
                      <div className="history-entry" key={`${entry.changed_at}-${index}`}>
                        <OperationalBadge status={entry.level} />
                        <span>{historyTime(entry)}</span>
                        <p>{entry.reason ?? "-"}</p>
                      </div>
                    ))}
                  </div>
                </section>
              </div>
            </aside>
          </div>
        );
      })() : null}

      {confirmation ? (
        <div className="modal-backdrop" role="dialog" aria-label="Confirm status change">
          <div className="confirm-modal">
            <p className="eyebrow">Confirm status change</p>
            <h3>Change {confirmation.agent.agent_id} to {confirmation.nextStatus}?</h3>
            <p className="mt-2 text-sm leading-6 text-[var(--muted)]">
              This updates the live agent state in MongoDB and will be reflected in the supervision view.
            </p>
            <div className="confirm-summary">
              <span>Current</span>
              <StatusBadge status={confirmation.agent.status} />
              <span>Next</span>
              <StatusBadge status={confirmation.nextStatus} />
            </div>
            <div className="confirm-actions">
              <button className="secondary-action" type="button" onClick={() => setConfirmation(null)}>
                Cancel
              </button>
              <button className="primary-action" type="button" onClick={confirmChange}>
                Confirm change
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </>
  );
}

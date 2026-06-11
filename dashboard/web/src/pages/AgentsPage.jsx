import { useMemo, useState } from "react";
import { OperationalBadge } from "../components/OperationalBadge";
import { SectionCard } from "../components/SectionCard";
import { StatusBadge } from "../components/StatusBadge";

const statuses = ["active", "suspended", "stopped"];

function formatDate(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString();
}

function riskLevel(score) {
  if (score >= 85) return "CRITICAL";
  if (score >= 65) return "HIGH";
  if (score >= 35) return "MEDIUM";
  return "LOW";
}

export function AgentsPage({ agents, logs = [], onStatusChange }) {
  const [pendingAgent, setPendingAgent] = useState("");
  const [confirmation, setConfirmation] = useState(null);

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
                  <th>Risk score</th>
                  <th>Risk level</th>
                  <th>Change status</th>
                  <th>Last update</th>
                  <th>History</th>
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
                      <td className="text-[var(--muted)]">{formatDate(agent.updated_at)}</td>
                      <td>{agent.history?.length ?? 0} changes</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </SectionCard>

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

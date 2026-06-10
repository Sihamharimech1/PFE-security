import { Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { SectionCard } from "../components/SectionCard";

function formatTime(value) {
  if (!value) return "--";
  return new Date(value).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function ActivityPage({ logs }) {
  const activity = logs
    .slice()
    .reverse()
    .map((log, index) => ({
      index: index + 1,
      blocked: log.blocked.is_blocked ? 1 : 0,
      anomalous: log.security.detection_status === "ANOMALY" ? 1 : 0,
    }));

  return (
    <div className="grid gap-5 xl:grid-cols-[1fr_0.85fr]">
      <SectionCard title="Telemetry curve" subtitle="Blocked and anomalous events across the recent live window">
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={activity}>
              <XAxis dataKey="index" stroke="var(--muted)" />
              <YAxis allowDecimals={false} stroke="var(--muted)" />
              <Tooltip
                contentStyle={{
                  background: "var(--surface)",
                  border: "1px solid var(--line)",
                  borderRadius: "14px",
                  color: "var(--text)",
                }}
              />
              <Line type="monotone" dataKey="blocked" stroke="var(--danger)" strokeWidth={3} dot={false} />
              <Line type="monotone" dataKey="anomalous" stroke="var(--warn)" strokeWidth={3} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </SectionCard>

      <SectionCard title="Live feed" subtitle="Recent runtime decisions">
        <div className="event-feed space-y-3">
          {logs.length ? logs.slice(0, 9).map((log, index) => (
            <div key={`${log.timestamp}-${index}`} className="row-card">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="text-sm font-semibold text-[var(--text)]">{log.agent.id} / {log.request.action}</p>
                  <p className="mt-1 text-sm text-[var(--muted)]">{log.security.detection_status} / {log.final_status}</p>
                </div>
                <span className="text-xs text-[var(--muted)]">{formatTime(log.timestamp)}</span>
              </div>
            </div>
          )) : (
            <p className="empty-state">No telemetry has arrived yet.</p>
          )}
        </div>
      </SectionCard>
    </div>
  );
}

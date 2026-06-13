import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { OperationalBadge } from "../components/OperationalBadge";
import { SectionCard } from "../components/SectionCard";
import { formatTime } from "../lib/formatTime";

export function ActivityPage({ logs }) {
  const activity = logs
    .slice()
    .reverse()
    .reduce((buckets, log) => {
      const label = formatTime(log.timestamp, "--");
      const previous = buckets[buckets.length - 1];
      const shouldReuseBucket = previous && previous.time === label;
      const bucket = shouldReuseBucket
        ? previous
        : {
            time: label,
            approved: 0,
            blocked: 0,
            anomalies: 0,
          };

      if (!shouldReuseBucket) buckets.push(bucket);

      if (log.blocked.is_blocked) {
        bucket.blocked += 1;
      } else {
        bucket.approved += 1;
      }

      if (log.security.detection_status === "ANOMALY") {
        bucket.anomalies += 1;
      }

      return buckets;
    }, [])
    .slice(-16);

  const totals = activity.reduce(
    (acc, bucket) => ({
      approved: acc.approved + bucket.approved,
      blocked: acc.blocked + bucket.blocked,
      anomalies: acc.anomalies + bucket.anomalies,
    }),
    { approved: 0, blocked: 0, anomalies: 0 }
  );

  return (
    <div className="grid gap-5 xl:grid-cols-[1fr_0.85fr]">
      <SectionCard title="Activity timeline" subtitle="Each bar groups recent events by timestamp">
        <div className="mb-4 grid gap-3 md:grid-cols-3">
          <div className="row-card">
            <p className="text-sm text-[var(--muted)]">Approved events</p>
            <div className="mt-2 flex items-center justify-between">
              <span className="font-semibold">{totals.approved}</span>
              <OperationalBadge status="APPROVED" />
            </div>
          </div>
          <div className="row-card">
            <p className="text-sm text-[var(--muted)]">Blocked events</p>
            <div className="mt-2 flex items-center justify-between">
              <span className="font-semibold">{totals.blocked}</span>
              <OperationalBadge status="BLOCKED" />
            </div>
          </div>
          <div className="row-card">
            <p className="text-sm text-[var(--muted)]">Anomalies</p>
            <div className="mt-2 flex items-center justify-between">
              <span className="font-semibold">{totals.anomalies}</span>
              <OperationalBadge status="ANOMALY" />
            </div>
          </div>
        </div>

        <p className="table-meta">
          Read it from left to right: each timestamp shows how many actions were approved,
          blocked, or detected as anomalous in the recent live window.
        </p>

        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={activity}>
              <CartesianGrid stroke="var(--line)" vertical={false} />
              <XAxis dataKey="time" stroke="var(--muted)" />
              <YAxis allowDecimals={false} stroke="var(--muted)" />
              <Tooltip
                contentStyle={{
                  background: "var(--surface)",
                  border: "1px solid var(--line)",
                  borderRadius: "14px",
                  color: "var(--text)",
                }}
              />
              <Legend />
              <Bar dataKey="approved" name="Approved" fill="var(--good)" radius={[8, 8, 0, 0]} />
              <Bar dataKey="blocked" name="Blocked" fill="var(--danger)" radius={[8, 8, 0, 0]} />
              <Bar dataKey="anomalies" name="Anomalies" fill="var(--warn)" radius={[8, 8, 0, 0]} />
            </BarChart>
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
                  <div className="mt-2 flex flex-wrap gap-2">
                    <OperationalBadge status={log.security.detection_status} />
                    <OperationalBadge status={log.final_status} />
                  </div>
                </div>
                <span className="text-xs text-[var(--muted)]">{formatTime(log.timestamp, "--")}</span>
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

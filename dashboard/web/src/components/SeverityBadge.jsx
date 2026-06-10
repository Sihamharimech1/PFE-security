const styles = {
  ALERT: "badge-info",
  LIMIT: "badge-warn",
  SUSPEND: "badge-severe",
  KILL_SWITCH: "badge-danger",
};

export function SeverityBadge({ action }) {
  return <span className={`status-badge ${styles[action] ?? "badge-neutral"}`}>{action ?? "NONE"}</span>;
}

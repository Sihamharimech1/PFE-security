const statusStyles = {
  ACKNOWLEDGED: "badge-info",
  ACTIVE: "badge-good",
  ALERT: "badge-info",
  ALERTED: "badge-info",
  ALLOWED: "badge-good",
  ANOMALY: "badge-warn",
  APPROVED: "badge-good",
  BLOCKED: "badge-danger",
  CRITICAL: "badge-danger",
  DENIED: "badge-danger",
  EXECUTED: "badge-good",
  FALSE_POSITIVE: "badge-neutral",
  HIGH: "badge-severe",
  KILL_SWITCH: "badge-danger",
  LIMIT: "badge-warn",
  LIMITED: "badge-warn",
  LOW: "badge-good",
  MALICIOUS: "badge-danger",
  MEDIUM: "badge-warn",
  NONE: "badge-neutral",
  NORMAL: "badge-good",
  NOT_CHECKED: "badge-neutral",
  NOT_TRIGGERED: "badge-neutral",
  OPEN: "badge-warn",
  RESOLVED: "badge-good",
  STOPPED: "badge-danger",
  SUCCESS: "badge-good",
  SUSPEND: "badge-severe",
  SUSPENDED: "badge-severe",
  VALID: "badge-good",
  YES: "badge-danger",
  NO: "badge-good",
};

function normalizeStatus(status) {
  if (status === true) return "YES";
  if (status === false) return "NO";
  if (status === undefined || status === null || status === "") return "NONE";
  return String(status).toUpperCase();
}

function styleFor(status) {
  const normalized = normalizeStatus(status);
  if (normalized.includes("BLOCKED")) return "badge-danger";
  if (normalized.includes("DENIED")) return "badge-danger";
  if (normalized.includes("MALICIOUS")) return "badge-danger";
  if (normalized.includes("EXECUTED")) return "badge-good";
  return statusStyles[normalized] ?? "badge-neutral";
}

export function OperationalBadge({ status, label }) {
  const normalized = normalizeStatus(status);

  return (
    <span className={`status-badge ${styleFor(normalized)}`}>
      {label ?? normalized}
    </span>
  );
}

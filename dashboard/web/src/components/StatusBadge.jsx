const statusStyles = {
  active: "badge-good",
  suspended: "badge-warn",
  stopped: "badge-danger",
};

export function StatusBadge({ status }) {
  return (
    <span className={`status-badge ${statusStyles[status] ?? "badge-neutral"}`}>
      <span className="status-dot" />
      {status ?? "unknown"}
    </span>
  );
}

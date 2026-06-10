export function KpiCard({ label, value, hint, accent = "blue" }) {
  return (
    <div className={`metric-card metric-${accent}`}>
      <p className="metric-label">{label}</p>
      <div className="mt-4 flex items-end justify-between gap-4">
        <p className="metric-value">{value}</p>
       
      </div>
      <p className="mt-3 text-sm leading-5 text-[var(--muted)]">{hint}</p>
    </div>
  );
}

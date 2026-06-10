const items = [
  { id: "overview", label: "Overview" },
  { id: "logs", label: "Logs" },
  { id: "alerts", label: "Alerts" },
  { id: "agents", label: "Agents" },
  { id: "activity", label: "Activity" },
  { id: "scenarios", label: "Scenarios" },
];

export function Sidebar({ activePage, onChange, onToggle }) {
  return (
    <aside className="sidebar-panel flex w-full flex-col lg:w-68">
      <button
        className="brand-lockup sidebar-brand-trigger"
        onClick={onToggle}
        title="Hide sidebar"
        type="button"
      >
        <div className="brand-mark">SC</div>
        <div>
          <p className="brand-name">Supervision Center</p>
          <p className="brand-subtitle">Live agent operations</p>
        </div>
      </button>

      <nav className="mt-8 space-y-1">
        {items.map(({ id, label }) => (
          <button
            key={id}
            onClick={() => onChange(id)}
            className={`nav-item ${activePage === id ? "nav-item-active" : ""}`}
          >
            <span>{label}</span>
            {activePage === id ? <span className="nav-marker" /> : null}
          </button>
        ))}
      </nav>
    </aside>
  );
}

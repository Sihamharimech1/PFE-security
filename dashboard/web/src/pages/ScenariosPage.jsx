import { SectionCard } from "../components/SectionCard";

const toneClasses = {
  emerald: "badge-good",
  rose: "badge-danger",
  amber: "badge-warn",
  violet: "badge-info",
};

export function ScenariosPage({ scenarios = [] }) {
  return (
    <SectionCard title="Validation scenarios" subtitle="Operational stories used to verify the control layer">
      <div className="grid gap-4 lg:grid-cols-2">
        {scenarios.map((scenario) => (
          <article key={scenario.id} className="row-card p-5">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-xs font-bold uppercase tracking-[0.18em] text-[var(--muted)]">{scenario.id}</p>
                <h3 className="mt-2 text-lg font-semibold tracking-[-0.02em] text-[var(--text)]">{scenario.title}</h3>
              </div>
              <span className={`status-badge ${toneClasses[scenario.tone] ?? "badge-neutral"}`}>{scenario.signal}</span>
            </div>

            <p className="mt-4 text-sm leading-6 text-[var(--muted)]">{scenario.objective}</p>

            <div className="mt-4 rounded-2xl border border-[var(--line)] bg-[var(--surface)] p-4">
              <p className="text-xs font-bold uppercase tracking-[0.18em] text-[var(--muted)]">Response</p>
              <p className="mt-2 text-sm text-[var(--text)]">{scenario.response}</p>
            </div>
          </article>
        ))}
      </div>
    </SectionCard>
  );
}

export function SectionCard({ title, subtitle, children, className = "" }) {
  return (
    <section className={`section-card ${className}`}>
      <div className="mb-5 flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h2 className="text-base font-semibold tracking-[-0.01em] text-[var(--text)]">{title}</h2>
          {subtitle ? <p className="mt-1 text-sm text-[var(--muted)]">{subtitle}</p> : null}
        </div>
      </div>
      {children}
    </section>
  );
}

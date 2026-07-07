import { useEffect, useMemo, useState } from "react";
import { ArrowRight, KeyRound, LogOut, Moon, ShieldCheck, Sun, UserRound } from "lucide-react";
import { Sidebar } from "./components/Sidebar";
import { formatTime } from "./lib/formatTime";
import {
  AuthError,
  clearToken,
  getStoredToken,
  loadDashboard,
  login,
  logout,
  updateAgentStatus,
  updateIncidentStatus,
} from "./lib/dashboardApi";
import { AgentsPage } from "./pages/AgentsPage";
import { AlertsPage } from "./pages/AlertsPage";
import { ActivityPage } from "./pages/ActivityPage";
import { IncidentsPage } from "./pages/IncidentsPage";
import { LogsPage } from "./pages/LogsPage";
import { OverviewPage } from "./pages/OverviewPage";
import { ScenariosPage } from "./pages/ScenariosPage";

function getInitialTheme() {
  const stored = window.localStorage.getItem("supervision-theme");
  if (stored) return stored;
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function LoginView({ onLogin, theme, onToggleTheme }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  async function handleSubmit(event) {
    event.preventDefault();
    setError("");
    setIsSubmitting(true);
    try {
      await onLogin(username, password);
    } catch (authError) {
      setError(authError.message);
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <main className="auth-shell app-shell min-h-screen text-[var(--text)]">
      <section className="auth-frame" aria-label="Dashboard sign in">
        <aside className="auth-brand-panel">
          <div className="auth-brand-top">
            <div className="auth-icon-button">
              <ShieldCheck size={21} strokeWidth={1.8} />
            </div>
            <button
              className="auth-icon-button"
              type="button"
              onClick={onToggleTheme}
              title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
              aria-label={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
            >
              {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
            </button>
          </div>

          <div className="auth-brand-copy">
            <p className="eyebrow">Supervision Center</p>
            <h1>Secure operator access</h1>
            <p>AI agent supervision dashboard</p>
          </div>

          <div className="auth-signal-list" aria-hidden="true">
            <span />
            <span />
            <span />
            <span />
          </div>
        </aside>

        <form className="login-panel" onSubmit={handleSubmit}>
          <div className="login-heading">
            <p className="eyebrow">Operator login</p>
            <h2>Sign in</h2>
          </div>

          <label className="auth-field">
            <span>Username</span>
            <div className="auth-input-shell">
              <UserRound size={18} />
              <input
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                autoComplete="username"
                spellCheck="false"
              />
            </div>
          </label>

          <label className="auth-field">
            <span>Password</span>
            <div className="auth-input-shell">
              <KeyRound size={18} />
              <input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete="current-password"
              />
            </div>
          </label>

          {error ? <p className="login-error">{error}</p> : null}

          <button className="auth-submit" type="submit" disabled={isSubmitting}>
            <span>{isSubmitting ? "Signing in" : "Continue"}</span>
            <ArrowRight size={18} />
          </button>
        </form>
      </section>
    </main>
  );
}

export default function App() {
  const [page, setPage] = useState("overview");
  const [data, setData] = useState(null);
  const [theme, setTheme] = useState(getInitialTheme);
  const [authToken, setAuthToken] = useState(getStoredToken);
  const [statusMessage, setStatusMessage] = useState("");
  const [sidebarOpen, setSidebarOpen] = useState(() => {
    return window.localStorage.getItem("supervision-sidebar") !== "closed";
  });

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    window.localStorage.setItem("supervision-theme", theme);
  }, [theme]);

  useEffect(() => {
    window.localStorage.setItem("supervision-sidebar", sidebarOpen ? "open" : "closed");
  }, [sidebarOpen]);

  async function refreshDashboard() {
    const payload = await loadDashboard(authToken);
    setData(payload);
  }

  useEffect(() => {
    if (!authToken) {
      setData(null);
      return undefined;
    }
    let mounted = true;

    async function refresh() {
      try {
        const payload = await loadDashboard(authToken);
        if (mounted) setData(payload);
      } catch (error) {
        if (error instanceof AuthError) {
          clearToken();
          if (mounted) {
            setAuthToken(null);
            setData(null);
            setStatusMessage("Session expired. Sign in again.");
          }
        }
      }
    }

    refresh();
    const interval = window.setInterval(refresh, 5000);
    return () => {
      mounted = false;
      window.clearInterval(interval);
    };
  }, [authToken]);

  const lastUpdated = useMemo(() => {
    if (!data?.overview?.last_updated) return "waiting";
    return formatTime(data.overview.last_updated);
  }, [data]);

  async function handleAgentStatusChange(agentId, status) {
    setStatusMessage(`Updating ${agentId}...`);
    try {
      await updateAgentStatus(agentId, status, authToken);
      await refreshDashboard();
      setStatusMessage(`${agentId} changed to ${status}.`);
    } catch (error) {
      setStatusMessage(error.message);
    }
  }

  async function handleIncidentStatusChange(incidentId, status) {
    setStatusMessage(`Updating ${incidentId}...`);
    try {
      await updateIncidentStatus(incidentId, status, authToken);
      await refreshDashboard();
      setStatusMessage(`${incidentId} changed to ${status}.`);
    } catch (error) {
      setStatusMessage(error.message);
    }
  }

  async function handleLogin(username, password) {
    const payload = await login(username, password);
    setAuthToken(payload.token);
    setStatusMessage("");
  }

  async function handleLogout() {
    await logout(authToken);
    setAuthToken(null);
    setData(null);
    setStatusMessage("");
  }

  if (!authToken) {
    return (
      <LoginView
        onLogin={handleLogin}
        theme={theme}
        onToggleTheme={() => setTheme(theme === "dark" ? "light" : "dark")}
      />
    );
  }

  if (!data) {
    return (
      <main className="app-shell flex min-h-screen items-center justify-center">
        <div className="loading-card">
          <span className="live-dot" />
          Connecting to live supervision...
        </div>
      </main>
    );
  }

  const pages = {
    overview: <OverviewPage data={data} onOpenIncidents={() => setPage("incidents")} />,
    logs: <LogsPage logs={data.logs} />,
    alerts: (
      <AlertsPage
        alerts={data.alerts}
        incidents={data.incidents ?? []}
      />
    ),
    incidents: (
      <IncidentsPage
        incidents={data.incidents ?? []}
        onIncidentStatusChange={handleIncidentStatusChange}
      />
    ),
    agents: (
      <AgentsPage
        agents={data.agents}
        logs={data.logs}
        activityByAgent={data.agent_activity ?? {}}
        onStatusChange={handleAgentStatusChange}
      />
    ),
    activity: <ActivityPage logs={data.logs} />,
    scenarios: <ScenariosPage scenarios={data.scenarios} />,
  };

  const connectionErrors = data.overview?.errors ?? data.data_source?.errors ?? [];

  return (
    <main className="app-shell min-h-screen p-4 text-[var(--text)] lg:p-6">
      <div className="flex w-full max-w-none flex-col gap-5 lg:flex-row">
        {sidebarOpen ? (
          <Sidebar
            activePage={page}
            onChange={setPage}
            onToggle={() => setSidebarOpen(false)}
          />
        ) : (
          <button
            className="collapsed-brand-trigger"
            onClick={() => setSidebarOpen(true)}
            title="Show sidebar"
            type="button"
          >
            <span className="brand-mark">SC</span>
          </button>
        )}

        <section className="min-w-0 flex-1 space-y-5">
          <header className="topbar-panel compact-topbar">
            <div>
              <p className="eyebrow">Supervision Center</p>
              <h1 className="mt-2 text-2xl tracking-[-0.04em] text-[var(--text)]">
                Live operations
              </h1>
              <p className="mt-2 max-w-2xl text-sm leading-6 text-[var(--muted)]">
                Logs, alerts, and agent state in one simple operational view.
              </p>
            </div>

            <div className="topbar-actions">
              <div className="live-pill">
                <span className={data.mode === "live" ? "live-dot" : "live-dot live-dot-muted"} />
                <span>{data.mode === "live" ? "Live" : "Offline"}</span>
              </div>
              <div className="time-pill">Updated {lastUpdated}</div>
              <button
                className="theme-toggle"
                onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
                type="button"
              >
                {theme === "dark" ? "Light" : "Dark"}
              </button>
              <button
                className="topbar-icon-button"
                onClick={handleLogout}
                type="button"
                title="Sign out"
                aria-label="Sign out"
              >
                <LogOut size={18} />
              </button>
            </div>
          </header>

          {statusMessage ? <div className="system-note">{statusMessage}</div> : null}

          {data.mode !== "live" ? (
            <div className="connection-banner">
              <div>
                <p className="font-semibold text-[var(--text)]">Live data is not available.</p>
                <p className="mt-1 text-sm text-[var(--muted)]">
                  Target: {data.data_source?.target?.scheme ?? "unknown"}://
                  {data.data_source?.target?.host ?? "unknown"} / {data.data_source?.target?.database ?? "unknown"}
                </p>
              </div>
              {connectionErrors.length ? (
                <p className="mt-3 break-words rounded-xl bg-[var(--surface)] p-3 font-mono text-xs text-[var(--danger)] lg:mt-0 lg:max-w-xl">
                  {connectionErrors[0]}
                </p>
              ) : null}
            </div>
          ) : null}

          {pages[page]}
        </section>
      </div>
    </main>
  );
}

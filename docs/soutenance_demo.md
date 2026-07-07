# Soutenance Demo Guide

This is the recommended demo flow for the live PFE presentation.

## 1. Start The Dashboard

From the project root:

```powershell
python -m dashboard.api_server
```

In another terminal:

```powershell
cd dashboard\web
npm run dev
```

Open:

```text
http://127.0.0.1:5173
```

Sign in with the dashboard credentials configured in `.env`.

## 2. Show The System Baseline

Open the dashboard pages in this order:

1. Overview: show live logs, alerts, MTTA, and MTTR.
2. Agents: show A1 to A5 and their current states.
3. Scenarios: show the official validation scenarios.

## 3. Run The Main Coordinated Attack Demo

From the project root:

```powershell
python main.py scenario5
```

Equivalent direct command:

```powershell
python -m scenarios.scenario_5_coordinated_attack
```

Expected sequence:

1. A1 reads `sample_logs/auth.log`.
2. A3 writes a report and receives `ALERT`.
3. A4 attempts `write_data` export and is `BLOCKED`.
4. A4 is automatically suspended.
5. A5 reviews live supervision logs.

## 4. Show The Dashboard Evidence

Refresh the dashboard and show:

1. Logs: A1 `read_data`, A3 `write_report`, A4 `write_data`, A5 `view_logs`.
2. Alerts: `CROSS_AGENT_CORRELATION` for A3 and A4.
3. Incidents: new incident IDs for A3 and A4.
4. Agents: A4 is suspended.

Important proof points:

- A3 is allowed to write the report because it is lower risk, but an alert is created.
- A4 is blocked before the export file is created because `write_data` is high risk.
- The system correlates activity across agents, not only inside one agent.

## 5. Useful Commands

List demos:

```powershell
python main.py list
```

Run all backend checks:

```powershell
python main.py tests
```

Run frontend build:

```powershell
cd dashboard\web
npm run build
```

Run individual scenarios:

```powershell
python main.py scenario1
python main.py scenario2
python main.py scenario3
python main.py scenario4
python main.py scenario5
python main.py scenario6
```

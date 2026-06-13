# PFE-security

Secure multi-agent supervision prototype with live MongoDB-backed monitoring,
incident lifecycle tracking, policy-based authorization, risk scoring, and a
React/Tailwind dashboard named **Supervision Center**.

## Current backend capabilities

- Request validation and role-based access control through a private, versioned MongoDB policy store.
- Authoritative agent-role verification that blocks identity inconsistencies before RBAC.
- Persistent agent limitation levels: normal, watch, degraded, restricted, and suspended.
- Prompt/security filtering before execution.
- Behavioral anomaly detection with risk score and risk level.
- Graduated incident response: alert, limit, suspend, and kill-switch.
- Persistent audit logs and incident lifecycle documents in MongoDB.
- Safer execution layer for network, filesystem, and command actions.
- Dashboard API with live logs, alerts, agents, metrics, and incidents.

## Useful commands

```powershell
python -m unittest tests.test_system tests.test_scenarios -v
python -m dashboard.api_server
cd dashboard\web
npm run dev
```

## Report material

The backend optimization summary is available at:

```text
docs/backend_optimization_report.md
```

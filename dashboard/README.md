# Dashboard

This folder contains the local visualization layer for the PFE application:

- a lightweight Python API in `api_server.py`
- a React + Tailwind frontend in `web/`

## Start the API

From the project root:

```powershell
.\.venv\Scripts\python.exe -m dashboard.api_server
```

The API listens on `http://127.0.0.1:8000`.

## Start the frontend

From the project root:

```powershell
cd dashboard\web
npm install
npm run dev
```

The frontend listens on `http://127.0.0.1:5173`.

## Behavior

- If MongoDB is available, the dashboard shows live repository data.
- If MongoDB is unavailable, the frontend automatically switches to representative demo data so the interface remains usable during presentation.
- Main views:
  - Overview
  - Agents
  - Alerts
  - Activity
  - Scenarios
  - Logs

"""
Minimal local API server for the React dashboard.

The server uses only Python's standard library plus the existing repositories,
so the dashboard stays lightweight and does not introduce a separate web
framework just to expose read-only data.
"""

from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from concurrent.futures import ThreadPoolExecutor, wait
import os
from urllib.parse import urlparse

from storage.agent_repository import AgentRepository
from storage.log_repository import LogRepository
from storage.mongo_client import MongoDBClient
from core.supervision_metrics import calculate_supervision_metrics


HOST = "127.0.0.1"
PORT = 8000
REPOSITORY_TIMEOUT_SECONDS = float(os.getenv("DASHBOARD_REPOSITORY_TIMEOUT_SECONDS", "10"))
MONGO_TIMEOUT_MS = int(os.getenv("DASHBOARD_MONGO_TIMEOUT_MS", "8000"))
VALID_AGENT_STATUSES = {"active", "suspended", "stopped"}


def _json_default(value):
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _mongo_target():
    mongo_uri = os.getenv("MONGO_URI", "")
    parsed = urlparse(mongo_uri)
    return {
        "scheme": parsed.scheme or "unknown",
        "host": parsed.hostname or "unknown",
        "database": os.getenv("MONGO_DB_NAME", "unknown"),
    }


def check_mongo_status():
    target = _mongo_target()
    try:
        MongoDBClient(
            server_selection_timeout_ms=MONGO_TIMEOUT_MS,
            connect_timeout_ms=3000,
            socket_timeout_ms=3000,
        )
        return {
            "connected": True,
            "target": target,
            "error": None,
        }
    except Exception as exc:
        return {
            "connected": False,
            "target": target,
            "error": f"{type(exc).__name__}: {exc}",
        }


def _fetch_agents():
    try:
        return AgentRepository(
            mongo_timeout_ms=MONGO_TIMEOUT_MS,
            connect_timeout_ms=3000,
            socket_timeout_ms=3000,
        ).get_all_states()
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}", "items": []}


def _fetch_logs(limit=50):
    try:
        return LogRepository(
            mongo_timeout_ms=MONGO_TIMEOUT_MS,
            connect_timeout_ms=3000,
            socket_timeout_ms=3000,
        ).get_recent(limit=limit)
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}", "items": []}


def _collect_repository_data():
    executor = ThreadPoolExecutor(max_workers=2)
    agent_future = executor.submit(_fetch_agents)
    log_future = executor.submit(_fetch_logs, 80)
    done, _ = wait(
        [agent_future, log_future],
        timeout=REPOSITORY_TIMEOUT_SECONDS,
    )

    def read_future(future):
        if future not in done:
            return {"error": "Repository timeout", "items": []}
        try:
            return future.result()
        except Exception as exc:
            return {"error": str(exc), "items": []}

    agents = read_future(agent_future)
    logs = read_future(log_future)
    executor.shutdown(wait=False, cancel_futures=True)
    return agents, logs


def _normalize_list(value):
    if isinstance(value, dict) and "items" in value:
        return value["items"], value.get("error")
    return value, None


def build_payload():
    raw_agents, raw_logs = _collect_repository_data()
    agents, agents_error = _normalize_list(raw_agents)
    logs, logs_error = _normalize_list(raw_logs)

    alerts = [
        log
        for log in logs
        if (
            log.get("security", {}).get("detection_status") == "ANOMALY"
            or log.get("security", {}).get("incident_action") not in (None, "NONE")
            or log.get("blocked", {}).get("is_blocked") is True
        )
    ]

    status_counts = {
        "active": sum(1 for agent in agents if agent.get("status") == "active"),
        "suspended": sum(1 for agent in agents if agent.get("status") == "suspended"),
        "stopped": sum(1 for agent in agents if agent.get("status") == "stopped"),
    }

    overview = {
        "total_agents": len(agents),
        "total_logs": len(logs),
        "active_alerts": len(alerts),
        "blocked_actions": sum(
            1 for log in logs if log.get("blocked", {}).get("is_blocked") is True
        ),
        "status_counts": status_counts,
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "errors": [error for error in [agents_error, logs_error] if error],
    }
    metrics = calculate_supervision_metrics(logs, agents)

    return {
        "overview": overview,
        "agents": agents,
        "logs": logs,
        "alerts": alerts,
        "metrics": metrics,
        "data_source": {
            "type": "mongo",
            "connected": not overview["errors"],
            "target": _mongo_target(),
            "errors": overview["errors"],
        },
    }


def update_agent_status(agent_id, status, reason=None):
    if not agent_id:
        return {"error": "agent_id is required"}, 400
    if status not in VALID_AGENT_STATUSES:
        return {"error": f"status must be one of {sorted(VALID_AGENT_STATUSES)}"}, 400

    try:
        repo = AgentRepository(
            mongo_timeout_ms=MONGO_TIMEOUT_MS,
            connect_timeout_ms=3000,
            socket_timeout_ms=3000,
        )
        current_state = repo.get_state(agent_id)
        if not current_state:
            return {"error": f"agent '{agent_id}' was not found"}, 404

        repo.update_status(
            agent_id,
            status,
            reason or "Updated from Supervision Center",
        )
        return {
            "ok": True,
            "agent_id": agent_id,
            "status": status,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }, 200
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}, 500


class DashboardHandler(BaseHTTPRequestHandler):
    def _write_json(self, payload, status=200):
        body = json.dumps(payload, default=_json_default).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/api/health":
            self._write_json({"status": "ok", "time": datetime.now(timezone.utc).isoformat()})
            return
        if path == "/api/mongo-status":
            self._write_json(check_mongo_status())
            return

        payload = build_payload()
        if path == "/api/overview":
            self._write_json(payload["overview"])
            return
        if path == "/api/agents":
            self._write_json(payload["agents"])
            return
        if path == "/api/logs":
            self._write_json(payload["logs"])
            return
        if path == "/api/alerts":
            self._write_json(payload["alerts"])
            return
        if path == "/api/metrics":
            self._write_json(payload["metrics"])
            return
        if path == "/api/dashboard":
            self._write_json(payload)
            return

        self._write_json({"error": "Not found"}, status=404)

    def do_POST(self):
        path = urlparse(self.path).path
        content_length = int(self.headers.get("Content-Length", 0))
        try:
            raw_body = self.rfile.read(content_length) if content_length else b"{}"
            body = json.loads(raw_body.decode("utf-8"))
        except Exception:
            self._write_json({"error": "Invalid JSON body"}, status=400)
            return

        if path == "/api/agents/status":
            payload, status_code = update_agent_status(
                body.get("agent_id"),
                body.get("status"),
                body.get("reason"),
            )
            self._write_json(payload, status=status_code)
            return

        self._write_json({"error": "Not found"}, status=404)

    def log_message(self, format, *args):
        # Keep console output concise during demos.
        return


def run():
    server = ThreadingHTTPServer((HOST, PORT), DashboardHandler)
    print(f"[dashboard-api] Listening on http://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    run()

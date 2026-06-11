"""
Safety boundaries for the execution engine.

This module centralizes controls around network access, filesystem paths, and
subprocess commands. The goal is to make agent execution useful but constrained.
"""

import ipaddress
import os
from pathlib import Path
from urllib.parse import urlparse

from core.policy_engine import execution_policy


WORKSPACE_ROOT = Path(__file__).resolve().parents[1]


SHELL_CONTROL_TOKENS = {
    "&",
    "&&",
    "|",
    "||",
    ";",
    ">",
    ">>",
    "<",
    "$(",
    "`",
}


def _policy_section(name):
    return execution_policy().get(name, {})


def _within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _safe_roots(kind):
    fs_policy = _policy_section("filesystem")
    roots = fs_policy.get(f"{kind}_dirs", [])
    return [(WORKSPACE_ROOT / root).resolve() for root in roots]


def resolve_workspace_path(path_value):
    path = Path(str(path_value))
    if not path.is_absolute():
        path = WORKSPACE_ROOT / path
    return path.resolve()


def validate_path(path_value, *, kind):
    resolved = resolve_workspace_path(path_value)
    roots = _safe_roots(kind)
    if any(_within(resolved, root) for root in roots):
        return True, resolved, None

    return (
        False,
        resolved,
        f"PATH_OUTSIDE_SAFE_{kind.upper()}_SCOPE: {resolved}",
    )


def validate_delete_path(path_value):
    allowed, resolved, reason = validate_path(path_value, kind="delete")
    if allowed:
        return True, resolved, None

    fs_policy = _policy_section("filesystem")
    if fs_policy.get("allow_dummy_delete_in_workspace", True):
        if resolved.name.startswith("dummy_") and _within(resolved, WORKSPACE_ROOT):
            return True, resolved, None

    return False, resolved, reason


def safe_output_config_path(target):
    target = target or "output_config/patch.json"
    resolved = resolve_workspace_path(target)
    allowed, _, _ = validate_path(resolved, kind="write")
    if not allowed:
        resolved = (WORKSPACE_ROOT / "output_config" / resolved.name).resolve()

    if resolved.suffix.lower() != ".json":
        resolved = resolved.with_suffix(".json")

    allowed, resolved, reason = validate_path(resolved, kind="write")
    if not allowed:
        return False, resolved, reason
    return True, resolved, None


def sanitize_report_type(report_type):
    clean = "".join(
        char for char in str(report_type or "report").lower()
        if char.isalnum() or char in {"-", "_"}
    ).strip("-_")
    return clean or "report"


def validate_url(url):
    network_policy = _policy_section("network")
    parsed = urlparse(url)
    allowed_schemes = set(network_policy.get("allowed_schemes", ["http", "https"]))

    if parsed.scheme not in allowed_schemes:
        return False, f"URL_SCHEME_NOT_ALLOWED: {parsed.scheme or 'missing'}"

    host = (parsed.hostname or "").lower()
    if not host:
        return False, "URL_HOST_MISSING"

    blocked_hosts = {host.lower() for host in network_policy.get("blocked_hosts", [])}
    if host in blocked_hosts or host.endswith(".localhost"):
        return False, f"URL_HOST_BLOCKED: {host}"

    try:
        ip = ipaddress.ip_address(host)
        if network_policy.get("block_private_ips", True):
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
                return False, f"URL_PRIVATE_IP_BLOCKED: {host}"
    except ValueError:
        # Hostname, not a literal IP. We avoid DNS resolution here so validation
        # stays deterministic and does not create a network side effect.
        pass

    return True, None


def command_policy():
    return _policy_section("commands")


def allowed_commands():
    return [command.lower() for command in command_policy().get("allowed", [])]


def command_timeout_seconds():
    return float(command_policy().get("timeout_seconds", 5))


def has_shell_control_token(command):
    lowered = str(command).lower()
    return any(token in lowered for token in SHELL_CONTROL_TOKENS)


def validate_command(command_parts, raw_command):
    if not command_parts:
        return False, "COMMAND_EMPTY"

    base = command_parts[0].lower()
    if base not in allowed_commands():
        return False, f"COMMAND_NOT_ALLOWED: {base}"

    if has_shell_control_token(raw_command):
        return False, "COMMAND_CONTAINS_SHELL_CONTROL_TOKEN"

    return True, None


def echo_output(command_parts):
    return " ".join(command_parts[1:])


def display_path(path: Path):
    try:
        return os.path.relpath(path, WORKSPACE_ROOT)
    except ValueError:
        return str(path)

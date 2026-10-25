#!/usr/bin/env python3
"""Allowlist-gated, low-impact checks for an authorized website root."""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config.json"
REPORTS_DIR = ROOT / "reports"
TEST_ORIGIN = "https://cors-probe.invalid"
MAX_BODY_BYTES = 64 * 1024
TIMEOUT_SECONDS = 8


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


OPENER = urllib.request.build_opener(
    NoRedirectHandler(),
    urllib.request.HTTPSHandler(context=ssl.create_default_context()),
)


def load_allowed_targets() -> list[str | dict[str, object]]:
    try:
        config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise RuntimeError("config.json is missing; scanning is disabled.") from error
    except json.JSONDecodeError as error:
        raise RuntimeError(f"config.json is invalid JSON: {error}") from error

    if not isinstance(config, dict) or not isinstance(config.get("allowedTargets"), list):
        raise RuntimeError("config.json must contain an allowedTargets array.")

    targets: list[str | dict[str, object]] = []
    for entry in config["allowedTargets"]:
        if isinstance(entry, str):
            hostname = entry.strip().lower().rstrip(".")
            normalized: str | dict[str, object] = hostname
        elif (
            isinstance(entry, dict)
            and set(entry) == {"hostname", "includeSubdomains"}
            and isinstance(entry["hostname"], str)
            and isinstance(entry["includeSubdomains"], bool)
        ):
            hostname = entry["hostname"].strip().lower().rstrip(".")
            normalized = {
                "hostname": hostname,
                "includeSubdomains": entry["includeSubdomains"],
            }
        else:
            raise RuntimeError("Invalid allowedTargets entry in config.json.")

        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            labels = hostname.split(".")
            if not hostname or len(hostname) > 253 or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in labels
            ):
                raise RuntimeError(f"Invalid host in config.json: {hostname!r}")
        targets.append(normalized)
    return targets


def normalize_target(value: str) -> tuple[str, str]:
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter an absolute http:// or https:// target URL.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Credentials, query strings, and fragments are not accepted.")
    if parsed.path not in {"", "/"}:
        raise ValueError("This low-impact check only accepts the site's root path.")
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("Invalid target port.") from error
    if port not in {None, 80 if parsed.scheme == "http" else 443}:
        raise ValueError("Only standard HTTP and HTTPS ports are accepted.")

    hostname = parsed.hostname.lower().rstrip(".")
    allowed = False
    for entry in load_allowed_targets():
        if isinstance(entry, str):
            allowed |= hostname == entry or hostname.endswith("." + entry)
        else:
            root = str(entry["hostname"])
            allowed |= hostname == root or (
                bool(entry["includeSubdomains"]) and hostname.endswith("." + root)
            )
    if not allowed:
        raise ValueError("Target is outside the configured allowlist.")
    return hostname, f"{parsed.scheme}://{hostname}/"


def resolve_public_addresses(hostname: str) -> list[str]:
    try:
        addresses = [ipaddress.ip_address(hostname)]
    except ValueError:
        try:
            records = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        except socket.gaierror as error:
            raise RuntimeError(f"DNS lookup failed: {error}") from error
        addresses = list(
            {
                ipaddress.ip_address(record[4][0].split("%", 1)[0])
                for record in records
            }
        )

    if not addresses:
        raise RuntimeError("Target did not resolve to an IP address.")
    if any(not address.is_global for address in addresses):
        raise RuntimeError("Target resolves to a non-public address; request blocked.")
    return sorted(str(address) for address in addresses)


def make_request(url: str, method: str, headers: dict[str, str]):
    req = urllib.request.Request(url, method=method, headers=headers)
    try:
        response = OPENER.open(req, timeout=TIMEOUT_SECONDS)
    except urllib.error.HTTPError as error:
        response = error
    except (TimeoutError, urllib.error.URLError, OSError) as error:
        raise RuntimeError(f"{method} request failed: {error}") from error

    try:
        body = response.read(MAX_BODY_BYTES) if method == "GET" else b""
        return response.code, dict(response.headers.items()), body
    finally:
        response.close()


def _header(headers: dict[str, str], name: str) -> str:
    return next(
        (value for key, value in headers.items() if key.lower() == name.lower()),
        "",
    )


def _report_folder(hostname: str) -> Path:
    safe_host = re.sub(r"[^a-z0-9.-]+", "-", hostname.lower()).strip(".-")
    return REPORTS_DIR / f"report_{safe_host[:180] or 'target'}"


def run_scan(target: str, emit) -> dict[str, object]:
    started = datetime.now(timezone.utc)
    stages: list[dict[str, str]] = []
    findings: list[dict[str, str]] = []

    def stage(name: str, state: str, detail: str) -> None:
        stages.append({"stage": name, "state": state, "detail": detail})
        emit(state.upper(), f"{name}: {detail}")

    hostname, url = normalize_target(target)
    stage("Scope", "success", f"Exact allowlist check passed for {hostname}")
    addresses = resolve_public_addresses(hostname)
    stage("DNS", "success", ", ".join(addresses))

    common_headers = {"User-Agent": "Authorized-Low-Impact-Check/1.0"}
    status, response_headers, body = make_request(url, "GET", common_headers)
    stage("Homepage", "success", f"HTTP {status}; read at most {len(body)} bytes")
    if status in {403, 429}:
        raise RuntimeError(f"HTTP {status}; stopped without retries.")
    if 300 <= status < 400:
        stage("Redirects", "blocked", "Redirect not followed; target scope preserved.")

    header_names = (
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
    )
    observed_headers = {
        name: _header(response_headers, name) or None for name in header_names
    }
    missing = [name for name, value in observed_headers.items() if value is None]
    if missing:
        findings.append(
            {
                "id": "security-header-observation",
                "severity": "informational",
                "evidence": "Missing on homepage: " + ", ".join(missing),
                "note": "Review in context; absence alone does not prove an exploitable vulnerability.",
            }
        )

    time.sleep(1)
    cors_status, cors_headers, _ = make_request(
        url,
        "OPTIONS",
        {
            **common_headers,
            "Origin": TEST_ORIGIN,
            "Access-Control-Request-Method": "GET",
        },
    )
    stage("CORS preflight", "success", f"HTTP {cors_status}")
    if cors_status in {403, 429}:
        raise RuntimeError(f"HTTP {cors_status}; stopped without retries.")

    allow_origin = _header(cors_headers, "access-control-allow-origin")
    allow_credentials = _header(
        cors_headers, "access-control-allow-credentials"
    ).lower()
    if allow_origin == TEST_ORIGIN and allow_credentials == "true":
        findings.append(
            {
                "id": "cors-reflection-observation",
                "severity": "review",
                "evidence": "Test Origin reflected with credentials on the homepage OPTIONS response.",
                "note": "This does not demonstrate access to private or authenticated data.",
            }
        )

    report: dict[str, object] = {
        "target": url,
        "hostname": hostname,
        "startedAt": started.isoformat(),
        "completedAt": datetime.now(timezone.utc).isoformat(),
        "scope": "Allowlisted host only; homepage GET and OPTIONS; no redirects or exploitation.",
        "resolvedAddresses": addresses,
        "homepage": {"status": status, "securityHeaders": observed_headers},
        "cors": {
            "status": cors_status,
            "testOrigin": TEST_ORIGIN,
            "allowOrigin": allow_origin or None,
            "allowCredentials": allow_credentials or None,
        },
        "stages": stages,
        "findings": findings,
        "limitations": [
            "Only the public homepage is requested.",
            "No subdomain enumeration, path brute-force, credentials, or payloads.",
            "This is not a comprehensive penetration test; manual review is required.",
        ],
    }
    report_dir = _report_folder(hostname)
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "report.json"
    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    stage("Report", "success", str(report_path.relative_to(ROOT)))
    return report


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        raise SystemExit(f"Usage: {Path(sys.argv[0]).name} https://allowlisted-host/")
    run_scan(sys.argv[1], lambda state, message: print(f"[{state}] {message}"))

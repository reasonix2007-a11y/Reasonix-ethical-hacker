#!/usr/bin/env python3
"""Authorization-focused, non-destructive checks for an allowlisted target.

Covers (as observations with real HTTP evidence only):
  * Vertical / horizontal privilege-escalation indicators (IDOR-style)
  * JWT structure (alg, role claims) — passive analysis, no guessing of secrets
  * Session / token handling (cookie flags, WWW-Authenticate, logout semantics)
  * Server-side authorization checks on allowlisted endpoints

All requests are GET / OPTIONS / HEAD with zero mutating payloads.
"""

from __future__ import annotations

import base64
import json
import os
import re
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

from master_scanner import (
    _header,
    _report_folder,
    make_request,
    normalize_target,
    resolve_public_addresses,
)

ROOT = Path(__file__).resolve().parent
REPORTS_DIR = ROOT / "reports"

COMMON_ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/panel", "/dashboard",
    "/api/admin", "/api/users", "/api/user", "/api/me", "/api/v1/users",
    "/api/v1/admin", "/api/v2/users", "/api/accounts", "/api/orders",
    "/api/invoices", "/api/documents", "/account", "/profile", "/settings",
    "/console", "/manager", "/control-panel", "/wp-admin/", "/api/config",
    "/api/debug", "/actuator", "/actuator/env", "/swagger.json", "/graphql",
]

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")


def _decode_jwt_segment(segment: str) -> dict | None:
    try:
        padded = segment + "=" * (-len(segment) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return None


def analyze_jwt(token: str) -> dict:
    parts = token.split(".")
    header = _decode_jwt_segment(parts[0]) or {}
    payload = _decode_jwt_segment(parts[1]) or {}
    signature = parts[2] if len(parts) > 2 else ""
    return {
        "header": header,
        "payload": payload,
        "signaturePresent": bool(signature),
        "algorithm": header.get("alg"),
        "roleClaim": payload.get("role") or payload.get("roles")
        or payload.get("isAdmin") or payload.get("permissions"),
        "hasExpiry": "exp" in payload,
        "notes": [],
    }


def _looks_protected(status: int, body: bytes) -> bool:
    if status in {401, 403}:
        return True
    lowered = body[:4096].lower()
    return any(
        marker in lowered
        for marker in (b"unauthorized", b"forbidden", b"login", b"sign in", b"authentication")
    )


def _add_finding(findings: list, fid: str, severity: str, evidence: str, note: str) -> None:
    findings.append(
        {"id": fid, "severity": severity, "evidence": evidence, "note": note}
    )


def run_privesc_scan(target: str, emit) -> dict:
    started = datetime.now(timezone.utc)
    stages: list[dict[str, str]] = []
    findings: list[dict[str, str]] = []
    evidence_log: list[dict] = []

    def stage(name: str, state: str, detail: str) -> None:
        stages.append({"stage": name, "state": state, "detail": detail})
        emit(state.upper(), f"{name}: {detail}")

    parsed = urllib.parse.urlsplit(target.strip())
    local_training = (
        os.environ.get("REASONIX_LOCAL_TARGET") == "1"
        and parsed.scheme in {"http", "https"}
        and parsed.hostname in {"127.0.0.1", "localhost"}
        and parsed.port in {None, 80, 443, 5099}
        and parsed.path in {"", "/"}
    )
    if local_training:
        hostname = parsed.hostname
        url = f"{parsed.scheme}://{hostname}:5099/" if parsed.port == 5099 else f"{parsed.scheme}://{hostname}/"
        addresses = ["127.0.0.1"]
        stage("Scope", "success", f"LOCAL TRAINING MODE: {hostname} (loopback only)")
    else:
        hostname, url = normalize_target(target)
        stage("Scope", "success", f"Allowlist check passed for {hostname}")
        addresses = resolve_public_addresses(hostname)
    stage("DNS", "success", ", ".join(addresses))

    ua = {"User-Agent": "Authorized-Privesc-Check/1.0"}

    # --- Stage 1: homepage, look for auth tokens / cookies ---
    status, headers, body = make_request(url, "GET", ua)
    stage("Homepage", "success", f"HTTP {status}")
    cookies = _header(headers, "set-cookie")

    # --- Stage 2: JWT discovery (homepage + API endpoints) ---
    jwt_analysis = []
    seen_tokens: set[str] = set()
    jwt_bodies = [body]
    for probe_path in ("/api/me", "/api/user", "/profile", "/account"):
        probe = urllib.parse.urljoin(url, probe_path)
        try:
            _, _, b = make_request(probe, "GET", ua)
            jwt_bodies.append(b)
        except RuntimeError:
            continue
    for b in jwt_bodies:
        for token in JWT_RE.findall(b.decode("utf-8", errors="ignore")):
            if token in seen_tokens or len(jwt_analysis) >= 5:
                continue
            seen_tokens.add(token)
            info = analyze_jwt(token)
            jwt_analysis.append(info)
            alg = info.get("algorithm")
            if alg == "none":
                _add_finding(
                    findings, "jwt-alg-none", "review",
                    "JWT found with alg=none. Claims present but unsigned.",
                    "Signature absence means tampering may be possible; verify server-side validation.",
                )
            elif alg and alg.startswith("HS") and len(token.split(".")[2] or "") < 20:
                _add_finding(
                    findings, "jwt-weak-signature", "review",
                    f"JWT alg={alg} with short signature ({len(token.split('.')[2])} chars).",
                    "May indicate a weak signing key; verify with the client's key material.",
                )
            if not info.get("hasExpiry"):
                _add_finding(
                    findings, "jwt-no-expiry", "review",
                    "JWT has no 'exp' claim; tokens may not expire.",
                    "Long-lived tokens increase risk of replay if leaked.",
                )
    stage("JWT discovery", "success", f"{len(jwt_analysis)} token(s) analyzed")

    # --- Stage 3: cookie security flags ---
    for cookie in cookies.split(","):
        cookie = cookie.strip()
        if not cookie:
            continue
        lowered = cookie.lower()
        missing = [
            flag for flag in ("httponly", "secure", "samesite")
            if flag not in lowered
        ]
        if missing:
            _add_finding(
                findings, "cookie-flags-missing", "review",
                f"Cookie missing: {', '.join(missing)} — {cookie[:80]}…",
                "Missing security flags on session cookies are a common hardening gap.",
            )
        if re.search(r"(session|token|auth|jwt)", cookie.split("=")[0], re.I):
            _add_finding(
                findings, "session-cookie-observed", "informational",
                f"Session/auth cookie observed: {cookie.split('=')[0]}",
                "For structural review only; no value is logged or tested offline.",
            )

    # --- Stage 4: endpoint authorization observations (GET only, no payloads) ---
    endpoint_results = []
    for path in COMMON_ADMIN_PATHS:
        probe = urllib.parse.urljoin(url, path)
        try:
            code, h, b = make_request(probe, "GET", ua)
        except RuntimeError as error:
            endpoint_results.append({"path": path, "error": str(error)})
            continue
        protected = _looks_protected(code, b)
        endpoint_results.append(
            {"path": path, "status": code, "protected": protected,
             "serverAuthCheck": protected}
        )
        evidence_log.append(
            {"request": f"GET {probe}", "statusCode": code,
             "responseHeaders": dict(list(h.items())[:10])}
        )
        if code in {200, 201} and not protected:
            _add_finding(
                findings, "unauth-admin-endpoint", "review",
                f"{path} returned HTTP {code} without any authentication signal.",
                "Server may not enforce authorization on this endpoint; requires manual confirmation.",
            )
        time.sleep(0.3)  # rate-limit friendly
    stage("Endpoint auth checks", "success", f"{len(endpoint_results)} endpoints probed (GET only)")

    # --- Stage 5: CORS on protected paths ---
    for path in ("/api/me", "/api/users"):
        probe = urllib.parse.urljoin(url, path)
        try:
            code, h, _ = make_request(
                probe, "OPTIONS",
                {**ua, "Origin": "https://cors-probe.invalid",
                 "Access-Control-Request-Method": "GET"},
            )
        except RuntimeError:
            continue
        allow_origin = _header(h, "access-control-allow-origin")
        allow_creds = _header(h, "access-control-allow-credentials").lower()
        if allow_origin == "https://cors-probe.invalid" and allow_creds == "true":
            _add_finding(
                findings, "cors-creds-reflection", "review",
                f"{path} OPTIONS reflected test origin with allow-credentials=true.",
                "If true credentials are included, any site could read authenticated responses.",
            )
    stage("CORS on protected paths", "success", "probed")

    # --- Stage 6: build report ---
    report: dict[str, object] = {
        "target": url,
        "hostname": hostname,
        "startedAt": started.isoformat(),
        "completedAt": datetime.now(timezone.utc).isoformat(),
        "scope": "Allowlisted host only; GET/OPTIONS/HEAD requests; no mutating payloads.",
        "resolvedAddresses": addresses,
        "jwtAnalysis": jwt_analysis,
        "endpointAuthorization": endpoint_results,
        "evidenceLog": evidence_log,
        "stages": stages,
        "findings": findings,
        "limitations": [
            "All requests are read-only (GET / OPTIONS); no login, no mutation.",
            "JWT analysis is structural only; keys/secrets are never guessed or brute-forced.",
            "Findings marked 'review' require manual confirmation before reporting to the client.",
            "This does not replace a full manual penetration test.",
        ],
    }
    report_dir = _report_folder(hostname)
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "privesc_report.json"
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
    run_privesc_scan(sys.argv[1], lambda state, msg: print(f"[{state}] {msg}"))

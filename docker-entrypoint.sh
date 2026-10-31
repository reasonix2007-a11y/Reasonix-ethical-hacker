#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Reasonix container entrypoint.
# Starts the optional local scan engines (sqlmap API, OWASP ZAP) in the
# background, then execs the Node server as PID-ish foreground process.
# Both engines bind to loopback only and are never exposed publicly.
# ---------------------------------------------------------------------------
set -euo pipefail

log() { printf '[entrypoint] %s\n' "$1"; }

# --- sqlmap REST API (port 8775) ---
if command -v sqlmapapi >/dev/null 2>&1; then
    log "starting sqlmap API on 127.0.0.1:8775"
    sqlmapapi -s -H 127.0.0.1 -p 8775 >/tmp/sqlmapapi.log 2>&1 &
elif [ -x /opt/pipx/venvs/sqlmap/bin/sqlmapapi ]; then
    log "starting sqlmap API (pipx) on 127.0.0.1:8775"
    /opt/pipx/venvs/sqlmap/bin/sqlmapapi -s -H 127.0.0.1 -p 8775 >/tmp/sqlmapapi.log 2>&1 &
else
    log "sqlmap API not found — skipping"
fi

# --- OWASP ZAP daemon (port 8090) ---
# Kali packages ZAP as `zaproxy`; a source install exposes `zap.sh`. Accept both.
ZAP_CMD=""
if command -v zap.sh >/dev/null 2>&1; then ZAP_CMD="zap.sh";
elif command -v zaproxy >/dev/null 2>&1; then ZAP_CMD="zaproxy";
elif [ -x /usr/share/zaproxy/zap.sh ]; then ZAP_CMD="/usr/share/zaproxy/zap.sh"; fi
if [ -n "$ZAP_CMD" ]; then
    ZAP_KEY="${REASONIX_ZAP_API_KEY:-}"
    if [ -n "$ZAP_KEY" ]; then
        log "starting OWASP ZAP daemon on 127.0.0.1:8090 via $ZAP_CMD (api key set)"
        "$ZAP_CMD" -daemon -host 127.0.0.1 -port 8090 \
            -config api.key="$ZAP_KEY" \
            -config api.addrs.addr.name=127.0.0.1 \
            >/tmp/zap.log 2>&1 &
    else
        log "REASONIX_ZAP_API_KEY not set — ZAP daemon not started"
    fi
else
    log "ZAP not found — skipping"
fi

# --- MobSF (optional; only when explicitly enabled) ---
if [ "${REASONIX_START_MOBSF:-}" = "true" ] && command -v mobsf >/dev/null 2>&1; then
    log "starting MobSF on 127.0.0.1:8000"
    mobsf 127.0.0.1:8000 >/tmp/mobsf.log 2>&1 &
fi

log "launching application: $*"
exec "$@"

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
if command -v zap.sh >/dev/null 2>&1; then
    ZAP_KEY="${REASONIX_ZAP_API_KEY:-}"
    if [ -n "$ZAP_KEY" ]; then
        log "starting OWASP ZAP daemon on 127.0.0.1:8090 (api key set)"
        zap.sh -daemon -host 127.0.0.1 -port 8090 \
            -config api.key="$ZAP_KEY" \
            -config api.addrs.addr.name=127.0.0.1 \
            >/tmp/zap.log 2>&1 &
    else
        log "REASONIX_ZAP_API_KEY not set — ZAP daemon not started"
    fi
else
    log "zap.sh not found — skipping"
fi

log "launching application: $*"
exec "$@"

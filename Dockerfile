# syntax=docker/dockerfile:1

# ============================================================================
# Reasonix — production container (Linux) with the full authorized-testing
# toolchain baked in. Build runs on Railway's cloud builder.
#
# Stages:
#   1) gobuild   — compiles the Go-based scanners (ProjectDiscovery et al.)
#   2) runtime   — node 24 + apt/pip/gem tools + ZAP, runs the server
# ============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Go tools
# ---------------------------------------------------------------------------
FROM golang:1.23-bookworm AS gobuild

# libpcap is needed for naabu (CGO).
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

ENV GOBIN=/out GOFLAGS=-trimpath CGO_ENABLED=1
RUN mkdir -p /out

# Each install is its own layer so a single failure is easy to pinpoint and
# the Docker cache survives edits to the rest.
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
RUN go install github.com/OJ/gobuster/v3@latest
RUN go install github.com/ffuf/ffuf/v2@latest
RUN go install github.com/owasp-amass/amass/v4/...@master
RUN go install github.com/tomnomnom/assetfinder@latest

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
FROM node:24-bookworm AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    NODE_ENV=production \
    PIPX_HOME=/opt/pipx \
    PIPX_BIN_DIR=/usr/local/bin \
    PATH=/usr/local/go-tools:/opt/tools/testssl.sh:$PATH

# ---- OS packages + apt-provided scanners ----
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl wget git unzip bsdmainutils \
        python3 python3-venv python3-pip pipx \
        ruby ruby-dev build-essential \
        default-jre-headless \
        nmap nikto whatweb sslscan wafw00f wfuzz dnsutils \
        libpcap0.8 procps \
    && rm -rf /var/lib/apt/lists/*

# ---- Go tool binaries from stage 1 ----
COPY --from=gobuild /out/ /usr/local/go-tools/

# ---- Python tools (isolated via pipx) ----
RUN pipx install sqlmap \
    && pipx install wapiti3 \
    && pipx install theHarvester \
    && pipx install sublist3r \
    || true

# ---- Ruby tool: wpscan ----
RUN gem install wpscan --no-document || true

# ---- testssl.sh (git) ----
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/tools/testssl.sh \
    && ln -sf /opt/tools/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# ---- retire.js (node, global) ----
RUN npm install -g retire || true

# ---- OWASP ZAP (daemon used by the zap-api integration) ----
ARG ZAP_VERSION=2.15.0
RUN wget -q "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" -O /tmp/zap.tgz \
    && tar -xzf /tmp/zap.tgz -C /opt \
    && mv "/opt/ZAP_${ZAP_VERSION}" /opt/zap \
    && ln -sf /opt/zap/zap.sh /usr/local/bin/zap.sh \
    && rm -f /tmp/zap.tgz

# ---- application ----
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY . .

# nikto's integration passes an explicit config path under tools/nikto/program/.
# Provide one that points at the system nikto install so the scan can run.
RUN mkdir -p /app/tools/nikto/program \
    && (cp /etc/nikto.conf /app/tools/nikto/program/nikto.conf.default 2>/dev/null \
        || cp /var/lib/nikto/nikto.conf /app/tools/nikto/program/nikto.conf.default 2>/dev/null \
        || touch /app/tools/nikto/program/nikto.conf.default)

# Persisted encrypted user data lives here. On Railway, attach a Railway Volume
# with mount path /app/data (the Dockerfile VOLUME instruction is unsupported by
# Railway's builder, so it is intentionally omitted).
RUN mkdir -p /app/data

# Local engine endpoints started by the entrypoint (never exposed publicly).
ENV REASONIX_SQLMAP_API_URL=http://127.0.0.1:8775 \
    REASONIX_ZAP_API_URL=http://127.0.0.1:8090 \
    PORT=5500

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 5500
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["node", "serve.mjs"]

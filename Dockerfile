# syntax=docker/dockerfile:1

# ============================================================================
# Reasonix — production container for authorized security testing.
#
# Built on Kali Linux rolling so the full Kali CLI toolchain is available from
# the official Kali repositories, with Node.js installed on top to run the
# Reasonix server. Freshly-built Go scanners (ProjectDiscovery, tomnomnom, …)
# are compiled in a separate stage and copied in so they stay current.
#
# Railway is a Linux container platform: GUI tools (Burp, Maltego, Vega, IDA),
# Windows-only tools (x64dbg), wireless tools needing a physical adapter, and
# commercial/licensed services (Nessus, Qualys, Burp Pro) cannot run here and
# are intentionally not installed. Everything installable as a Linux CLI is.
#
# Every tool install is best-effort: a single unavailable package logs a
# ">>> ... FAILED" marker and does not abort the build, so missing tools simply
# remain visible as missing at runtime instead of breaking the whole image.
# ============================================================================

# ---------------------------------------------------------------------------
# Stage 1: fresh Go-based scanners
# ---------------------------------------------------------------------------
FROM golang:1.26-bookworm AS gobuild

# libpcap is needed for naabu (CGO).
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

ENV GOBIN=/out GOFLAGS=-trimpath CGO_ENABLED=1 GOTOOLCHAIN=auto
RUN mkdir -p /out

# Core ProjectDiscovery / recon scanners (kept fresh here rather than via apt).
RUN set -eux; for mod in \
      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" \
      "github.com/projectdiscovery/httpx/cmd/httpx@latest" \
      "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" \
      "github.com/projectdiscovery/katana/cmd/katana@latest" \
      "github.com/projectdiscovery/dnsx/cmd/dnsx@latest" \
      "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" \
      "github.com/projectdiscovery/tlsx/cmd/tlsx@latest" \
      "github.com/projectdiscovery/chaos-client/cmd/chaos@latest" \
      "github.com/OJ/gobuster/v3@latest" \
      "github.com/ffuf/ffuf/v2@latest" \
      "github.com/owasp-amass/amass/v4/...@master" \
      "github.com/tomnomnom/assetfinder@latest" \
    ; do echo ">>> go install: $mod"; go install "$mod" || echo ">>> go install FAILED: $mod"; done

# Extra Go utilities (XSS/CRLF/fuzzing/recon/SBOM/k8s) — all best-effort.
RUN set -eux; for mod in \
      "github.com/hahwul/dalfox/v2@latest" \
      "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest" \
      "github.com/lc/gau/v2/cmd/gau@latest" \
      "github.com/tomnomnom/waybackurls@latest" \
      "github.com/tomnomnom/qsreplace@latest" \
      "github.com/tomnomnom/gf@latest" \
      "github.com/tomnomnom/meg@latest" \
      "github.com/tomnomnom/unfurl@latest" \
      "github.com/Josue87/gotator@latest" \
      "github.com/d3mondev/puredns/v2@latest" \
      "github.com/PentestPad/subzy@latest" \
      "github.com/jaeles-project/jaeles@latest" \
      "github.com/google/osv-scanner/cmd/osv-scanner@latest" \
      "github.com/goodwithtech/dockle/cmd/dockle@latest" \
      "github.com/aquasecurity/kube-bench@latest" \
      "github.com/Shopify/kubeaudit@latest" \
      "github.com/controlplaneio/kubesec/v2@latest" \
      "github.com/derailed/popeye@latest" \
    ; do echo ">>> go install: $mod"; go install "$mod" || echo ">>> go install FAILED: $mod"; done

# ---------------------------------------------------------------------------
# Stage 2: runtime (Kali Linux + Node.js + tools)
# ---------------------------------------------------------------------------
FROM kalilinux/kali-rolling AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    NODE_ENV=production \
    PIPX_HOME=/opt/pipx \
    PIPX_BIN_DIR=/usr/local/bin \
    LANG=C.UTF-8 \
    PATH=/usr/local/go-tools:/usr/local/bin:/opt/tools/bin:$PATH

# ---- base OS / build dependencies ----
RUN apt-get update && apt-get install -y --no-install-recommends \
        kali-archive-keyring ca-certificates curl wget git unzip xz-utils \
        gnupg lsb-release bsdmainutils procps \
        python3 python3-venv python3-pip pipx python3-dev \
        libcurl4-openssl-dev libssl-dev build-essential \
        ruby ruby-dev \
        default-jre-headless \
        dnsutils libpcap0.8 perl \
    && rm -rf /var/lib/apt/lists/*

# ---- Node.js 24 (NodeSource) ----
RUN curl -fsSL https://deb.nodesource.com/setup_24.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/* \
    && node --version && npm --version

# ---- Kali tool metapackages ----
# Each category is its own layer so Railway's layer cache resumes a failed
# build, and so one slow/broken category cannot stall the others. Wireless and
# hardware-bound metapackages are omitted: they cannot function on Railway.
RUN apt-get update \
    && apt-get install -y --no-install-recommends kali-tools-information-gathering \
       || echo ">>> kali-tools-information-gathering FAILED" ; rm -rf /var/lib/apt/lists/*
RUN apt-get update \
    && apt-get install -y --no-install-recommends kali-tools-web \
       || echo ">>> kali-tools-web FAILED" ; rm -rf /var/lib/apt/lists/*
RUN apt-get update \
    && apt-get install -y --no-install-recommends kali-tools-vulnerability \
       || echo ">>> kali-tools-vulnerability FAILED" ; rm -rf /var/lib/apt/lists/*
RUN apt-get update \
    && apt-get install -y --no-install-recommends kali-tools-database \
       || echo ">>> kali-tools-database FAILED" ; rm -rf /var/lib/apt/lists/*
RUN apt-get update \
    && apt-get install -y --no-install-recommends kali-tools-passwords \
       || echo ">>> kali-tools-passwords FAILED" ; rm -rf /var/lib/apt/lists/*
RUN apt-get update \
    && apt-get install -y --no-install-recommends kali-tools-reverse-engineering \
       || echo ">>> kali-tools-reverse-engineering FAILED" ; rm -rf /var/lib/apt/lists/*
RUN apt-get update \
    && apt-get install -y --no-install-recommends kali-tools-exploitation \
       || echo ">>> kali-tools-exploitation FAILED" ; rm -rf /var/lib/apt/lists/*
RUN apt-get update \
    && apt-get install -y --no-install-recommends kali-tools-forensics \
       || echo ">>> kali-tools-forensics FAILED" ; rm -rf /var/lib/apt/lists/*
RUN apt-get update \
    && apt-get install -y --no-install-recommends kali-tools-sniffing-spoofing \
       || echo ">>> kali-tools-sniffing-spoofing FAILED" ; rm -rf /var/lib/apt/lists/*

# ---- explicit key packages (ensure present even if a metapackage changed) ----
RUN apt-get update \
    && for pkg in nmap masscan nikto whatweb sqlmap sslscan testssl.sh \
                  wfuzz wafw00f gobuster ffuf dirb dirbuster commix skipfish \
                  wpscan joomscan whatweb amass sublist3r dnsrecon dnsenum fierce \
                  theharvester recon-ng spiderfoot dnsmap \
                  hydra medusa ncrack patator john hashcat crunch \
                  radare2 binwalk foremost exiftool clamav lynis \
                  tcpdump tshark ngrep \
                  metasploit-framework exploitdb seclists \
                  zaproxy ; do \
         echo ">>> apt install: $pkg"; \
         apt-get install -y --no-install-recommends "$pkg" || echo ">>> apt install FAILED: $pkg"; \
       done ; rm -rf /var/lib/apt/lists/*

# ---- Go tool binaries from stage 1 ----
COPY --from=gobuild /out/ /usr/local/go-tools/

# ---- Python CLI tools via pipx (isolated venvs, each best-effort) ----
# Only tools Kali lacks or that are better kept fresh from PyPI; Kali already
# provides sqlmap, wapiti, theHarvester, wafw00f, wfuzz, sublist3r, recon-ng,
# spiderfoot, dnsrecon and fierce via apt above.
RUN for pkg in semgrep checkov sslyze arjun dirsearch holehe h8mail \
               detect-secrets bandit kube-hunter knockpy py-altdns \
               scoutsuite prowler njsscan droopescan dnstwist wapiti3 ; do \
      echo ">>> pipx install: $pkg"; pipx install "$pkg" || echo ">>> pipx install FAILED: $pkg"; \
    done

# ---- git-only Python tools (venv + PATH symlink named as the catalog bin) ----
RUN set -ux; \
    install_git_tool() { \
      name="$1"; repo="$2"; entry="$3"; \
      echo ">>> git tool: $name"; \
      if git clone --depth 1 "$repo" "/opt/tools/$name"; then \
        python3 -m venv "/opt/tools/$name/.venv"; \
        "/opt/tools/$name/.venv/bin/pip" install --no-cache-dir -r "/opt/tools/$name/requirements.txt" 2>/dev/null || true; \
        printf '#!/bin/sh\nexec "/opt/tools/%s/.venv/bin/python" "/opt/tools/%s/%s" "$@"\n' "$name" "$name" "$entry" > "/usr/local/bin/$name"; \
        chmod +x "/usr/local/bin/$name"; \
      else echo ">>> git tool FAILED: $name"; fi; \
    }; \
    install_git_tool xsstrike https://github.com/s0md3v/XSStrike.git xsstrike.py; \
    install_git_tool ssrfmap  https://github.com/swisskyrepo/SSRFmap.git ssrfmap.py; \
    install_git_tool tplmap   https://github.com/epinna/tplmap.git tplmap.py; \
    install_git_tool cmseek   https://github.com/Tuhinshubhra/CMSeeK.git cmseek.py

# ---- binary-release security scanners (official install scripts) ----
RUN echo ">>> trivy"   && curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin || echo ">>> trivy FAILED"
RUN echo ">>> grype"   && curl -fsSL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin || echo ">>> grype FAILED"
RUN echo ">>> syft"    && curl -fsSL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin || echo ">>> syft FAILED"
RUN echo ">>> gitleaks" && curl -fsSL https://raw.githubusercontent.com/gitleaks/gitleaks/master/install.sh | sh 2>/dev/null \
    || ( GL=$(curl -fsSL https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep -o 'https://[^"]*linux_x64.tar.gz' | head -1) \
         && curl -fsSL "$GL" -o /tmp/gl.tgz && tar -xzf /tmp/gl.tgz -C /usr/local/bin gitleaks && rm -f /tmp/gl.tgz ) \
    || echo ">>> gitleaks FAILED"
RUN echo ">>> trufflehog" && curl -fsSL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin || echo ">>> trufflehog FAILED"
RUN echo ">>> hadolint" && curl -fsSL -o /usr/local/bin/hadolint \
      https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64 \
    && chmod +x /usr/local/bin/hadolint || echo ">>> hadolint FAILED"
RUN echo ">>> findomain" && curl -fsSL -o /tmp/findomain.zip \
      https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip \
    && unzip -o /tmp/findomain.zip -d /usr/local/bin && chmod +x /usr/local/bin/findomain && rm -f /tmp/findomain.zip \
    || echo ">>> findomain FAILED"

# ---- Node / Ruby extra tools ----
RUN npm install -g retire snyk wscat || echo ">>> npm global tools FAILED"
RUN gem install brakeman --no-document || echo ">>> brakeman FAILED"

# ---- MobSF (optional, heavy; installed but not auto-started) ----
# Enable by starting it and setting MOBSF_API_KEY + MOBSF URL env vars.
RUN pipx install mobsf || echo ">>> MobSF install FAILED (optional)"

# ---- application ----
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY . .

# nikto's integration passes an explicit config path under tools/nikto/program/.
RUN mkdir -p /app/tools/nikto/program \
    && (cp /etc/nikto.conf /app/tools/nikto/program/nikto.conf.default 2>/dev/null \
        || cp /etc/nikto/nikto.conf /app/tools/nikto/program/nikto.conf.default 2>/dev/null \
        || touch /app/tools/nikto/program/nikto.conf.default)

# Persisted encrypted user data. On Railway attach a Volume at /app/data.
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

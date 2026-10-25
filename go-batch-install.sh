#!/bin/bash
export GOPATH=/root/go
export PATH=$PATH:/usr/local/go/bin:/root/go/bin
MODULES=(
  github.com/ffuf/feroxbuster/v2
  github.com/projectdiscovery/katana/cmd/katana
  github.com/lc/gau/v2/cmd/gau
  github.com/tomnomnom/waybackurls
  github.com/tomnomnom/gf
  github.com/tomnomnom/qsreplace
  github.com/tomnomnom/meg
  github.com/projectdiscovery/dalfox/v2
  github.com/projectdiscovery/dnsx/cmd/dnsx
  github.com/projectdiscovery/subfinder/v2/cmd/subfinder
  github.com/projectdiscovery/nuclei/v2/cmd/nuclei
  github.com/projectdiscovery/httpx/cmd/httpx
  github.com/projectdiscovery/tlsx/cmd/tlsx
  github.com/projectdiscovery/chaos-client/cmd/chaos
  github.com/owasp-amass/amass/v4/cmd/amass
  github.com/hahwul/nabu
  github.com/projectdiscovery/crlfuzz/cmd/crlfuzz
  github.com/s0md3v/Arrow/public/recon/findomain
)
for m in "${MODULES[@]}"; do
  echo "== $m"
  go install -v "$m@latest" >/dev/null 2>&1 && echo "[OK] $m" || echo "[FAILED] $m"
done
echo GO-DONE
ls /root/go/bin

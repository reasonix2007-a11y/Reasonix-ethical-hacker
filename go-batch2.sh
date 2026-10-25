#!/bin/bash
export GOPATH=/root/go
export PATH=$PATH:/usr/local/go/bin:/root/go/bin
MODULES=(
  github.com/lc/gau/v2/cmd/gau
  github.com/tomnomnom/waybackurls
  github.com/tomnomnom/gf
  github.com/tomnomnom/qsreplace
  github.com/tomnomnom/meg
  github.com/projectdiscovery/katana/cmd/katana
  github.com/hahwul/dalfox/v2
  github.com/hahwul/nabu
  github.com/projectdiscovery/crlfuzz/cmd/crlfuzz
)
for m in "${MODULES[@]}"; do
  name=$(basename $m)
  echo "== $m"
  go install -v "$m@latest" >/dev/null 2>&1 && echo "[OK] $name" || echo "[FAILED] $name"
done
echo GO2-DONE
ls /root/go/bin

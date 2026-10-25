#!/bin/bash
# Final full-install batch
export GOPATH=/root/go
export PATH=$PATH:/usr/local/go/bin:/root/go/bin
L="/mnt/c/Users/hamza rajeh/CodeGPT/reasonix-ethical-hacker"
{
echo "=== 1. Remaining Go tools ==="
for m in github.com/hahwul/dalfox/v2 github.com/hahwul/nabu github.com/projectdiscovery/crlfuzz/cmd/crlfuzz; do
  n=$(basename $m)
  go install -v "$m@latest" >/dev/null 2>&1 && echo "[OK] $n" || echo "[FAILED] $n"
done
echo "=== 2. Go retry katana ==="
go install -v github.com/projectdiscovery/katana/cmd/katana@latest >/dev/null 2>&1 && echo "[OK] katana" || echo "[FAILED] katana"
echo "=== 3. pip tools ==="
pip3 install --break-system-packages -q h8mail mitmproxy websocat 2>&1 | tail -2 || pip3 install -q h8mail mitmproxy 2>&1 | tail -2
echo "[pip done]"
echo "=== 4. apt tools ==="
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq knockpy mitmproxy websocat wscat ncat 2>&1 | tail -3
echo "=== 5. git-clone tools ==="
mkdir -p /opt/extratools
[ -d /opt/extratools/tplmap ] || git clone -q https://github.com/carlospolop/Tplmap /opt/extratools/tplmap 2>&1
[ -d /opt/extratools/SSRFmap ] || git clone -q https://github.com/swisskyrepo/SSRFmap /opt/extratools/SSRFmap 2>&1
[ -d /opt/extratools/cmseek ] || git clone -q https://github.com/Tuhinshubhra/CMSeeK /opt/extratools/cmseek 2>&1
[ -d /opt/extratools/arachni ] || git clone -q https://github.com/Arachni/arachni /opt/extratools/arachni 2>&1
ln -sf /opt/extratools/tplmap/tplmap /usr/local/bin/tplmap 2>/dev/null
ln -sf /opt/extratools/SSRFmap/ssrfmap.py /usr/local/bin/ssrfmap 2>/dev/null
ln -sf /opt/extratools/cmseek/cmseek.py /usr/local/bin/cmseek 2>/dev/null
echo "=== 6. wafw00f, identywaf etc via pip ==="
pip3 install --break-system-packages -q wafw00f dnstwist arjun dirsearch subzy 2>&1 | tail -2 || pip3 install -q wafw00f dnstwist arjun dirsearch subzy 2>&1 | tail -2
echo "ALL-DONE"
} > "/mnt/c/Users/hamza rajeh/CodeGPT/reasonix-ethical-hacker/final-install.log" 2>&1

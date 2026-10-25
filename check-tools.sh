#!/usr/bin/env bash
echo "=== TOOL STATUS ==="
for t in nmap nikto whatweb gobuster testssl.sh sslscan wafw00f sublist3r theHarvester subfinder httpx nuclei; do
  if command -v "$t" >/dev/null 2>&1; then
    printf "%-15s OK   ->  %s\n" "$t" "$(command -v $t)"
  else
    printf "%-15s MISSING\n" "$t"
  fi
done
echo
echo "=== VERSIONS ==="
nmap --version 2>&1 | head -1
nikto -Version 2>&1 | grep -m1 "Nikto" || true
whatweb --version 2>&1 | head -1 || true
gobuster --version 2>&1 | head -1 || true
testssl.sh --version 2>&1 | head -1 || true
sslscan --version 2>&1 | head -1 || true
subfinder -version 2>&1 | head -1 || true
httpx -version 2>&1 | head -1 || true
nuclei -version 2>&1 | head -1 || true
theHarvester 2>&1 | grep -m1 "theHarvester" || true
echo
echo "=== WHATWEB PATH CHECK ==="
dpkg -L whatweb 2>/dev/null | head -8

echo "=== WAIT FOR NUCLEI BUILD ==="
for i in $(seq 1 30); do
  grep -q ALL_DONE /root/go-install.log 2>/dev/null && break
  sleep 10
done
echo "=== BUILD RESULT ==="
grep -E "OK|ALL_DONE" /root/go-install.log | tail -6
echo
echo "=== BINARIES ==="
ls -la /usr/local/bin/ | grep -E "subfinder|httpx|nuclei" || echo "none yet"
echo
echo "=== FINAL ALL-TOOLS CHECK ==="
for t in nmap nikto whatweb gobuster testssl.sh sslscan wafw00f sublist3r theHarvester subfinder httpx nuclei; do
  if command -v "$t" >/dev/null 2>&1; then
    printf "%-15s OK -> %s\n" "$t" "$(command -v $t)"
  else
    printf "%-15s MISSING\n" "$t"
  fi
done

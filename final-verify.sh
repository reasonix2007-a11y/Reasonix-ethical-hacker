#!/usr/bin/env bash
# Reasonix final tool verification — all 12 tools.
# Mirrors how scan-server.mjs resolves tools: local tools/ tree, PERL:/RUBY:/BASH:/PY: wrappers.
TOOLS="$(cd "$(dirname "$0")" && pwd)/tools"
GIT_BASH="/c/Program Files/Git/bin/bash.exe"
GIT_PERL="/c/Program Files/Git/usr/bin/perl.exe"
RUBY="$TOOLS/ruby/bin/ruby.exe"
PYTHON="$TOOLS/python/python.exe"

echo '=========================================='
echo '   FINAL TOOL VERIFICATION (all 12)'
echo '=========================================='
PASS=0; FAIL=0
ok()   { printf '[OK]   %-15s %s\n' "$1" "${2:0:80}"; PASS=$((PASS+1)); }
bad()  { printf '[FAIL] %-15s %s\n' "$1" "${2:0:80}"; FAIL=$((FAIL+1)); }
first() { "$@" 2>&1 | head -1; }

# 1) nmap
if [ -x "$TOOLS/nmap/nmap.exe" ]; then
  ok nmap "$(first "$TOOLS/nmap/nmap.exe" --version)"
else bad nmap "nmap.exe missing in tools/nmap"; fi

# 2) nikto (Perl)
if [ -x "$GIT_PERL" ] && [ -f "$TOOLS/nikto/program/nikto.pl" ]; then
  ok nikto "$(first "$GIT_PERL" "$TOOLS/nikto/program/nikto.pl" -config "$TOOLS/nikto/program/nikto.conf.default" -Version)"
else bad nikto "nikto.pl + Git Perl missing"; fi

# 3) whatweb (Ruby)
if [ -x "$RUBY" ] && [ -f "$TOOLS/whatweb/whatweb" ]; then
  ok whatweb "$(first "$RUBY" "$TOOLS/whatweb/whatweb" --version)"
else bad whatweb "whatweb + bundled Ruby missing"; fi

# 4) gobuster
if [ -x "$TOOLS/gobuster/gobuster.exe" ]; then
  ok gobuster "$(first "$TOOLS/gobuster/gobuster.exe" version)"
else bad gobuster "gobuster.exe missing in tools/gobuster"; fi

# 5) testssl.sh (Git Bash)
if [ -x "$GIT_BASH" ] && [ -f "$TOOLS/testssl.sh/testssl.sh" ]; then
  ok testssl.sh "$(first "$GIT_BASH" "$TOOLS/testssl.sh/testssl.sh" --version)"
else bad testssl.sh "testssl.sh + Git Bash missing"; fi

# 6) sslscan
SSLSCAN=$(find "$TOOLS/sslscan" -name 'sslscan*.exe' 2>/dev/null | head -1)
if [ -n "$SSLSCAN" ]; then
  ok sslscan "$(first "$SSLSCAN" --version)"
else bad sslscan "sslscan.exe missing in tools/sslscan"; fi

# 7) wafw00f (bundled Python launcher)
WAF="$TOOLS/python/Scripts/wafw00f.exe"
if [ -x "$WAF" ]; then
  ok wafw00f "$(first "$WAF" --version)"
else bad wafw00f "wafw00f.exe missing in tools/python/Scripts"; fi

# 8) sublist3r
SL="$TOOLS/mobile-venv/Scripts/sublist3r.exe"
SLPY="$TOOLS/mobile-venv/Lib/site-packages/sublist3r.py"
if [ -x "$SL" ]; then
  ok sublist3r "$(first "$SL" --version)"
elif [ -f "$SLPY" ] || ls "$TOOLS/mobile-venv/Lib/site-packages"/sublist3r* >/dev/null 2>&1; then
  ok sublist3r "sublist3r module present in tools/mobile-venv"
else bad sublist3r "not found in tools/mobile-venv"; fi

# 9) theHarvester
TH="$TOOLS/security-tools/theharvester/bin/theHarvester.exe"
THROOT="$TOOLS/security-tools/theharvester"
if [ -x "$TH" ] && [ -x "$PYTHON" ]; then
  out=$(cd "$THROOT" && PYTHONPATH=. "$PYTHON" bin/theHarvester.exe --help 2>&1 | head -1)
  if [ -n "$out" ]; then ok theHarvester "$out"; else bad theHarvester "theHarvester.exe exits empty"; fi
else bad theHarvester "theHarvester.exe missing in tools/security-tools"; fi

# 10) subfinder
if [ -x "$TOOLS/subfinder/subfinder.exe" ]; then
  ok subfinder "$(first "$TOOLS/subfinder/subfinder.exe" -version)"
else bad subfinder "subfinder.exe missing in tools/subfinder"; fi

# 11) httpx
if [ -x "$TOOLS/httpx/httpx.exe" ]; then
  ok httpx "$(first "$TOOLS/httpx/httpx.exe" -version)"
else bad httpx "httpx.exe missing in tools/httpx"; fi

# 12) nuclei
if [ -x "$TOOLS/nuclei/nuclei.exe" ]; then
  ok nuclei "$(first "$TOOLS/nuclei/nuclei.exe" -version)"
else bad nuclei "nuclei.exe missing in tools/nuclei"; fi

echo '=========================================='
echo "RESULT: $PASS PASS / $FAIL FAIL"
echo '=========================================='
exit 0

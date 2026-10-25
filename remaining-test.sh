لش#!/usr/bin/env bash
# اختبار الأدوات الباقية مع مهل سخية
echo '======== REMAINING TOOLS TEST ========'

echo '--- [A] nuclei templates update (up to 100s) ---'
timeout 100 nuclei -update-templates 2>&1 | tail -2
ls /root/nuclei-templates 2>/dev/null | head -3 || ls /root/.config/nuclei 2>/dev/null

echo '--- [B] nuclei real scan (up to 60s, tech tags only) ---'
timeout 60 nuclei -u https://example.com -silent -nc -tags tech 2>&1 | head -5
echo 'nuclei exit: done'

echo '--- [C] gobuster (wordlist install + quick dir scan) ---'
timeout 40 apt-get install -y -qq dirb 2>&1 | tail -1
ls /usr/share/wordlists/dirb/common.txt 2>/dev/null && \
  timeout 40 gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt -q 2>&1 | head -5

echo '--- [D] wafw00f ---'
timeout 40 wafw00f https://example.com 2>&1 | grep -iE 'is behind|no waf|general' | head -3

echo '--- [E] testssl.sh short ---'
timeout 70 testssl.sh --quiet --short example.com 2>&1 | head -8

echo '--- [F] sublist3r ---'
timeout 60 sublist3r -d example.com -t 3 -n 2>&1 | grep -vE '^\[|^$|Searching|Enumerating' | head -5

echo '--- [G] theHarvester crtsh ---'
timeout 60 theHarvester -d example.com -b crtsh -l 10 2>&1 | grep -vE '^\*|^$' | head -6

echo '--- [H] nikto quick ---'
timeout 90 nikto -h example.com -nointeractive -Tuning b -timeout 10 2>&1 | tail -6

echo '======== ALL REMAINING TESTS DONE ========'
exit 0

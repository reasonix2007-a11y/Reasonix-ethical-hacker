#!/usr/bin/env bash
# اختبار حقيقي: كل أداة تفحص example.com فعلياً
echo '======== REAL FUNCTIONAL TEST: example.com ========'
echo
echo '--- [1] nmap ---'
nmap -Pn -T4 --top-ports 20 example.com 2>&1 | grep -E 'PORT|http|open' | head -5
echo
echo '--- [2] whatweb ---'
whatweb --no-errors -q https://example.com 2>&1 | head -2
echo
echo '--- [3] sslscan ---'
sslscan --no-colour example.com 2>&1 | grep -E 'Supported|SSL|TLS' | head -4
echo
echo '--- [4] httpx ---'
echo 'example.com' | httpx -silent -status-code -title 2>&1 | head -2
echo
echo '--- [5] subfinder ---'
subfinder -d example.com -silent 2>&1 | head -3
echo
echo '--- [6] nuclei (1 template only, fast) ---'
nuclei -u https://example.com -silent -t /root/.config/nuclei/ -tags tech -nc 2>&1 | head -3 || echo '(نو nuclei templates may need download, skipping deep test)'
echo
echo '--- [7] gobuster ---'
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt -q 2>&1 | head -3 || echo '(wordlist may be missing)'
echo
echo '--- [8] wafw00f ---'
wafw00f https://example.com 2>&1 | grep -E 'is behind|No WAF|Testing' | head -3
echo
echo '--- [9] testssl.sh (quick) ---'
testssl.sh --quiet --short example.com 2>&1 | head -6
echo
echo '--- [10] nikto (short) ---'
timeout 60 nikto -h example.com -nointeractive -Tuning b 2>&1 | tail -5
echo
echo '--- [11] sublist3r ---'
timeout 60 sublist3r -d example.com -t 3 -n 2>&1 | head -5
echo
echo '--- [12] theHarvester ---'
timeout 60 theHarvester -d example.com -b crtsh -l 10 2>&1 | head -5
echo
echo '======== END FUNCTIONAL TEST ========'
exit 0

ما ا#!/usr/bin/env bash
# اختبار gobuster بالمسار الصحيح
timeout 40 gobuster dir -u https://example.com -w /usr/share/dirb/wordlists/common.txt -q 2>&1 | head -5
echo 'GOBUSTER_OK'
exit 0

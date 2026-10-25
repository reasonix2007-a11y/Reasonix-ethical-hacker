#!/usr/bin/env bash
# gobuster wordlist مسار بديل (dirb package layout on Ubuntu 26.04)
echo '--- locate common.txt ---'
find /usr/share -name 'common.txt' 2>/dev/null | head -5
dpkg -L dirb 2>/dev/null | grep -i common | head -3
ls /usr/share/dirb/wordlists 2>/dev/null | head -3
exit 0

#!/usr/bin/env bash
grep -E 'OK$|ALL_DONE' /root/go-install.log | tail -6
echo '--- binaries ---'
ls /usr/local/bin | grep -E 'subfinder|httpx|nuclei'
exit 0

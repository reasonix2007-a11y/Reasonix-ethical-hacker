#!/usr/bin/env bash
# انتظار اكتمال بناء nuclei (حتى 20 دقيقة)
for i in $(seq 1 120); do
  if grep -q 'NUCLEI_BUILD_EXIT_CODE_' /root/nuclei.log 2>/dev/null; then
    break
  fi
  sleep 10
done
echo '=== nuclei build log tail ==='
tail -5 /root/nuclei.log 2>/dev/null
echo
echo '=== binary check ==='
ls -la /usr/local/bin/nuclei 2>/dev/null && /usr/local/bin/nuclei -version 2>&1 | head -2 || echo 'nuclei still missing'
exit 0

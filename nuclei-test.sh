شكل المطلوب#!/usr/bin/env bash
# nuclei templates تحديث في الخلفية ثم اختبار سريع
echo '--- updating nuclei templates (background-safe) ---'
timeout 50 nuclei -update-templates -silent 2>&1 | head -3
echo 'template update done (or skipped)'
echo
echo '--- nuclei quick test ---'
timeout 30 nuclei -u https://example.com -silent -nc -tl 5 2>&1 | head -3
echo 'nuclei test done'
exit 0

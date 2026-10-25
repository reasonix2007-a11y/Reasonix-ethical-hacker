#!/usr/bin/env bash
# whatweb يبحث عن lib/messages.rb عبر require_relative من /usr/bin
# الحل: أنشئ /usr/bin/lib symlink يشير لمجلد vendor_ruby
if [ -d /usr/lib/ruby/vendor_ruby ]; then
  ln -sfn /usr/lib/ruby/vendor_ruby /usr/bin/lib
  echo 'symlink created: /usr/bin/lib -> /usr/lib/ruby/vendor_ruby'
else
  echo 'vendor_ruby dir missing'
fi
echo '=== whatweb test ==='
whatweb --version 2>&1 | head -2
echo
echo '=== whatweb on example.com ==='
whatweb --no-errors -q https://example.com 2>&1 | head -2
exit 0

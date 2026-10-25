#!/usr/bin/env bash
echo '=== dpkg files ==='
dpkg -L whatweb | grep -E 'messages|/lib' | head -10
echo
echo '=== find messages.rb ==='
find /usr -name 'messages.rb' 2>/dev/null | grep -i whatweb | head -3
echo
echo '=== /usr/share/whatweb contents ==='
ls /usr/share/whatweb 2>/dev/null || echo 'dir missing'
exit 0

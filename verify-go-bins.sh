#!/bin/bash
export PATH=$PATH:/root/go/bin
for b in feroxbuster findomain httpx jaeles nuclei puredns subfinder tlsx chaos dnsx gau waybackurls gf qsreplace meg katana dalfox nabu crlfuzz; do
  if [ -x /root/go/bin/$b ]; then
    if /root/go/bin/$b --version >/dev/null 2>&1 || /root/go/bin/$b -version >/dev/null 2>&1; then
      echo "[OK] $b"
    else
      echo "[BROKEN] $b"
    fi
  else
    echo "[MISSING] $b"
  fi
done

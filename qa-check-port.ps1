Get-NetTCPConnection -LocalPort 17890 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { $_.OwningProcess }

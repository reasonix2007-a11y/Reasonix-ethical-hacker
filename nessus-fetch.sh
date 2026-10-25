#!/bin/bash
API='https://www.tenable.com/downloads/api/v2/pages/nessus'
curl -fsSL "$API" 2>/dev/null > /tmp/nessus-api.json
python3 <<'EOF'
import json
try:
    d = json.load(open('/tmp/nessus-api.json'))
except Exception as e:
    print('parse-error:', e); raise SystemExit
files = d.get('payload', {}).get('all', [])
for f in files:
    name = f.get('file', '')
    if 'ubuntu' in name.lower() and 'amd64' in name:
        print(f.get('file'), '->', f.get('size'))
EOF

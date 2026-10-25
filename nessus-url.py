#!/usr/bin/env python3
import json, urllib.request
d = json.load(open('/tmp/nessus-api.json'))
for rel_name, files in d['releases']['latest'].items():
    for f in files:
        n = f.get('file', '')
        if 'ubuntu' in n.lower() and 'amd64' in n:
            print(n, '|', f.get('file_url'))

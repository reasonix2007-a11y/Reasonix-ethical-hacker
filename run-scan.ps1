Set-Location 'c:\Users\hamza rajeh\CodeGPT\reasonix-ethical-hacker'
$appHealth = Invoke-WebRequest -Uri 'http://127.0.0.1:5500/' -TimeoutSec 5 -UseBasicParsing
if ($appHealth.StatusCode -ne 200) { throw 'The local app is not responding on port 5500.' }
$scannerHealth = Invoke-RestMethod -Uri 'http://127.0.0.1:17777/health' -TimeoutSec 5
if (-not $scannerHealth.ok) { throw 'The local scanner is not healthy on port 17777.' }
$out = Invoke-RestMethod -Method POST http://127.0.0.1:17777/scan -ContentType 'application/json' -Body '{"target":"http://127.0.0.1:5500"}' -TimeoutSec 1800
$out | ConvertTo-Json -Depth 8 | Set-Content -Path scan-result.json -Encoding UTF8
'DONE' | Set-Content -Path scan-done.txt -Encoding UTF8

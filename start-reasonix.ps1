param(
  [switch]$InstallTools,
  [switch]$SkipUbuntuWindow
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$envFile = Join-Path $projectRoot '.env'
$distro = 'Ubuntu'

if (Test-Path -LiteralPath $envFile) {
  $distroLine = Get-Content -LiteralPath $envFile |
    Where-Object { $_ -match '^\s*REASONIX_WSL_DISTRO\s*=' } |
    Select-Object -First 1
  if ($distroLine -match '^\s*REASONIX_WSL_DISTRO\s*=\s*["'']?([^"'']+?)["'']?\s*$') {
    $distro = $Matches[1].Trim()
  }
}

$wsl = Get-Command 'wsl.exe' -ErrorAction SilentlyContinue
if (-not $wsl) {
  throw 'WSL is not available. Install WSL and an Ubuntu distribution, then retry.'
}

$installedDistros = @(& $wsl.Source --list --quiet 2>$null | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
if ($LASTEXITCODE -ne 0 -or $installedDistros -notcontains $distro) {
  $available = if ($installedDistros.Count) { $installedDistros -join ', ' } else { 'none found' }
  throw "WSL distribution '$distro' was not found. Available distributions: $available. Set REASONIX_WSL_DISTRO in .env to the exact installed name."
}

$env:REASONIX_WSL_DISTRO = $distro
Push-Location $projectRoot
try {
  if ($InstallTools) {
    Write-Host "Installing supported scanner tools in the detected environment. Review and confirm the installer prompt."
    & npm.cmd run tools:install
    if ($LASTEXITCODE -ne 0) { throw 'Tool installation failed or was cancelled.' }
  }

  Write-Host "Checking scanner readiness for WSL distribution: $distro"
  & npm.cmd run tools:check
  if ($LASTEXITCODE -ne 0) { throw 'Tool readiness check failed.' }

  if (-not $SkipUbuntuWindow) {
    Write-Host "Opening Ubuntu ($distro) in a separate terminal window."
    $ubuntuProcess = Start-Process -FilePath $wsl.Source `
      -ArgumentList @('--distribution', $distro) `
      -PassThru
    if (-not $ubuntuProcess) { throw 'Could not open the WSL terminal.' }
  }

  Write-Host 'Starting the Reasonix web app in this PowerShell window.'
  Write-Host 'When a scan starts, its live progress opens in a separate PowerShell window.'
  & npm.cmd start
  if ($LASTEXITCODE -ne 0) { throw 'Reasonix server exited with an error.' }
}
finally {
  Pop-Location
}

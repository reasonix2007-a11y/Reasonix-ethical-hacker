@echo off
setlocal
cd /d "%~dp0"

fltmc >nul 2>&1
if errorlevel 1 (
    if /i "%~1"=="/elevated" (
        echo [ERROR] Administrator privileges were not granted.
        pause
        exit /b 1
    )
    echo Requesting administrator privileges through Windows UAC...
    set "REASONIX_BATCH=%~f0"
    set "REASONIX_PROJECT=%~dp0"
    powershell.exe -NoProfile -Command "try { $q = [char]34; $cmdArgs = '/c call ' + $q + $env:REASONIX_BATCH + $q + ' /elevated'; Start-Process -FilePath $env:ComSpec -ArgumentList $cmdArgs -WorkingDirectory $env:REASONIX_PROJECT -Verb RunAs -ErrorAction Stop; exit 0 } catch { exit 1 }"
    if errorlevel 1 (
        echo [ERROR] UAC was cancelled or the elevated process could not be started.
        pause
        exit /b 1
    )
    exit /b 0
)

where npm >nul 2>&1
if errorlevel 1 (
    echo [ERROR] npm was not found. Install Node.js and make sure npm is on PATH.
    pause
    exit /b 1
)

echo.
echo [1/2] Checking installed tools...
call npm run tools:check
if errorlevel 1 goto failed

echo.
echo [2/2] Running project tests...
call npm test
if errorlevel 1 goto failed

echo.
echo All checks completed successfully.
pause
exit /b 0

:failed
set "RESULT=%ERRORLEVEL%"
echo.
echo [ERROR] A command failed with exit code %RESULT%.
pause
exit /b %RESULT%

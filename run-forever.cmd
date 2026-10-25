@echo off
title Reasonix - Always Running
cd /d "%~dp0"
set "PATH=C:\Program Files\nodejs;%PATH%"
set "NODE_ENV=development"
:loop
echo [%date% %time%] Starting server...
node serve.mjs
echo [%date% %time%] Server stopped - restarting in 3 seconds...
timeout /t 3 /nobreak >nul
goto loop

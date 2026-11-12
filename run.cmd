@echo off
rem Launch the unified device tool. Keep this file ASCII + CRLF for cmd.exe.
rem Double click  -> pythonw, no console window.
rem run.cmd console -> run in console (window stays, errors visible).
cd /d "%~dp0"

if /i "%~1"=="console" goto console

set "PYW="
where pyw.exe >nul 2>nul && set "PYW=pyw -3"
if not defined PYW (
    where pythonw.exe >nul 2>nul && set "PYW=pythonw"
)
if defined PYW (
    start "" %PYW% "device_tool.py"
    exit /b 0
)

:console
set "PY=python"
where py >nul 2>nul && set "PY=py -3"
%PY% device_tool.py
if errorlevel 1 pause

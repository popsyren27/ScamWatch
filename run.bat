@echo off
REM ==========================================================================
REM run.bat - double-click launcher for THREAT-RECON (Windows).
REM Starts Tor (tor -f torrc) and the app via launch.py, then opens the GUI.
REM Any arguments are forwarded:  run.bat scan https://example.com
REM ==========================================================================
cd /d "%~dp0"

REM Prefer the py launcher, fall back to python on PATH.
where py >nul 2>nul
if %errorlevel%==0 (
    py launch.py %*
) else (
    python launch.py %*
)

echo.
pause

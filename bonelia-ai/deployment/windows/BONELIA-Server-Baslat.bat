@echo off
rem BONELIA AI Server - starts in the background (no console window).
rem Log: C:\BoneliaAI\server.log
setlocal
cd /d "%~dp0..\.."
set "ROOT=%CD%"
set "CFG=%ROOT%\deployment\server.home.toml"
if defined BONELIA_CONFIG set "CFG=%BONELIA_CONFIG%"

curl.exe -s -o nul --max-time 2 http://127.0.0.1:8742/v1/health
if %ERRORLEVEL%==0 (
  echo BONELIA AI Server zaten calisiyor / laeuft bereits.
  goto :end
)

set "EXE=%ROOT%\.venv\Scripts\bonelia-server.exe"
if not exist "%EXE%" (
  for /f "delims=" %%i in ('where bonelia-server.exe 2^>nul') do set "EXE=%%i"
)
if not exist "%EXE%" (
  echo Kurulum bulunamadi / Installation nicht gefunden: %ROOT%\.venv
  goto :end
)

if not exist "C:\BoneliaAI" mkdir "C:\BoneliaAI"
powershell -NoProfile -Command "Start-Process -FilePath '%EXE%' -ArgumentList '--config','\"%CFG%\"','serve' -WorkingDirectory '%ROOT%' -WindowStyle Hidden -RedirectStandardError 'C:\BoneliaAI\server.log' -RedirectStandardOutput 'C:\BoneliaAI\server-out.log'"

set /a N=0
:wait
timeout /t 1 /nobreak >nul
curl.exe -s -o nul --max-time 2 http://127.0.0.1:8742/v1/health
if %ERRORLEVEL%==0 (
  echo BONELIA AI Server arka planda calisiyor / laeuft im Hintergrund: http://127.0.0.1:8742
  goto :end
)
set /a N+=1
if %N% lss 30 goto :wait
echo Sunucu baslamadi / Server nicht gestartet. Log: C:\BoneliaAI\server.log
endlocal & exit /b 1

:end
if "%~1"=="/quiet" ( endlocal & exit /b 0 )
if not defined CI timeout /t 4 >nul
endlocal & exit /b 0

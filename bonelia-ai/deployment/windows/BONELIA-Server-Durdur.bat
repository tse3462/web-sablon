@echo off
rem Stops the BONELIA AI Server started in the background.
taskkill /IM bonelia-server.exe /T /F >nul 2>&1
if %ERRORLEVEL%==0 (echo BONELIA AI Server durduruldu / gestoppt.) else (echo Calisan sunucu yok / kein laufender Server.)
if not defined CI timeout /t 3 >nul
exit /b 0

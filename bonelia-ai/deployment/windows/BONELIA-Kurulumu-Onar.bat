@echo off
rem Repairs the installation: installs BONELIA into THIS checkout's .venv (editable),
rem verifies it, then restarts the server and the phone panel with the new code.
rem Use this when the panel keeps showing the old phone link (#token instead of ?t=).
cd /d "%~dp0..\.."
set "ROOT=%CD%"
set "PY=%ROOT%\.venv\Scripts\python.exe"

if not exist "%PY%" (
  echo .venv bulunamadi / nicht gefunden: %PY%
  echo Once kurulumu yapin / zuerst installieren.
  pause
  exit /b 1
)

echo [1/4] Sunucu ve panel durduruluyor (dosya kilidi olmasin diye)...
call "%~dp0BONELIA-Server-Durdur.bat"

echo.
echo [2/4] Program .venv icine kuruluyor (bir dakika surebilir)...
"%PY%" -m pip install -e ".[server]"
if errorlevel 1 (
  echo.
  echo *** KURULUM BASARISIZ *** Yukaridaki hatayi Claude'a gonderin.
  pause
  exit /b 1
)

echo.
echo [3/4] Dogrulama...
"%PY%" -c "import bonelia,os;print('BONELIA OK:',os.path.dirname(bonelia.__file__))"
if errorlevel 1 (
  echo.
  echo *** DOGRULAMA BASARISIZ *** Yukaridaki hatayi Claude'a gonderin.
  pause
  exit /b 1
)

echo.
echo [4/4] Sunucu ve panel yeni kodla baslatiliyor...
call "%~dp0BONELIA-Server-Baslat.bat" /quiet
call "%~dp0BONELIA-Panel-Baslat.bat" /quiet
timeout /t 6 /nobreak >nul
if exist "C:\BoneliaAI\server-data\panel-url.txt" start notepad "C:\BoneliaAI\server-data\panel-url.txt"

echo.
echo ================================================================
echo BITTI. Acilan panel-url.txt artik ?t= ile baslamali (# degil).
echo O adresi telefonda acin, sonra Ana Ekrana Ekle.
echo ================================================================
pause

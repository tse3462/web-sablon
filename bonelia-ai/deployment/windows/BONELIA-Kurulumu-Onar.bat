@echo off
rem Repairs a broken .venv: the venv's python.exe stopped working ("This app can't run
rem on your PC" / Access denied). This recreates .venv with the working system Python
rem (Python 3.14 via PyManager / the `python` command), installs BONELIA into it, and
rem restarts the server and phone panel on the new code. One double-click, no typing.
cd /d "%~dp0..\.."
set "ROOT=%CD%"

rem Pick a working base Python: the real PyManager interpreter if present, else `python`.
set "BASEPY=%LocalAppData%\Python\pythoncore-3.14-64\python.exe"
if not exist "%BASEPY%" set "BASEPY=python"

echo [1/6] Sunucu, panel ve ajan durduruluyor (dosya kilidi olmasin diye)...
call "%~dp0BONELIA-Server-Durdur.bat"
schtasks /End /TN "BONELIA AI Agent" >nul 2>&1
timeout /t 2 /nobreak >nul

echo.
echo [2/6] Bozuk .venv siliniyor...
if exist ".venv" rmdir /s /q ".venv"

echo.
echo [3/6] Yeni .venv olusturuluyor (Python 3.14 ile)...
"%BASEPY%" -m venv ".venv"
if not exist ".venv\Scripts\python.exe" (
  echo    python -m venv olmadi, py -3 deneniyor...
  py -3 -m venv ".venv"
)
if not exist ".venv\Scripts\python.exe" (
  echo.
  echo *** .venv OLUSTURULAMADI *** Ekranin fotografini Claude'a gonderin.
  pause
  exit /b 1
)

echo.
echo [4/6] pip guncelleniyor...
".venv\Scripts\python.exe" -m pip install --upgrade pip

echo.
echo [5/6] BONELIA kuruluyor (internetten, bir-iki dakika surebilir)...
".venv\Scripts\python.exe" -m pip install -e ".[server]"
echo.
echo    --- Dogrulama ---
".venv\Scripts\python.exe" -c "import bonelia,os;print('BONELIA OK:',os.path.dirname(bonelia.__file__))"
if errorlevel 1 (
  echo.
  echo *** KURULUM BASARISIZ *** Ekranin fotografini Claude'a gonderin.
  pause
  exit /b 1
)

echo.
echo [6/6] Sunucu ve panel yeni kodla baslatiliyor...
call "%~dp0BONELIA-Server-Baslat.bat" /quiet
call "%~dp0BONELIA-Panel-Baslat.bat" /quiet
timeout /t 6 /nobreak >nul
if exist "C:\BoneliaAI\server-data\panel-url.txt" start notepad "C:\BoneliaAI\server-data\panel-url.txt"

echo.
echo ================================================================
echo  BITTI. Acilan panel-url.txt artik ?t= ile baslamali ( # degil ).
echo  O adresi telefonda acin, sonra Ana Ekrana Ekle.
echo ================================================================
pause

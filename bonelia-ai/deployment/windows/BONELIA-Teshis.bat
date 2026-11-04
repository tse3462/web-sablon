@echo off
rem Read-only diagnostic: finds which Python interpreters work on this PC and where the
rem running bonelia-server.exe comes from. Changes nothing. Screenshot the result.
cd /d "%~dp0..\.."
set "ROOT=%CD%"
echo ================= BONELIA TESHIS =================
echo.
echo -- 1) Calisan program (bonelia-server.exe) nerede:
where bonelia-server.exe 2>nul
if errorlevel 1 echo    (PATH'te yok)
echo.
echo -- 2) PATH'teki python:
where python 2>nul
if errorlevel 1 echo    (PATH'te yok)
echo.
echo -- 3) py launcher:
where py 2>nul
if errorlevel 1 echo    (yok)
echo.
echo -- 4) Kurulu Python'lar (py -0p):
py -0p 2>nul
if errorlevel 1 echo    (py launcher calismadi)
echo.
echo -- 5) .venv python testi:
"%ROOT%\.venv\Scripts\python.exe" -c "import sys;print('.venv OK', sys.version)" 2>&1
echo.
echo -- 6) 'python' ile test:
python -c "import sys;print('python OK', sys.version)" 2>&1
echo.
echo -- 7) 'py -3' ile test:
py -3 -c "import sys;print('py-3 OK', sys.version)" 2>&1
echo.
echo ==================================================
echo Bu ekranin fotografini Claude'a gonderin.
pause

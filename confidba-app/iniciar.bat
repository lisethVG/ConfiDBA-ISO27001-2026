@echo off
chcp 65001 >nul
cd /d "%~dp0"
title ConfiDBA Studio
echo.
echo  ConfiDBA Studio - iniciando...
echo.
set PY=
py -3 --version >nul 2>&1 && set PY=py -3
if not "%PY%"=="" goto hay
python --version 2>nul | findstr /c:"Python 3" >nul && set PY=python
if not "%PY%"=="" goto hay
goto sinpython

:hay
echo  Python encontrado: %PY%
echo  Instalando lo necesario, la primera vez tarda un minuto...
%PY% -m pip install -q -r requirements.txt
if errorlevel 1 goto errpip
echo.
echo  Listo. Se abrira el navegador en http://127.0.0.1:5000
echo  NO CIERRE ESTA VENTANA mientras use la app. Para apagarla, presione Ctrl+C.
echo.
start "" cmd /c "timeout /t 4 >nul && start http://127.0.0.1:5000"
%PY% app.py
pause
goto fin

:sinpython
echo  NO se encontro Python en esta computadora.
echo.
echo  1. Se abrira la pagina de descarga. Baje el instalador de Python.
echo  2. Al abrirlo, MARQUE la casilla "Add python.exe to PATH" y presione Install Now.
echo  3. Cuando termine, cierre esta ventana y haga doble clic otra vez en iniciar.bat
echo.
start "" https://www.python.org/downloads/
pause
goto fin

:errpip
echo.
echo  No se pudieron instalar los componentes. Revise la conexion a internet y reintente.
pause

:fin

@echo off
setlocal enabledelayedexpansion

echo ========================================
echo PhishGuard System Startup
echo ========================================

:: Set absolute paths to avoid navigation issues
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"
set "ROOT_DIR=%SCRIPT_DIR%.."
set "BACKEND_DIR=%ROOT_DIR%\backend"
set "FRONTEND_DIR=%ROOT_DIR%\frontend"
set "ML_DIR=%ROOT_DIR%\ml"
set "VENV_DIR=%ROOT_DIR%\myenvv"
set "KEYS_FILE=%ROOT_DIR%\api_keys.env"

:: Check Python installation and version
for /f "tokens=2 delims=." %%I in ('python -V 2^>^&1') do set PYTHON_VERSION=%%I
if %PYTHON_VERSION% LSS 8 (
    echo Error: Python 3.8 or higher is required!
    pause
    exit /b 1
)

:: Check Node.js installation and version
for /f "tokens=1,2,3 delims=." %%a in ('node -v 2^>^&1') do set NODE_VERSION=%%a
if %NODE_VERSION% LSS 14 (
    echo Error: Node.js 14 or higher is required!
    pause
    exit /b 1
)

:: Verify directories exist and create if necessary
for %%D in (BACKEND_DIR FRONTEND_DIR ML_DIR) do (
    if not exist "!%%D!" (
        echo Creating directory: !%%D!
        mkdir "!%%D!"
        if errorlevel 1 (
            echo Error: Failed to create !%%D!
            pause
            exit /b 1
        )
    )
)

:: Setup virtual environment with error handling
if not exist "%VENV_DIR%\Scripts\activate.bat" (
    echo Creating virtual environment...
    python -m venv "%VENV_DIR%" 2>nul
    if errorlevel 1 (
        echo Error: Failed to create virtual environment!
        echo Please ensure Python venv module is installed.
        pause
        exit /b 1
    )
)

:: Install backend requirements with proper activation
echo Installing backend requirements...
call "%VENV_DIR%\Scripts\activate.bat" 2>nul
if errorlevel 1 (
    echo Error: Failed to activate virtual environment!
    pause
    exit /b 1
)

:: Check and install backend requirements
cd /d "%BACKEND_DIR%"
if exist "requirements.txt" (
    pip install -r requirements.txt
    if errorlevel 1 (
        echo Error: Failed to install backend requirements!
        pause
        exit /b 1
    )
) else (
    echo Warning: requirements.txt not found in backend directory!
)

:: Install frontend dependencies with error handling
echo Installing frontend dependencies...
cd /d "%FRONTEND_DIR%"
if exist "package.json" (
    call npm install --silent
    if errorlevel 1 (
        echo Error: Failed to install frontend dependencies!
        pause
        exit /b 1
    )
) else (
    echo Warning: package.json not found in frontend directory!
)

:: Load or create API keys file
if exist "%KEYS_FILE%" (
    echo Loading API keys...
    for /f "tokens=*" %%a in ('type "%KEYS_FILE%"') do set "%%a"
) else (
    echo Creating new API keys file...
    (
        echo VIRUSTOTAL_API_KEY=
        echo GOOGLE_SAFEBROWSING_API_KEY=
    ) > "%KEYS_FILE%"
)

:: Start Backend with proper path and activation
echo Starting backend server...
cd /d "%BACKEND_DIR%"
start "PhishGuard Backend" cmd /k "call "%VENV_DIR%\Scripts\activate.bat" && python manage.py runserver"

:: Wait for backend to initialize
timeout /t 5 /nobreak > nul

:: Start Frontend with proper path
echo Starting frontend server...
cd /d "%FRONTEND_DIR%"
start "PhishGuard Frontend" cmd /k "npm start"

:: Display comprehensive status
echo.
echo ========================================
echo PhishGuard System Status
echo ========================================
echo Backend URL: http://localhost:8000
echo Frontend URL: http://localhost:3000
echo.
echo API Status:
if defined VIRUSTOTAL_API_KEY (echo VirusTotal API: Enabled) else (echo VirusTotal API: Disabled)
if defined GOOGLE_SAFEBROWSING_API_KEY (echo Google Safe Browsing API: Enabled) else (echo Google Safe Browsing API: Disabled)
echo.
echo Directory Status:
echo Backend: %BACKEND_DIR%
echo Frontend: %FRONTEND_DIR%
echo ML: %ML_DIR%
echo Virtual Environment: %VENV_DIR%
echo.
echo Check the opened command windows for any errors
echo ========================================

endlocal
pause
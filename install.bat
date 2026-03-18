@echo off
REM NetWatch Installer Script for Windows
REM 
REM This script installs NetWatch and its Python dependencies.
REM Note: nmap binary must be installed manually from https://nmap.org/download.html
REM
REM Usage: install.bat
REM

setlocal EnableDelayedExpansion

REM Colors (using ANSI escape sequences for Windows 10+)
set "RESET=[0m"
set "RED=[31m"
set "GREEN=[32m"
set "YELLOW=[33m"
set "BLUE=[34m"
set "BOLD=[1m"

REM Track step results
set "STEP_NUM=0"
set "PASS_COUNT=0"
set "FAIL_COUNT=0"

REM ASCII Banner
echo.
echo %BLUE%%BOLD%==============================================================%RESET%
echo %BLUE%%BOLD%                                                              %RESET%
echo %BLUE%%BOLD%              NetWatch Installer                              %RESET%
echo %BLUE%%BOLD%              Network EOL Scanner Setup                       %RESET%
echo %BLUE%%BOLD%                                                              %RESET%
echo %BLUE%%BOLD%==============================================================%RESET%
echo.

REM Helper functions
goto :main

:print_pass
echo %GREEN%PASS%RESET%: %~1
goto :eof

:print_fail
echo %RED%FAIL%RESET%: %~1
goto :eof

:print_info
echo %BLUE%INFO%RESET%: %~1
goto :eof

:print_warn
echo %YELLOW%WARN%RESET%: %~1
goto :eof

:record_step
set /a STEP_NUM+=1
set "STEP_%STEP_NUM%_NAME=%~2"
set "STEP_%STEP_NUM%_STATUS=%~3"
set "STEP_%STEP_NUM%_MESSAGE=%~4"
if "%~3"=="PASS" set /a PASS_COUNT+=1
if "%~3"=="FAIL" set /a FAIL_COUNT+=1
goto :eof

:main

REM ============================================================================
REM STEP 1: Check Python >= 3.9
REM ============================================================================
call :print_info "Step 1: Checking Python version..."

python --version >nul 2>&1
if errorlevel 1 (
    call :print_fail "Python is not installed or not in PATH"
    echo.
    echo %RED%CRITICAL: Python 3.9 or higher is required.%RESET%
    echo.
    echo Installation instructions:
    echo   1. Download Python from: https://www.python.org/downloads/
    echo   2. Run the installer and select "Add Python to PATH"
    echo   3. Restart your terminal and run this script again
    echo.
    call :record_step 1 "Python Check" "FAIL" "Python not found"
    goto :summary
)

for /f "tokens=2" %%a in ('python --version 2^>^&1') do set PYTHON_VERSION=%%a
echo Detected Python version: %PYTHON_VERSION%

REM Check version >= 3.9
for /f "tokens=1,2 delims=." %%a in ("%PYTHON_VERSION%") do (
    set MAJOR=%%a
    set MINOR=%%b
)

if %MAJOR% LSS 3 (
    call :print_fail "Python version %PYTHON_VERSION% is too old (requires >= 3.9)"
    echo.
    echo %RED%CRITICAL: Python 3.9 or higher is required.%RESET%
    echo Please upgrade Python and try again.
    echo Visit: https://www.python.org/downloads/
    echo.
    call :record_step 1 "Python Check" "FAIL" "Python %PYTHON_VERSION% < 3.9"
    goto :summary
)

if %MAJOR% EQU 3 (
    if %MINOR% LSS 9 (
        call :print_fail "Python version %PYTHON_VERSION% is too old (requires >= 3.9)"
        echo.
        echo %RED%CRITICAL: Python 3.9 or higher is required.%RESET%
        echo Please upgrade Python and try again.
        echo.
        call :record_step 1 "Python Check" "FAIL" "Python %PYTHON_VERSION% < 3.9"
        goto :summary
    )
)

call :print_pass "Python %PYTHON_VERSION% found"
call :record_step 1 "Python Check" "PASS" "Python %PYTHON_VERSION%"

REM ============================================================================
REM STEP 2: Check pip
REM ============================================================================
call :print_info "Step 2: Checking pip..."

python -m pip --version >nul 2>&1
if errorlevel 1 (
    call :print_fail "pip is not installed"
    echo.
    echo %RED%CRITICAL: pip is required.%RESET%
    echo Try reinstalling Python with pip included.
    echo.
    call :record_step 2 "pip Check" "FAIL" "pip not found"
    goto :summary
)

for /f "tokens=2" %%a in ('python -m pip --version 2^>^&1') do set PIP_VERSION=%%a
call :print_pass "pip %PIP_VERSION% found"
call :record_step 2 "pip Check" "PASS" "pip %PIP_VERSION%"

REM ============================================================================
REM STEP 3: Upgrade pip
REM ============================================================================
call :print_info "Step 3: Upgrading pip..."

python -m pip install --upgrade pip >nul 2>&1
if errorlevel 1 (
    call :print_warn "Failed to upgrade pip (continuing anyway)"
    call :record_step 3 "pip Upgrade" "WARN" "upgrade failed"
) else (
    call :print_pass "pip upgraded successfully"
    call :record_step 3 "pip Upgrade" "PASS" "upgraded"
)

REM ============================================================================
REM STEP 4: Remind about nmap binary
REM ============================================================================
call :print_info "Step 4: Checking nmap binary..."

nmap --version >nul 2>&1
if errorlevel 1 (
    call :print_warn "nmap binary not found in PATH"
    echo.
    echo %YELLOW%IMPORTANT: nmap binary is required for NetWatch to function.%RESET%
    echo.
    echo nmap must be installed manually on Windows.
    echo.
    echo Download from: https://nmap.org/download.html
    echo.
    echo Installation steps:
    echo   1. Download the latest stable release installer
    echo   2. Run the installer (nmap-xxx-setup.exe)
    echo   3. Ensure nmap is added to your system PATH
    echo   4. Restart your terminal
    echo.
    echo Note: NetWatch uses python-nmap which is a wrapper around the nmap binary.
    echo       Both the nmap binary AND the python-nmap Python package are required.
    echo.
    pause
    call :record_step 4 "nmap Check" "WARN" "nmap not installed"
) else (
    for /f "tokens=3" %%a in ('nmap --version 2^>^&1 ^| findstr /B "Nmap version"') do set NMAP_VERSION=%%a
    call :print_pass "nmap %NMAP_VERSION% found"
    call :record_step 4 "nmap Check" "PASS" "nmap %NMAP_VERSION%"
)

REM ============================================================================
REM STEP 5: Create virtual environment
REM ============================================================================
call :print_info "Step 5: Creating Python virtual environment..."

if exist "venv" (
    call :print_warn "venv directory already exists, using existing"
    call :record_step 5 "Create venv" "PASS" "venv exists"
) else (
    python -m venv venv >nul 2>&1
    if errorlevel 1 (
        call :print_fail "Failed to create virtual environment"
        call :record_step 5 "Create venv" "FAIL" "venv creation failed"
        goto :summary
    ) else (
        call :print_pass "Virtual environment created"
        call :record_step 5 "Create venv" "PASS" "venv created"
    )
)

REM ============================================================================
REM STEP 6: Activate virtual environment
REM ============================================================================
call :print_info "Step 6: Activating virtual environment..."

if exist "venv\Scripts\activate.bat" (
    call venv\Scripts\activate.bat
    call :print_pass "Virtual environment activated"
    call :record_step 6 "Activate venv" "PASS" "venv activated"
) else (
    call :print_fail "Could not find virtual environment activation script"
    call :record_step 6 "Activate venv" "FAIL" "activation failed"
    goto :summary
)

REM ============================================================================
REM STEP 7: Install Python dependencies
REM ============================================================================
call :print_info "Step 7: Installing Python dependencies..."

REM Check if requirements.txt exists
if not exist "requirements.txt" (
    call :print_warn "requirements.txt not found, creating default..."
    (
        echo python-nmap==0.7.1
        echo requests==2.31.0
        echo rich==13.7.0
        echo packaging==24.0
    ) > requirements.txt
)

pip install -r requirements.txt >nul 2>&1
if errorlevel 1 (
    call :print_fail "Failed to install Python dependencies"
    echo.
    echo %RED%CRITICAL: Failed to install required packages.%RESET%
    echo Check your internet connection and try again.
    echo.
    call :record_step 7 "Install deps" "FAIL" "pip install failed"
    goto :summary
) else (
    call :print_pass "Python dependencies installed"
    call :record_step 7 "Install deps" "PASS" "dependencies installed"
)

REM ============================================================================
REM STEP 8: Verify package imports
REM ============================================================================
call :print_info "Step 8: Verifying package installation..."

python -c "import nmap; import requests; import rich; import packaging" >nul 2>&1
if errorlevel 1 (
    call :print_fail "Package verification failed"
    echo One or more packages failed to install correctly.
    call :record_step 8 "Verify imports" "FAIL" "import verification failed"
    goto :summary
) else (
    call :print_pass "All packages import successfully"
    call :record_step 8 "Verify imports" "PASS" "imports verified"
)

REM ============================================================================
REM STEP 9: Run self-test
REM ============================================================================
call :print_info "Step 9: Running self-test..."

python netwatch.py --version >nul 2>&1
if errorlevel 1 (
    call :print_fail "Self-test failed"
    call :record_step 9 "Self-test" "FAIL" "self-test failed"
    goto :summary
) else (
    for /f "usebackq" %%a in (`python netwatch.py --version 2^>^&1`) do set NW_VERSION=%%a
    call :print_pass "Self-test passed: %NW_VERSION%"
    call :record_step 9 "Self-test" "PASS" "self-test OK"
)

REM ============================================================================
REM Installation Summary
REM ============================================================================
:summary
echo.
echo %BLUE%%BOLD%==============================================================%RESET%
echo %BLUE%%BOLD%                    Installation Summary                      %RESET%
echo %BLUE%%BOLD%==============================================================%RESET%
echo.

for /L %%i in (1,1,%STEP_NUM%) do (
    call :print_step_summary %%i
)

echo.

if %FAIL_COUNT% GTR 0 (
    echo %RED%%BOLD%Installation completed with errors!%RESET%
) else (
    echo %GREEN%%BOLD%NetWatch installation complete!%RESET%
)

echo.
echo Usage:
echo   netwatch.py              Launch interactive menu
echo   netwatch.py --help       Show help
echo   netwatch.py --version    Show version
echo.
echo Run from install directory: python netwatch.py
echo.
echo %YELLOW%Note: For full scan capabilities, run as Administrator.%RESET%
echo.

pause
goto :eof

:print_step_summary
set "num=%~1"
set "name=!STEP_%num%_NAME!"
set "status=!STEP_%num%_STATUS!"
set "msg=!STEP_%num%_MESSAGE!"

if "!status!"=="PASS" (
    echo %GREEN%PASS%RESET% Step %num%: %name% - %msg%
) else if "!status!"=="FAIL" (
    echo %RED%FAIL%RESET% Step %num%: %name% - %msg%
) else if "!status!"=="WARN" (
    echo %YELLOW%WARN%RESET% Step %num%: %name% - %msg%
) else (
    echo %BLUE%INFO%RESET% Step %num%: %name% - %msg%
)
goto :eof

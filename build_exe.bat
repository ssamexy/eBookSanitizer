@echo off
REM ===================================================================
REM eBookSanitizer Executable Builder Script
REM Automated script to build a single standalone .exe using PyInstaller
REM ===================================================================

echo ============================================
echo eBookSanitizer Executable Builder
echo ============================================
echo.

REM Check if Python is available
echo [1/4] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH.
    echo Please install Python and ensure it's accessible.
    pause
    exit /b 1
)
echo Python found successfully.

REM Check if PyInstaller is installed
echo.
echo [2/4] Checking PyInstaller installation...
python -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo WARNING: PyInstaller not found. Attempting to install...
    python -m pip install pyinstaller
    if errorlevel 1 (
        echo ERROR: Failed to install PyInstaller.
        echo Please manually install: pip install pyinstaller
        pause
        exit /b 1
    )
    echo PyInstaller installed successfully.
) else (
    echo PyInstaller found successfully.
)

REM Confirm build
echo.
echo [3/4] Build configuration:
echo Current directory: %CD%

REM Extract Version dynamically from package init
for /f "tokens=*" %%i in ('python -c "import sanitizer; print(sanitizer.__version__)"') do set APP_VERSION=%%i
if "%APP_VERSION%"=="" (
    set APP_VERSION=1.0.0
)

echo Target Entry Script: main.py
echo Version: %APP_VERSION%
echo Output Name: eBookSanitizer_v%APP_VERSION%.exe
echo.

REM Terminate any running instances to avoid PyInstaller file lock errors
echo [3.5/4] Terminating any running instances of eBookSanitizer...
taskkill /F /IM eBookSanitizer* /T >nul 2>&1

set /p confirm="Do you want to proceed with the build? (Y/N): "
if /i not "%confirm%"=="Y" (
    echo Build cancelled by user.
    pause
    exit /b 0
)

REM Start the build process
echo.
echo [4/4] Starting PyInstaller build process...
echo Command: python -m PyInstaller -y --onefile --noconsole --clean --collect-all customtkinter --name="eBookSanitizer_v%APP_VERSION%" main.py
echo.
echo ============================================
echo BUILD OUTPUT:
echo ============================================

python -m PyInstaller -y --onefile --noconsole --clean --collect-all customtkinter --name="eBookSanitizer_v%APP_VERSION%" main.py

REM Check if build was successful
if errorlevel 1 (
    echo.
    echo ============================================
    echo BUILD FAILED!
    echo ============================================
    echo The build process encountered errors.
    echo.
    pause
    exit /b 1
) else (
    echo.
    echo ============================================
    echo BUILD COMPLETED SUCCESSFULLY!
    echo ============================================
    echo.
    echo The executable has been created in the 'dist' directory.
    echo.
    if exist "dist\" (
        echo Contents of dist directory:
        dir dist /b
        echo.
        echo You can now run your standalone application.
    )
    echo.
    echo Press any key to open the dist folder...
    pause >nul
    if exist "dist\" explorer dist
)

echo.
echo ============================================
echo Script completed.
echo ============================================
pause

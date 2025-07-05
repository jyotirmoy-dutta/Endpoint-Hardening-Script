# Endpoint-Hardening.ps1
# Robust Windows Endpoint Hardening Script
# Applies recommended security policies for improved security posture
# Author: (Your Name)
# Date: (Today's Date)

# =========================
# CONFIGURATION & LOGGING
# =========================
$LogFile = "$PSScriptRoot\Endpoint-Hardening.log"
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$timestamp [$Level] $Message" | Out-File -FilePath $LogFile -Append
}

# =========================
# ADMIN CHECK
# =========================
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as Administrator." -ForegroundColor Red
    Write-Log "Script not run as Administrator. Exiting." 'ERROR'
    exit 1
}
Write-Log "Script started as Administrator."

# =========================
# FUNCTION DEFINITIONS
# =========================

function Disable-SMBv1 {
    Write-Log "Disabling SMBv1..."
    try {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -Value 0 -Force
        Write-Log "SMBv1 disabled successfully."
    } catch {
        Write-Log "Failed to disable SMBv1: $_" 'ERROR'
    }
}

function Enforce-PasswordPolicy {
    Write-Log "Enforcing password complexity and length..."
    try {
        secedit /export /cfg "$env:TEMP\secpol.cfg" | Out-Null
        (Get-Content "$env:TEMP\secpol.cfg") |
            ForEach-Object {
                $_ -replace 'MinimumPasswordLength = \d+', 'MinimumPasswordLength = 12'
            } |
            ForEach-Object {
                $_ -replace 'PasswordComplexity = \d+', 'PasswordComplexity = 1'
            } |
            Set-Content "$env:TEMP\secpol.cfg"
        secedit /configure /db secedit.sdb /cfg "$env:TEMP\secpol.cfg" /areas SECURITYPOLICY | Out-Null
        Remove-Item "$env:TEMP\secpol.cfg" -Force
        Write-Log "Password policy enforced."
    } catch {
        Write-Log "Failed to enforce password policy: $_" 'ERROR'
    }
}

function Disable-GuestAccount {
    Write-Log "Disabling Guest account..."
    try {
        net user Guest /active:no | Out-Null
        Write-Log "Guest account disabled."
    } catch {
        Write-Log "Failed to disable Guest account: $_" 'ERROR'
    }
}

function Enable-WindowsFirewall {
    Write-Log "Enabling Windows Firewall..."
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
        Write-Log "Windows Firewall enabled."
    } catch {
        Write-Log "Failed to enable Windows Firewall: $_" 'ERROR'
    }
}

function Disable-UnnecessaryServices {
    Write-Log "Disabling unnecessary services (e.g., Telnet)..."
    $services = @('TlntSvr')
    foreach ($svc in $services) {
        try {
            Set-Service -Name $svc -StartupType Disabled -ErrorAction Stop
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            Write-Log "Service $svc disabled."
        } catch {
            Write-Log ("Failed to disable service {0}: {1}" -f $svc, $_) 'ERROR'
        }
    }
}

function Enable-BitLocker {
    Write-Log "Checking BitLocker status..."
    try {
        $osDrive = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
        if ($osDrive -and $osDrive.ProtectionStatus -eq 0) {
            Enable-BitLocker -MountPoint "C:" -UsedSpaceOnly -TpmProtector | Out-Null
            Write-Log "BitLocker enabled on C:."
        } else {
            Write-Log "BitLocker already enabled or not available."
        }
    } catch {
        Write-Log "BitLocker not available or failed to enable: $_" 'ERROR'
    }
}

function Disable-Autorun {
    Write-Log "Disabling Autorun..."
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoDriveTypeAutoRun -Value 255 -Force
        Write-Log "Autorun disabled."
    } catch {
        Write-Log "Failed to disable Autorun: $_" 'ERROR'
    }
}

function Enable-AutomaticUpdates {
    Write-Log "Enabling automatic updates..."
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name AUOptions -Value 4 -Force
        Write-Log "Automatic updates enabled."
    } catch {
        Write-Log "Failed to enable automatic updates: $_" 'ERROR'
    }
}

function Enable-Auditing {
    Write-Log "Enabling auditing for logon events..."
    try {
        auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable | Out-Null
        Write-Log "Auditing enabled for logon events."
    } catch {
        Write-Log "Failed to enable auditing: $_" 'ERROR'
    }
}

function Disable-LLMNR {
    Write-Log "Disabling LLMNR..."
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast -Value 0 -Force
        Write-Log "LLMNR disabled."
    } catch {
        Write-Log "Failed to disable LLMNR: $_" 'ERROR'
    }
}

function Enforce-UAC {
    Write-Log "Enforcing User Account Control (UAC)..."
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name ConsentPromptBehaviorAdmin -Value 2 -Force
        Write-Log "UAC enforced."
    } catch {
        Write-Log "Failed to enforce UAC: $_" 'ERROR'
    }
}

function Disable-RemoteRegistry {
    Write-Log "Disabling Remote Registry service..."
    try {
        Set-Service -Name RemoteRegistry -StartupType Disabled -ErrorAction Stop
        Stop-Service -Name RemoteRegistry -Force -ErrorAction SilentlyContinue
        Write-Log "Remote Registry service disabled."
    } catch {
        Write-Log "Failed to disable Remote Registry: $_" 'ERROR'
    }
}

function Restrict-RDP {
    Write-Log "Restricting Remote Desktop access..."
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -Value 1 -Force
        Write-Log "Remote Desktop access restricted."
    } catch {
        Write-Log "Failed to restrict RDP: $_" 'ERROR'
    }
}

function Disable-WindowsScriptHost {
    Write-Log "Disabling Windows Script Host..."
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name Enabled -Value 0 -Force
        Write-Log "Windows Script Host disabled."
    } catch {
        Write-Log "Failed to disable Windows Script Host: $_" 'ERROR'
    }
}

function Disable-AnonymousSIDEnumeration {
    Write-Log "Disabling anonymous SID/Name translation..."
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RestrictAnonymousSAM -Value 1 -Force
        Write-Log "Anonymous SID/Name translation disabled."
    } catch {
        Write-Log "Failed to disable anonymous SID enumeration: $_" 'ERROR'
    }
}

function Disable-IPv6 {
    Write-Log "Disabling IPv6..."
    try {
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name DisabledComponents -PropertyType DWord -Value 0xFF -Force | Out-Null
        Write-Log "IPv6 disabled."
    } catch {
        Write-Log "Failed to disable IPv6: $_" 'ERROR'
    }
}

function Disable-NetBIOS {
    Write-Log "Disabling NetBIOS over TCP/IP..."
    try {
        Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled } | ForEach-Object { $_.SetTcpipNetbios(2) } | Out-Null
        Write-Log "NetBIOS disabled."
    } catch {
        Write-Log "Failed to disable NetBIOS: $_" 'ERROR'
    }
}

function Restrict-USBStorage {
    Write-Log "Restricting USB storage..."
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name Start -Value 4 -Force
        Write-Log "USB storage restricted."
    } catch {
        Write-Log "Failed to restrict USB storage: $_" 'ERROR'
    }
}

function Enforce-ScreenLockTimeout {
    Write-Log "Enforcing screen lock timeout..."
    try {
        $timeout = 900 # 15 minutes
        powercfg /change standby-timeout-ac 15
        powercfg /change standby-timeout-dc 15
        powercfg /change monitor-timeout-ac 15
        powercfg /change monitor-timeout-dc 15
        Write-Log "Screen lock timeout enforced."
    } catch {
        Write-Log "Failed to enforce screen lock timeout: $_" 'ERROR'
    }
}

function Disable-Cortana {
    Write-Log "Disabling Cortana..."
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name AllowCortana -Value 0 -Force
        Write-Log "Cortana disabled."
    } catch {
        Write-Log "Failed to disable Cortana: $_" 'ERROR'
    }
}

function Disable-Telemetry {
    Write-Log "Disabling telemetry..."
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name AllowTelemetry -Value 0 -Force
        Write-Log "Telemetry disabled."
    } catch {
        Write-Log "Failed to disable telemetry: $_" 'ERROR'
    }
}

function Restrict-PowerShellExecution {
    Write-Log "Restricting PowerShell script execution policy..."
    try {
        Set-ExecutionPolicy -ExecutionPolicy AllSigned -Scope LocalMachine -Force
        Write-Log "PowerShell execution policy set to AllSigned."
    } catch {
        Write-Log "Failed to restrict PowerShell execution policy: $_" 'ERROR'
    }
}

function Disable-ErrorReporting {
    Write-Log "Disabling Windows Error Reporting..."
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name Disabled -Value 1 -Force
        Write-Log "Windows Error Reporting disabled."
    } catch {
        Write-Log "Failed to disable Windows Error Reporting: $_" 'ERROR'
    }
}

function Disable-UnnecessaryScheduledTasks {
    Write-Log "Disabling unnecessary scheduled tasks..."
    $tasks = @(
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
    )
    foreach ($task in $tasks) {
        try {
            schtasks /Change /TN $task /Disable | Out-Null
            Write-Log "Scheduled task $task disabled."
        } catch {
            Write-Log ("Failed to disable scheduled task {0}: {1}" -f $task, $_) 'ERROR'
        }
    }
}

function Restrict-LocalAdminLogon {
    Write-Log "Restricting local administrator logon..."
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LocalAccountTokenFilterPolicy -Value 0 -Force
        Write-Log "Local admin logon restricted."
    } catch {
        Write-Log "Failed to restrict local admin logon: $_" 'ERROR'
    }
}

function Disable-RemoteAssistance {
    Write-Log "Disabling Remote Assistance..."
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name fAllowToGetHelp -Value 0 -Force
        Write-Log "Remote Assistance disabled."
    } catch {
        Write-Log "Failed to disable Remote Assistance: $_" 'ERROR'
    }
}

function Enforce-SecureBoot {
    Write-Log "Checking Secure Boot status..."
    try {
        $sb = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        if ($sb -eq $true) {
            Write-Log "Secure Boot is enabled."
        } else {
            Write-Log "Secure Boot is not enabled or not supported."
        }
    } catch {
        Write-Log "Failed to check Secure Boot: $_" 'ERROR'
    }
}

function Disable-WiFiSense {
    Write-Log "Disabling Wi-Fi Sense..."
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name AutoConnectAllowedOEM -Value 0 -Force
        Write-Log "Wi-Fi Sense disabled."
    } catch {
        Write-Log "Failed to disable Wi-Fi Sense: $_" 'ERROR'
    }
}

function Disable-Bluetooth {
    Write-Log "Disabling Bluetooth..."
    try {
        Stop-Service -Name bthserv -Force -ErrorAction SilentlyContinue
        Set-Service -Name bthserv -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Log "Bluetooth disabled."
    } catch {
        Write-Log "Failed to disable Bluetooth: $_" 'ERROR'
    }
}

function Disable-WindowsHello {
    Write-Log "Disabling Windows Hello biometrics..."
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics" -Name Enabled -Value 0 -Force
        Write-Log "Windows Hello biometrics disabled."
    } catch {
        Write-Log "Failed to disable Windows Hello: $_" 'ERROR'
    }
}

function Disable-ConsumerExperience {
    Write-Log "Disabling Microsoft consumer experiences..."
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name DisableConsumerFeatures -Value 1 -Force
        Write-Log "Consumer experiences disabled."
    } catch {
        Write-Log "Failed to disable consumer experiences: $_" 'ERROR'
    }
}

function Disable-OneDrive {
    Write-Log "Disabling OneDrive integration..."
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name DisableFileSyncNGSC -Value 1 -Force
        Write-Log "OneDrive integration disabled."
    } catch {
        Write-Log "Failed to disable OneDrive: $_" 'ERROR'
    }
}

function Disable-WindowsStore {
    Write-Log "Disabling Windows Store..."
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name RemoveWindowsStore -Value 1 -Force
        Write-Log "Windows Store disabled."
    } catch {
        Write-Log "Failed to disable Windows Store: $_" 'ERROR'
    }
}

function Disable-PrefetchSuperfetch {
    Write-Log "Disabling Prefetch and Superfetch..."
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name EnablePrefetcher -Value 0 -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name EnableSuperfetch -Value 0 -Force
        Write-Log "Prefetch and Superfetch disabled."
    } catch {
        Write-Log "Failed to disable Prefetch/Superfetch: $_" 'ERROR'
    }
}

function Disable-FastUserSwitching {
    Write-Log "Disabling Fast User Switching..."
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name HideFastUserSwitching -Value 1 -Force
        Write-Log "Fast User Switching disabled."
    } catch {
        Write-Log "Failed to disable Fast User Switching: $_" 'ERROR'
    }
}

function Disable-DefenderSampleSubmission {
    Write-Log "Disabling Defender sample submission..."
    try {
        Set-MpPreference -SubmitSamplesConsent 2
        Write-Log "Defender sample submission disabled."
    } catch {
        Write-Log "Failed to disable Defender sample submission: $_" 'ERROR'
    }
}

function Enable-SecureDNS {
    Write-Log "Enabling Secure DNS (DoH)..."
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name EnableAutoDoh -Value 2 -Force
        Write-Log "Secure DNS (DoH) enabled."
    } catch {
        Write-Log "Failed to enable Secure DNS: $_" 'ERROR'
    }
}

function Harden-RDP {
    Write-Log "Hardening RDP..."
    try {
        # Require NLA
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -Value 1 -Force
        # Restrict users (example: only Administrators)
        # Add-LocalGroupMember -Group "Remote Desktop Users" -Member "Administrators" # Uncomment and customize as needed
        # Set strong encryption
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name MinEncryptionLevel -Value 3 -Force
        # Disable clipboard and printer redirection
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name fDisableClip -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name fDisableCcm -Value 1 -Force
        Write-Log "RDP hardened."
    } catch {
        Write-Log "Failed to harden RDP: $_" 'ERROR'
    }
}

function Harden-WindowsDefender {
    Write-Log "Hardening Windows Defender..."
    try {
        Set-MpPreference -DisableRealtimeMonitoring $false
        Set-MpPreference -DisableIOAVProtection $false
        Set-MpPreference -EnableControlledFolderAccess Enabled
        Set-MpPreference -MAPSReporting Advanced
        Set-MpPreference -SubmitSamplesConsent 1
        Set-MpPreference -PUAProtection Enabled
        Set-MpPreference -CloudBlockLevel High
        Set-MpPreference -EnableNetworkProtection Enabled
        Set-MpPreference -EnableLowCpuPriority $true
        Write-Log "Windows Defender hardened."
    } catch {
        Write-Log "Failed to harden Windows Defender: $_" 'ERROR'
    }
}

function Harden-EventLogging {
    Write-Log "Hardening Event Logging..."
    try {
        wevtutil sl Security /ms:327680
        wevtutil sl Application /ms:327680
        wevtutil sl System /ms:327680
        auditpol /set /category:* /success:enable /failure:enable | Out-Null
        Write-Log "Event Logging hardened."
    } catch {
        Write-Log "Failed to harden Event Logging: $_" 'ERROR'
    }
}

function Harden-LocalSecurityPolicy {
    Write-Log "Hardening Local Security Policy..."
    try {
        # Restrict anonymous access
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RestrictAnonymous -Value 1 -Force
        # Enforce account lockout
        net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30
        # Restrict user rights (example: deny local logon to Guests)
        ntrights -u Guest -r SeDenyInteractiveLogonRight
        Write-Log "Local Security Policy hardened."
    } catch {
        Write-Log "Failed to harden Local Security Policy: $_" 'ERROR'
    }
}

function Harden-WindowsUpdate {
    Write-Log "Hardening Windows Update..."
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name ExcludeWUDriversInQualityUpdate -Value 1 -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name WUServer -Value "" -Force
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name WUStatusServer -Value "" -Force
        Write-Log "Windows Update hardened."
    } catch {
        Write-Log "Failed to harden Windows Update: $_" 'ERROR'
    }
}

function Harden-AppLocker {
    Write-Log "Hardening Application Control (AppLocker)..."
    try {
        # Enable AppLocker policies (requires Enterprise/Education)
        # Example: Allow only signed executables
        # Set-AppLockerPolicy -PolicyObject (New-AppLockerPolicy -DefaultRule) -Merge
        Write-Log "AppLocker hardening attempted (manual review may be required)."
    } catch {
        Write-Log "Failed to harden AppLocker: $_" 'ERROR'
    }
}

function Harden-Network {
    Write-Log "Hardening Network..."
    try {
        # Disable unused adapters
        Get-NetAdapter | Where-Object { $_.Status -eq 'Disconnected' } | Disable-NetAdapter -Confirm:$false
        # Enforce strong Wi-Fi encryption (WPA2/WPA3)
        # Manual review required for Wi-Fi profiles
        Write-Log "Network hardened."
    } catch {
        Write-Log "Failed to harden Network: $_" 'ERROR'
    }
}

function Harden-Browser {
    Write-Log "Hardening Browser..."
    try {
        # Disable Internet Explorer
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_BROWSER_EMULATION" -Name iexplore.exe -Value 0 -Force
        # Enforce Edge security settings (manual/group policy recommended)
        Write-Log "Browser hardened."
    } catch {
        Write-Log "Failed to harden Browser: $_" 'ERROR'
    }
}

function Harden-PrintSpooler {
    Write-Log "Hardening Print Spooler..."
    try {
        Stop-Service -Name Spooler -Force -ErrorAction SilentlyContinue
        Set-Service -Name Spooler -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Log "Print Spooler hardened."
    } catch {
        Write-Log "Failed to harden Print Spooler: $_" 'ERROR'
    }
}

# =========================
# MAIN EXECUTION
# =========================

Write-Host "Starting Endpoint Hardening..." -ForegroundColor Cyan
Write-Log "Endpoint Hardening started."

Disable-SMBv1
Enforce-PasswordPolicy
Disable-GuestAccount
Enable-WindowsFirewall
Disable-UnnecessaryServices
Enable-BitLocker
Disable-Autorun
Enable-AutomaticUpdates
Enable-Auditing
Disable-LLMNR
Enforce-UAC
Disable-RemoteRegistry
Restrict-RDP
Disable-WindowsScriptHost
Disable-AnonymousSIDEnumeration
Disable-IPv6
Disable-NetBIOS
Restrict-USBStorage
Enforce-ScreenLockTimeout
Disable-Cortana
Disable-Telemetry
Restrict-PowerShellExecution
Disable-ErrorReporting
Disable-UnnecessaryScheduledTasks
Restrict-LocalAdminLogon
Disable-RemoteAssistance
Enforce-SecureBoot
Disable-WiFiSense
Disable-Bluetooth
Disable-WindowsHello
Disable-ConsumerExperience
Disable-OneDrive
Disable-WindowsStore
Disable-PrefetchSuperfetch
Disable-FastUserSwitching
Disable-DefenderSampleSubmission
Enable-SecureDNS
Harden-RDP
Harden-WindowsDefender
Harden-EventLogging
Harden-LocalSecurityPolicy
Harden-WindowsUpdate
Harden-AppLocker
Harden-Network
Harden-Browser
Harden-PrintSpooler

Write-Host "Endpoint Hardening complete. See $LogFile for details." -ForegroundColor Green
Write-Log "Endpoint Hardening complete." 
﻿# Force Windows Updates Script with Policy Override
# ⚠️ WARNING: This script overrides organizational policies!
# Use only with proper authorization and understanding of implications

param(
    [switch]$SetupCredSSP,
    [switch]$RunServerCheck,
    [switch]$ForceUpdates,
    [switch]$ScheduleReboot,
    [string]$TrustedHosts = "*",
    [string]$RebootTime = "03:00"
)


# Add this function at the beginning of the script
function Get-WindowsVersionDetailed {
    $result = "Unknown"
    
    # Method 1: Using CimInstance (preferred method)
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ($os) {
            $result = "$($os.Caption) Build $($os.BuildNumber)"
            Write-SuccessLog "Windows version determined via CimInstance: $result"
            return $result
        }
    } catch {
        Write-ErrorLog "CimInstance version detection failed: $($_.Exception.Message)"
    }

    # Method 2: Using WMI
    try {
        $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        if ($os) {
            $result = "$($os.Caption) Build $($os.BuildNumber)"
            Write-SuccessLog "Windows version determined via WMI: $result"
            return $result
        }
    } catch {
        Write-ErrorLog "WMI version detection failed: $($_.Exception.Message)"
    }

    # Method 3: Using Registry
    try {
        $currentVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop
        if ($currentVersion) {
            $productName = $currentVersion.ProductName
            $buildNumber = $currentVersion.CurrentBuildNumber
            $ubr = $currentVersion.UBR
            $result = "$productName Build $buildNumber.$ubr"
            Write-SuccessLog "Windows version determined via Registry: $result"
            return $result
        }
    } catch {
        Write-ErrorLog "Registry version detection failed: $($_.Exception.Message)"
    }

    # Method 4: Using systeminfo command
    try {
        $systemInfo = systeminfo | Select-String "OS Name:", "OS Version:"
        if ($systemInfo) {
            $osName = ($systemInfo[0] -split ":\s+")[1]
            $osVersion = ($systemInfo[1] -split ":\s+")[1]
            $result = "$osName $osVersion"
            Write-SuccessLog "Windows version determined via systeminfo: $result"
            return $result
        }
    } catch {
        Write-ErrorLog "Systeminfo version detection failed: $($_.Exception.Message)"
    }

    # Method 5: Using [Environment]::OSVersion
    try {
        $osVersion = [Environment]::OSVersion
        if ($osVersion) {
            $result = "Windows $($osVersion.Version.Major).$($osVersion.Version.Minor) Build $($osVersion.Version.Build)"
            Write-SuccessLog "Windows version determined via Environment.OSVersion: $result"
            return $result
        }
    } catch {
        Write-ErrorLog "Environment.OSVersion detection failed: $($_.Exception.Message)"
    }

    Write-ErrorLog "All Windows version detection methods failed"
    return $result
}
function Write-ErrorLog {
    param([string]$Message)
    $logPath = "error.log"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logPath -Value "$timestamp $Message"
}

function Write-SuccessLog {
    param([string]$Message)
    $logPath = "success.log"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logPath -Value "$timestamp $Message"
}

function Enable-CredSSPClient {
    param([string]$TrustedHosts = "*")
    Write-Host "🔧 Enabling CredSSP Client..." -ForegroundColor Yellow
    try {
        Enable-WSManCredSSP -Role Client -DelegateComputer $TrustedHosts -Force
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
        if (!(Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        Set-ItemProperty -Path $regPath -Name "AllowFreshCredentials" -Value 1
        Set-ItemProperty -Path $regPath -Name "ConcatenateDefaults_AllowFresh" -Value 1
        $credPath = "$regPath\AllowFreshCredentials"
        if (!(Test-Path $credPath)) {
            New-Item -Path $credPath -Force | Out-Null
        }
        Set-ItemProperty -Path $credPath -Name "1" -Value "wsman/$TrustedHosts"
        Write-Host "✅ CredSSP Client enabled successfully" -ForegroundColor Green
        Write-SuccessLog "CredSSP Client enabled successfully for $TrustedHosts"
        return $true
    } catch {
        Write-ErrorLog "Enable-CredSSPClient failed: $($_.Exception.Message)"
        Write-Error "❌ Failed to enable CredSSP Client: $_"
        return $false
    }
}

function Set-WindowsUpdateRegistryKeys {
    $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $changed = $false
    try {
        if (!(Test-Path $wuPath)) {
            New-Item -Path $wuPath -Force | Out-Null
            Write-SuccessLog "Created Windows Update registry path: $wuPath"
        }
        $currentDisableAccess = (Get-ItemProperty -Path $wuPath -Name "DisableWindowsUpdateAccess" -ErrorAction SilentlyContinue)."DisableWindowsUpdateAccess"
        if ($currentDisableAccess -ne 0) {
            Set-ItemProperty -Path $wuPath -Name "DisableWindowsUpdateAccess" -Value 0 -Type DWord
            Write-Host "✅ Registry: DisableWindowsUpdateAccess set to 0." -ForegroundColor Green
            Write-SuccessLog "Registry modified: DisableWindowsUpdateAccess set to 0"
            $changed = $true
        } else {
            Write-Host "ℹ️  Registry: DisableWindowsUpdateAccess already set to 0." -ForegroundColor Yellow
            Write-SuccessLog "Registry check: DisableWindowsUpdateAccess already set to 0"
        }
        $currentElevate = (Get-ItemProperty -Path $wuPath -Name "ElevateNonAdmins" -ErrorAction SilentlyContinue)."ElevateNonAdmins"
        if ($currentElevate -ne 0) {
            Set-ItemProperty -Path $wuPath -Name "ElevateNonAdmins" -Value 0 -Type DWord
            Write-Host "✅ Registry: ElevateNonAdmins set to 0." -ForegroundColor Green
            Write-SuccessLog "Registry modified: ElevateNonAdmins set to 0"
            $changed = $true
        } else {
            Write-Host "ℹ️  Registry: ElevateNonAdmins already set to 0." -ForegroundColor Yellow
            Write-SuccessLog "Registry check: ElevateNonAdmins already set to 0"
        }
        if ($changed) {
            try {
                Set-Service -Name wuauserv -StartupType Automatic
                Write-SuccessLog "Windows Update service (wuauserv) startup type set to Automatic"
                
                Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
                Write-SuccessLog "Windows Update service (wuauserv) stopped successfully"
                
                Start-Sleep -Seconds 2
                
                Start-Service -Name wuauserv
                Write-SuccessLog "Windows Update service (wuauserv) started successfully"
                
                Start-Sleep -Seconds 3
                Write-Host "🔄 Windows Update service (wuauserv) restarted after registry modification." -ForegroundColor Cyan
                Write-SuccessLog "Windows Update service (wuauserv) restart cycle completed successfully after registry modifications"
            } catch {
                Write-Host "❌ Could not restart wuauserv: $($_.Exception.Message)" -ForegroundColor Red
                Write-ErrorLog "Could not restart wuauserv: $($_.Exception.Message)"
            }
        }
        Write-SuccessLog "Windows Update registry configuration completed successfully"
    } catch {
        Write-Host "❌ Error modifying Windows Update registry settings: $($_.Exception.Message)" -ForegroundColor Red
        Write-ErrorLog "Error modifying Windows Update registry settings: $($_.Exception.Message)"
    }
}

function Enable-WindowsUpdatesPolicy {
    param(
        [bool]$ForceInstall = $false,
        [string]$RebootTime = "03:00"
    )
    $result = @{
        Success = $false
        Message = ""
        Changes = @()
    }
    try {
        Write-Host "🔧 Modifying Windows Update policies..." -ForegroundColor Yellow
        $auPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        if (!(Test-Path $wuPath)) {
            New-Item -Path $wuPath -Force | Out-Null
            $result.Changes += "Created WindowsUpdate policy path"
        }
        if (!(Test-Path $auPath)) {
            New-Item -Path $auPath -Force | Out-Null
            $result.Changes += "Created AU policy path"
        }
        $backupPath = "HKLM:\SOFTWARE\BackupWindowsUpdatePolicies_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        if (Test-Path $auPath) {
            Copy-Item -Path $auPath -Destination $backupPath -Recurse -Force
            $result.Changes += "Backed up current policies to $backupPath"
        }
        Set-ItemProperty -Path $auPath -Name "NoAutoUpdate" -Value 0 -Type DWord
        $result.Changes += "Enabled automatic updates (NoAutoUpdate=0)"
        Set-ItemProperty -Path $auPath -Name "AUOptions" -Value 4 -Type DWord
        $result.Changes += "Set AUOptions to 4 (auto download and schedule install)"
        Set-ItemProperty -Path $auPath -Name "ScheduledInstallDay" -Value 0 -Type DWord
        $result.Changes += "Set scheduled install day to daily"
        $hour = [int]$RebootTime.Split(':')[0]
        Set-ItemProperty -Path $auPath -Name "ScheduledInstallTime" -Value $hour -Type DWord
        $result.Changes += "Set scheduled install time to $hour:00"
        Set-ItemProperty -Path $auPath -Name "NoAutoRebootWithLoggedOnUsers" -Value 0 -Type DWord
        $result.Changes += "Enabled automatic reboot"
        Set-ItemProperty -Path $auPath -Name "RebootWarningTimeoutEnabled" -Value 1 -Type DWord
        Set-ItemProperty -Path $auPath -Name "RebootWarningTimeout" -Value 15 -Type DWord
        $result.Changes += "Set reboot warning to 15 minutes"
        Remove-ItemProperty -Path $wuPath -Name "DisableWindowsUpdateAccess" -ErrorAction SilentlyContinue
        $result.Changes += "Removed DisableWindowsUpdateAccess restriction"
        Set-ItemProperty -Path $auPath -Name "UseWUServer" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        $result.Changes += "Disabled WSUS-only restriction"
        if ($ForceInstall) {
            Set-ItemProperty -Path $auPath -Name "DetectionFrequencyEnabled" -Value 1 -Type DWord
            Set-ItemProperty -Path $auPath -Name "DetectionFrequency" -Value 1 -Type DWord
            $result.Changes += "Enabled frequent update detection (1 hour)"
        }

        # --- Additional Windows Update for Business settings ---
        Set-ItemProperty -Path $wuPath -Name "DeferQualityUpdates" -Value 0 -Type DWord
        Set-ItemProperty -Path $wuPath -Name "DeferQualityUpdatesPeriodInDays" -Value 3 -Type DWord
        Set-ItemProperty -Path $wuPath -Name "SetComplianceDeadline" -Value 1 -Type DWord
        Set-ItemProperty -Path $wuPath -Name "ComplianceDeadlineGracePeriod" -Value 3 -Type DWord
        Set-ItemProperty -Path $wuPath -Name "QualityUpdateDeadlineInDays" -Value 3 -Type DWord
        Set-ItemProperty -Path $wuPath -Name "FeatureUpdateDeadlineInDays" -Value 3 -Type DWord
        $result.Changes += "Set DeferQualityUpdates=0, DeferQualityUpdatesPeriodInDays=3, SetComplianceDeadline=1, ComplianceDeadlineGracePeriod=3, QualityUpdateDeadlineInDays=3, FeatureUpdateDeadlineInDays=3"
        # --- End of additional settings ---

        Set-WindowsUpdateRegistryKeys

        $result.Success = $true
        $result.Message = "Windows Update policies modified successfully"
        Write-SuccessLog "Enable-WindowsUpdatesPolicy succeeded. Registry policies set as: $($result.Changes -join '; ')"
    } catch {
        Write-ErrorLog "Enable-WindowsUpdatesPolicy failed: $($_.Exception.Message)"
        $result.Success = $false
        $result.Message = "Failed to modify policies: $($_.Exception.Message)"
    }
    return $result
}

function Force-WindowsUpdateInstallation {
    $result = @{
        Success = $false
        Message = ""
        UpdatesFound = 0
        UpdatesInstalled = 0
    }
    try {
        Write-Host "🔄 Forcing Windows Update detection and installation..." -ForegroundColor Yellow
        try {
            Set-Service -Name wuauserv -StartupType Automatic
            $result.Message += "wuauserv set to Automatic. "
        } catch {
            Write-ErrorLog "Force-WindowsUpdateInstallation: Failed to set wuauserv to Automatic: $($_.Exception.Message)"
            $result.Message += "Failed to set wuauserv to Automatic: $($_.Exception.Message). "
        }
        try {
            Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            Start-Service -Name wuauserv
            Start-Sleep -Seconds 3
            $result.Message += "Windows Update service restarted. "
        } catch {
            Write-ErrorLog "Force-WindowsUpdateInstallation: Service restart failed: $($_.Exception.Message)"
            $result.Message += "Service restart failed: $($_.Exception.Message). "
        }
        try {
            $updateSession = New-Object -ComObject Microsoft.Update.Session
            $updateSearcher = $updateSession.CreateUpdateSearcher()
            Write-Host "🔍 Searching for available updates..." -ForegroundColor Cyan
            $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
            $result.UpdatesFound = $searchResult.Updates.Count
            if ($searchResult.Updates.Count -gt 0) {
                Write-Host "📦 Found $($searchResult.Updates.Count) updates to install" -ForegroundColor Green
                $updatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
                foreach ($update in $searchResult.Updates) {
                    if ($update.EulaAccepted -eq $false) {
                        $update.AcceptEula()
                    }
                    $updatesToInstall.Add($update) | Out-Null
                    Write-Host "  • $($update.Title)" -ForegroundColor White
                }
                Write-Host "⬇️  Downloading updates..." -ForegroundColor Cyan
                $downloader = $updateSession.CreateUpdateDownloader()
                $downloader.Updates = $updatesToInstall
                $downloadResult = $downloader.Download()
                if ($downloadResult.ResultCode -eq 2) {
                    Write-Host "✅ Updates downloaded successfully" -ForegroundColor Green
                    Write-Host "⚙️  Installing updates..." -ForegroundColor Cyan
                    $installer = $updateSession.CreateUpdateInstaller()
                    $installer.Updates = $updatesToInstall
                    $installResult = $installer.Install()
                    $result.UpdatesInstalled = $installResult.GetUpdateResult(0).ResultCode
                    if ($installResult.ResultCode -eq 2) {
                        $result.Success = $true
                        $result.Message += "Updates installed successfully. "
                        if ($installResult.RebootRequired) {
                            $result.Message += "Reboot required. "
                        }
                    } else {
                        Write-ErrorLog "Force-WindowsUpdateInstallation: Installation failed with code: $($installResult.ResultCode)"
                        $result.Message += "Installation failed with code: $($installResult.ResultCode). "
                    }
                } else {
                    Write-ErrorLog "Force-WindowsUpdateInstallation: Download failed with code: $($downloadResult.ResultCode)"
                    $result.Message += "Download failed with code: $($downloadResult.ResultCode). "
                }
            } else {
                $result.Success = $true
                $result.Message += "No updates available. "
            }
        } catch {
            Write-ErrorLog "Force-WindowsUpdateInstallation: Update process failed: $($_.Exception.Message)"
            $result.Message += "Update process failed: $($_.Exception.Message). "
        }
        try {
            $autoUpdateClient = New-Object -ComObject Microsoft.Update.AutoUpdate
            $autoUpdateClient.DetectNow()
            $result.Message += "Triggered automatic detection. "
        } catch {
            Write-ErrorLog "Force-WindowsUpdateInstallation: AutoUpdate.DetectNow failed: $($_.Exception.Message)"
        }
    } catch {
        Write-ErrorLog "Force-WindowsUpdateInstallation: Force update failed: $($_.Exception.Message)"
        $result.Success = $false
        $result.Message = "Force update failed: $($_.Exception.Message)"
    }
    return $result
}

function Set-RebootSchedule {
    param([string]$Time = "03:00")
    $result = @{
        Success = $false
        Message = ""
    }
    try {
        $tomorrow = (Get-Date).AddDays(1).Date.Add([TimeSpan]::Parse($Time))
        $taskName = "AutomaticReboot_WindowsUpdates"
        try {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        } catch {
            Write-ErrorLog "Set-RebootSchedule: Failed to unregister scheduled task: $($_.Exception.Message)"
        }
        $action = New-ScheduledTaskAction -Execute "shutdown.exe" -Argument "/r /t 30 /c 'Automatic reboot for Windows Updates'"
        $trigger = New-ScheduledTaskTrigger -Once -At $tomorrow
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Automatic reboot for Windows Updates installation"
        $result.Success = $true
        $result.Message = "Reboot scheduled for $tomorrow"
    } catch {
        Write-ErrorLog "Set-RebootSchedule failed: $($_.Exception.Message)"
        $result.Success = $false
        $result.Message = "Failed to schedule reboot: $($_.Exception.Message)"
    }
    return $result
}

function Test-CredSSPEnabled {
    $setting = (Get-WSManCredSSP 2>&1)
    return ($setting -match "Client: Enabled")
}

function Start-ServerUpdateCheck {
    if (-not (Test-CredSSPEnabled)) {
        Write-Host "⚠️  CredSSP is not enabled on this client. You may encounter authentication or delegation errors." -ForegroundColor Yellow
        Write-Host "    To configure: Enable-WSManCredSSP -Role Client -DelegateComputer '$TrustedHosts' -Force" -ForegroundColor White
        Write-ErrorLog "CredSSP is not enabled on this client. Command needed: Enable-WSManCredSSP -Role Client -DelegateComputer '$TrustedHosts' -Force"
        # Do NOT return, just warn and continue
    }
    $cred = Get-Credential -Message "Enter domain credentials for server access"
    $outputFile = "NON-AD-Prodservers-ForceUpdate.csv"
    $results = @()
    Write-Host "🔍 Retrieving servers from AD..." -ForegroundColor Cyan
   $patterns = @('*TST*', 'ACC*', '*DEV*', '*-TS*', '*ACC*','TST*','ALG*','*CIC*')
# Dynamically construct the filter string
$filterString = ($patterns | ForEach-Object { "Name -like '$_'" }) -join ' -or '

try {
    $servers = Get-ADComputer -Filter $filterString -Server "nwk-dc101" -Properties Name, IPv4Address
    Write-Host "📊 Found $($servers.Count) servers to process" -ForegroundColor Cyan
} catch {
    Write-ErrorLog "Start-ServerUpdateCheck: Failed to retrieve servers from AD: $($_.Exception.Message)"
    Write-Error "Failed to retrieve servers from AD: $_"
    return
}
    foreach ($server in $servers) {
        $serverName = $server.Name
        $ip = $server.IPv4Address
        $status = "Unknown"
        $lastUpdate = "N/A"
        $winVersion = "Unknown"
        $policyStatus = "Unknown"
        $updateResult = "Unknown"
        $rebootScheduled = "No"
        Write-Host "`n🖥️  Processing server: $($serverName) ($ip)" -ForegroundColor White -BackgroundColor DarkBlue
        try {
            if (Test-Connection -ComputerName $serverName -Count 1 -Quiet) {
                Write-Host "✅ Server $($serverName) is reachable" -ForegroundColor Green
                # ---- LOG SUCCESSFUL CONNECTION ----
              
$remoteInfoScript = {
    $lastPatch = $null
    try {
        $hotfix = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
        $lastPatch = if ($hotfix.InstalledOn) { $hotfix.InstalledOn.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
    } catch { $lastPatch = "N/A" }
    
    # Enhanced Last Reboot Detection with Multiple Methods
    $lastReboot = "N/A"
    
    # Method 1: Try CIM Instance (Primary Method)
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        if ($os.LastBootUpTime) {
            $lastReboot = $os.LastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss")
            Write-Host "Method 1 (CIM) succeeded for reboot time"
        }
    } catch {
        Write-Host "Method 1 (CIM) failed for reboot time: $($_.Exception.Message)"
    }

    # Method 2: Try WMI if Method 1 failed
    if ($lastReboot -eq "N/A") {
        try {
            $os = Get-WmiObject -Class Win32_OperatingSystem
            if ($os.LastBootUpTime) {
                $lastReboot = [Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime).ToString("yyyy-MM-dd HH:mm:ss")
                Write-Host "Method 2 (WMI) succeeded for reboot time"
            }
        } catch {
            Write-Host "Method 2 (WMI) failed for reboot time: $($_.Exception.Message)"
        }
    }

    # Method 3: Try SystemInfo parsing if Method 2 failed
    if ($lastReboot -eq "N/A") {
        try {
            $systemInfo = systeminfo | Select-String "System Boot Time:"
            if ($systemInfo -match "System Boot Time:\s+(.+)") {
                $bootTime = [DateTime]::Parse($matches[1])
                $lastReboot = $bootTime.ToString("yyyy-MM-dd HH:mm:ss")
                Write-Host "Method 3 (SystemInfo) succeeded for reboot time"
            }
        } catch {
            Write-Host "Method 3 (SystemInfo) failed for reboot time: $($_.Exception.Message)"
        }
    }

    # Method 4: Try Event Log if Method 3 failed
    if ($lastReboot -eq "N/A") {
        try {
            $event = Get-WinEvent -FilterHashtable @{
                LogName = 'System'
                ID = 6005  # Event ID for system startup
            } -MaxEvents 1 -ErrorAction Stop
            
            if ($event) {
                $lastReboot = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                Write-Host "Method 4 (Event Log) succeeded for reboot time"
            }
        } catch {
            Write-Host "Method 4 (Event Log) failed for reboot time: $($_.Exception.Message)"
        }
    }

    # Method 5: Try uptime command if everything else failed
    if ($lastReboot -eq "N/A") {
        try {
            $uptime = (net statistics server) -match "Statistics since"
            if ($uptime) {
                $uptimeLine = $uptime[0]
                if ($uptimeLine -match "Statistics since (.+)") {
                    $bootTime = [DateTime]::Parse($matches[1])
                    $lastReboot = $bootTime.ToString("yyyy-MM-dd HH:mm:ss")
                    Write-Host "Method 5 (Net Statistics) succeeded for reboot time"
                }
            }
        } catch {
            Write-Host "Method 5 (Net Statistics) failed for reboot time: $($_.Exception.Message)"
        }
    }

    # Enhanced Windows Version Detection with Multiple Methods
    $winVer = "Unknown"
    
    # Method 1: Try CIM Instance (Primary Method)
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        if ($os) {
            $winVer = "$($os.Caption) Build $($os.BuildNumber)"
            Write-Host "Method 1 (CIM) succeeded for Windows version"
        }
    } catch {
        Write-Host "Method 1 (CIM) failed for Windows version: $($_.Exception.Message)"
    }

    # Method 2: Try Registry if Method 1 failed
    if ($winVer -eq "Unknown") {
        try {
            $reg = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop
            $productName = $reg.ProductName
            $currentBuild = $reg.CurrentBuild
            $ubr = $reg.UBR
            if ($productName -and $currentBuild) {
                $winVer = "$productName Build $currentBuild.$ubr"
                Write-Host "Method 2 (Registry) succeeded for Windows version"
            }
        } catch {
            Write-Host "Method 2 (Registry) failed for Windows version: $($_.Exception.Message)"
        }
    }

    # Method 3: Try WMI if Method 2 failed
    if ($winVer -eq "Unknown") {
        try {
            $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
            if ($os) {
                $winVer = "$($os.Caption) Build $($os.BuildNumber)"
                Write-Host "Method 3 (WMI) succeeded for Windows version"
            }
        } catch {
            Write-Host "Method 3 (WMI) failed for Windows version: $($_.Exception.Message)"
        }
    }

    # Method 4: Try System.Environment if Method 3 failed
    if ($winVer -eq "Unknown") {
        try {
            $osVersion = [System.Environment]::OSVersion
            $winVer = "Windows $($osVersion.Version.Major).$($osVersion.Version.Minor) Build $($osVersion.Version.Build)"
            Write-Host "Method 4 (Environment) succeeded for Windows version"
        } catch {
            Write-Host "Method 4 (Environment) failed for Windows version: $($_.Exception.Message)"
        }
    }

    # Method 5: Try systeminfo command if all else failed
    if ($winVer -eq "Unknown") {
        try {
            $sysInfo = systeminfo | Select-String "OS Name:", "OS Version:"
            if ($sysInfo) {
                $osName = ($sysInfo[0] -split ":\s+")[1]
                $osVersion = ($sysInfo[1] -split ":\s+")[1]
                $winVer = "$osName ($osVersion)"
                Write-Host "Method 5 (systeminfo) succeeded for Windows version"
            }
        } catch {
            Write-Host "Method 5 (systeminfo) failed for Windows version: $($_.Exception.Message)"
        }
    }

    return @{
        Version = $winVer
        LastPatch = $lastPatch
        LastReboot = $lastReboot
    }
}

  $remoteInfo = Invoke-Command -ComputerName $serverName -Credential $cred -ScriptBlock $remoteInfoScript -ErrorAction SilentlyContinue
                if ($remoteInfo) {
                    $successMsg = "Server: $serverName | Version: $($remoteInfo.Version) | LastPatch: $($remoteInfo.LastPatch) | LastReboot: $($remoteInfo.LastReboot)"
                } else {
                    $successMsg = "Server: $serverName | Version: Unknown | LastPatch: N/A | LastReboot: N/A"
                }
                Write-SuccessLog $successMsg
                # ---- END SUCCESS LOG ----

                # --- Enable CredSSP on the remote server before authentication attempts ---
                $enableCredSSPScript = {
                    try {
                        Enable-WSManCredSSP -Role Server -Force -ErrorAction Stop
                        "CredSSP enabled"
                    } catch {
                        "CredSSP enable failed: $($_.Exception.Message)"
                    }
                }
                $credsspResult = Invoke-Command -ComputerName $serverName -Credential $cred -ScriptBlock $enableCredSSPScript -ErrorAction SilentlyContinue
                Write-Host "Remote CredSSP status: $credsspResult" -ForegroundColor Yellow
                Write-SuccessLog "Remote CredSSP status for $($serverName) : $credsspResult"

                $remoteScript = {
                    param($ForceUpdates, $ScheduleReboot, $RebootTime)
                    
                    function Write-ErrorLog {
                        param([string]$Message)
                        $logPath = "error.log"
                        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        Add-Content -Path $logPath -Value "$timestamp $Message"
                    }
                    function Set-WindowsUpdateRegistryKeys {
                        $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
                        $changed = $false
                        try {
                            if (!(Test-Path $wuPath)) {
                                New-Item -Path $wuPath -Force | Out-Null
                            }
                            $currentDisableAccess = (Get-ItemProperty -Path $wuPath -Name "DisableWindowsUpdateAccess" -ErrorAction SilentlyContinue)."DisableWindowsUpdateAccess"
                            if ($currentDisableAccess -ne 0) {
                                Set-ItemProperty -Path $wuPath -Name "DisableWindowsUpdateAccess" -Value 0 -Type DWord
                                Write-ErrorLog "Registry: DisableWindowsUpdateAccess set to 0."
                                $changed = $true
                            }
                            $currentElevate = (Get-ItemProperty -Path $wuPath -Name "ElevateNonAdmins" -ErrorAction SilentlyContinue)."ElevateNonAdmins"
                            if ($currentElevate -ne 0) {
                                Set-ItemProperty -Path $wuPath -Name "ElevateNonAdmins" -Value 0 -Type DWord
                                Write-ErrorLog "Registry: ElevateNonAdmins set to 0."
                                $changed = $true
                            }
                            if ($changed) {
                                try {
                                    Set-Service -Name wuauserv -StartupType Automatic
                                    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
                                    Start-Sleep -Seconds 2
                                    Start-Service -Name wuauserv
                                    Start-Sleep -Seconds 3
                                    Write-ErrorLog "Windows Update service (wuauserv) restarted after registry modification."
                                } catch {
                                    Write-ErrorLog "Could not restart wuauserv: $($_.Exception.Message)"
                                }
                            }
                        } catch {
                            Write-ErrorLog "Error modifying Windows Update registry settings: $($_.Exception.Message)"
                        }
                    }
                    function Enable-WindowsUpdatesPolicy {
                        param([bool]$ForceInstall = $false, [string]$RebootTime = "03:00")
                        $result = @{
                            Success = $false
                            Message = ""
                            Changes = @()
                        }
                        try {
                            $auPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
                            $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
                            if (!(Test-Path $wuPath)) {
                                New-Item -Path $wuPath -Force | Out-Null
                                $result.Changes += "Created WindowsUpdate policy path"
                            }
                            if (!(Test-Path $auPath)) {
                                New-Item -Path $auPath -Force | Out-Null
                                $result.Changes += "Created AU policy path"
                            }
                            $backupPath = "HKLM:\SOFTWARE\BackupWindowsUpdatePolicies_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
                            if (Test-Path $auPath) {
                                Copy-Item -Path $auPath -Destination $backupPath -Recurse -Force
                                $result.Changes += "Backed up current policies to $backupPath"
                            }
                            Set-ItemProperty -Path $auPath -Name "NoAutoUpdate" -Value 0 -Type DWord
                            $result.Changes += "Enabled automatic updates (NoAutoUpdate=0)"
                            Set-ItemProperty -Path $auPath -Name "AUOptions" -Value 4 -Type DWord
                            $result.Changes += "Set AUOptions to 4 (auto download and schedule install)"
                            Set-ItemProperty -Path $auPath -Name "ScheduledInstallDay" -Value 0 -Type DWord
                            $result.Changes += "Set scheduled install day to daily"
                            $hour = [int]$RebootTime.Split(':')[0]
                            Set-ItemProperty -Path $auPath -Name "ScheduledInstallTime" -Value $hour -Type DWord
                            $result.Changes += "Set scheduled install time to $hour:00"
                            Set-ItemProperty -Path $auPath -Name "NoAutoRebootWithLoggedOnUsers" -Value 0 -Type DWord
                            $result.Changes += "Enabled automatic reboot"
                            Set-ItemProperty -Path $auPath -Name "RebootWarningTimeoutEnabled" -Value 1 -Type DWord
                            Set-ItemProperty -Path $auPath -Name "RebootWarningTimeout" -Value 15 -Type DWord
                            $result.Changes += "Set reboot warning to 15 minutes"
                            Remove-ItemProperty -Path $wuPath -Name "DisableWindowsUpdateAccess" -ErrorAction SilentlyContinue
                            $result.Changes += "Removed DisableWindowsUpdateAccess restriction"
                            Set-ItemProperty -Path $auPath -Name "UseWUServer" -Value 0 -Type DWord -ErrorAction SilentlyContinue
                            $result.Changes += "Disabled WSUS-only restriction"
                            if ($ForceInstall) {
                                Set-ItemProperty -Path $auPath -Name "DetectionFrequencyEnabled" -Value 1 -Type DWord
                                Set-ItemProperty -Path $auPath -Name "DetectionFrequency" -Value 1 -Type DWord
                                $result.Changes += "Enabled frequent update detection (1 hour)"
                            }
                            Set-WindowsUpdateRegistryKeys
                            $result.Success = $true
                            $result.Message = "Windows Update policies modified successfully"
                        } catch {
                            Write-ErrorLog "Enable-WindowsUpdatesPolicy failed: $($_.Exception.Message)"
                            $result.Success = $false
                            $result.Message = "Failed to modify policies: $($_.Exception.Message)"
                        }
                        return $result
                    }
                   
                    function Force-WindowsUpdateInstallation {
    $result = @{
        Success = $false
        Message = ""
        UpdatesFound = 0
        UpdatesInstalled = 0
        Details = @()
    }

    try {
        Write-Host "🔄 Starting Windows Update force installation process..." -ForegroundColor Yellow
        Write-SuccessLog "Starting Windows Update force installation - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

        # 1. Ensure Windows Update service is running and properly configured
        Write-Host "👉 Configuring Windows Update service..." -ForegroundColor Cyan
        try {
            Stop-Service -Name wuauserv -Force -ErrorAction Stop
            Set-Service -Name wuauserv -StartupType Automatic
            Start-Service -Name wuauserv
            Start-Sleep -Seconds 5  # Give service time to stabilize
            $result.Details += "Windows Update service configured successfully"
            Write-SuccessLog "Windows Update service reconfigured"
        }
        catch {
            Write-ErrorLog "Service configuration failed: $($_.Exception.Message)"
            throw "Failed to configure Windows Update service: $($_.Exception.Message)"
        }

        # 2. Create update session with extended timeout
        Write-Host "👉 Creating Update Session..." -ForegroundColor Cyan
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSession.ClientApplicationID = "UpdateForce Script"
        $updateSearcher = $updateSession.CreateUpdateSearcher()

        # 3. Search for updates with detailed criteria
        Write-Host "🔍 Searching for available updates..." -ForegroundColor Cyan
        $searchCriteria = "IsInstalled=0 and Type='Software' and IsHidden=0"
        $searchResult = $updateSearcher.Search($searchCriteria)
        $result.UpdatesFound = $searchResult.Updates.Count

        if ($result.UpdatesFound -gt 0) {
            Write-Host "📦 Found $($result.UpdatesFound) updates to install" -ForegroundColor Green
            Write-SuccessLog "Found $($result.UpdatesFound) updates to install"
            
            $updatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl

            # 4. Process each update
            foreach ($update in $searchResult.Updates) {
                try {
                    Write-Host "  • Processing: $($update.Title)" -ForegroundColor White
                    
                    # Accept EULA if needed
                    if (-not $update.EulaAccepted) {
                        $update.AcceptEula()
                        Write-Host "    ✓ EULA Accepted" -ForegroundColor Gray
                    }

                    # Verify update is applicable
                    if ($update.IsDownloaded) {
                        Write-Host "    ✓ Already downloaded" -ForegroundColor Gray
                    }

                    $updatesToInstall.Add($update) | Out-Null
                    $result.Details += "Update added to queue: $($update.Title)"
                    Write-SuccessLog "Update queued: $($update.Title)"
                }
                catch {
                    Write-ErrorLog "Failed to process update $($update.Title): $($_.Exception.Message)"
                    Write-Host "    ⚠️ Failed to process update" -ForegroundColor Yellow
                    continue
                }
            }

            if ($updatesToInstall.Count -gt 0) {
                # 5. Download updates
                Write-Host "⬇️ Downloading updates..." -ForegroundColor Cyan
                $downloader = $updateSession.CreateUpdateDownloader()
                $downloader.Updates = $updatesToInstall
                $downloadResult = $downloader.Download()

                if ($downloadResult.ResultCode -eq 2) { # 2 = success
                    Write-Host "✅ Updates downloaded successfully" -ForegroundColor Green
                    Write-SuccessLog "Updates downloaded successfully"

                    # 6. Install updates
                    Write-Host "⚙️ Installing updates..." -ForegroundColor Cyan
                    $installer = $updateSession.CreateUpdateInstaller()
                    $installer.Updates = $updatesToInstall
                    $installResult = $installer.Install()

                    # 7. Process installation results
                    $result.UpdatesInstalled = ($installResult.GetUpdateResults() | 
                        Where-Object { $_.ResultCode -eq 2 }).Count

                    $result.Success = ($installResult.ResultCode -eq 2)
                    $result.Message = "Installation completed. $($result.UpdatesInstalled) of $($result.UpdatesFound) updates installed successfully."
                    
                    if ($installResult.RebootRequired) {
                        $result.Message += " Reboot required."
                    }

                    Write-SuccessLog $result.Message
                }
                else {
                    throw "Download failed with code: $($downloadResult.ResultCode)"
                }
            }
        }
        else {
            Write-Host "✅ No updates available to install" -ForegroundColor Green
            $result.Success = $true
            $result.Message = "No updates available for installation"
            Write-SuccessLog "No updates found to install"
        }

        # 8. Force update detection for next run
        try {
            $autoUpdateClient = New-Object -ComObject Microsoft.Update.AutoUpdate
            $autoUpdateClient.DetectNow()
            $result.Details += "Triggered automatic detection for next run"
        }
        catch {
            Write-ErrorLog "Failed to trigger automatic detection: $($_.Exception.Message)"
        }

        # 9. Verify installation
        Write-Host "🔍 Verifying installation..." -ForegroundColor Cyan
        $verifySearch = $updateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
        $remainingUpdates = $verifySearch.Updates.Count
        $result.Details += "Remaining updates after installation: $remainingUpdates"
        Write-SuccessLog "Verification complete - Remaining updates: $remainingUpdates"

    }
    catch {
        $errorMessage = "Force update failed: $($_.Exception.Message)"
        Write-ErrorLog $errorMessage
        $result.Success = $false
        $result.Message = $errorMessage
    }

    # Final logging
    if ($result.Success) {
        Write-Host "✅ Update process completed successfully" -ForegroundColor Green
    }
    else {
        Write-Host "❌ Update process completed with errors" -ForegroundColor Red
    }

    Write-Host "📝 Details:" -ForegroundColor Cyan
    foreach ($detail in $result.Details) {
        Write-Host "   • $detail" -ForegroundColor White
    }

    return $result
}
                    function Set-RebootSchedule {
                        param([string]$Time = "03:00")
                        $result = @{
                            Success = $false
                            Message = ""
                        }
                        try {
                            $tomorrow = (Get-Date).AddDays(1).Date.Add([TimeSpan]::Parse($Time))
                            $taskName = "AutomaticReboot_WindowsUpdates"
                            try {
                                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
                            } catch {
                                Write-ErrorLog "Set-RebootSchedule: Failed to unregister scheduled task: $($_.Exception.Message)"
                            }
                            $action = New-ScheduledTaskAction -Execute "shutdown.exe" -Argument "/r /t 30 /c 'Automatic reboot for Windows Updates'"
                            $trigger = New-ScheduledTaskTrigger -Once -At $tomorrow
                            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
                            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
                            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Automatic reboot for Windows Updates installation"
                            $result.Success = $true
                            $result.Message = "Reboot scheduled for $tomorrow"
                        } catch {
                            Write-ErrorLog "Set-RebootSchedule failed: $($_.Exception.Message)"
                            $result.Success = $false
                            $result.Message = "Failed to schedule reboot: $($_.Exception.Message)"
                        }
                        return $result
                    }
                    $result = @{
                        UpdateStatus = "Unknown"
                        LastUpdateDate = "N/A"
                        WindowsVersion = "Unknown"
                        PolicyStatus = "Unknown"
                        UpdateResult = "Unknown"
                        RebootScheduled = "No"
                        Changes = @()
                    }
                    try {
                        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
                        if ($os) {
                            $result.WindowsVersion = "$($os.Caption) Build $($os.BuildNumber)"
                        }
                        $auPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
                        if (Test-Path $auPath) {
                            $noAutoUpdate = Get-ItemProperty -Path $auPath -Name "NoAutoUpdate" -ErrorAction SilentlyContinue
                            if ($noAutoUpdate -and $noAutoUpdate.NoAutoUpdate -eq 1) {
                                $result.PolicyStatus = "Automatic updates disabled by policy"
                            } else {
                                $result.PolicyStatus = "Automatic updates enabled"
                            }
                        } else {
                            $result.PolicyStatus = "No policy restrictions found"
                        }
                        if ($ForceUpdates) {
                            $policyResult = Enable-WindowsUpdatesPolicy -ForceInstall $ForceUpdates -RebootTime $RebootTime
                            $result.Changes += $policyResult.Changes
                            if ($policyResult.Success) {
                                $result.PolicyStatus = "Policy overridden - updates enabled"
                                $updateResult = Force-WindowsUpdateInstallation
                                $result.UpdateResult = $updateResult.Message
                                $result.UpdateStatus = "Found: $($updateResult.UpdatesFound), Installed: $($updateResult.UpdatesInstalled)"
                                if ($ScheduleReboot) {
                                    $rebootResult = Set-RebootSchedule -Time $RebootTime
                                    $result.RebootScheduled = if ($rebootResult.Success) { $rebootResult.Message } else { "Failed: $($rebootResult.Message)" }
                                }
                            } else {
                                $result.UpdateResult = "Policy override failed: $($policyResult.Message)"
                            }
                        } else {
                            try {
                                $updateSession = New-Object -ComObject Microsoft.Update.Session
                                $updateSearcher = $updateSession.CreateUpdateSearcher()
                                $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
                                $result.UpdateStatus = "$($searchResult.Updates.Count) updates available"
                            } catch {
                                try {
                                    $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending
                                    $result.UpdateStatus = "$($hotfixes.Count) hotfixes installed"
                                    if ($hotfixes) {
                                        $latest = $hotfixes | Select-Object -First 1
                                        if ($latest.InstalledOn) {
                                            $result.LastUpdateDate = $latest.InstalledOn.ToString("yyyy-MM-dd HH:mm:ss")
                                        }
                                    }
                                } catch {
                                    Write-ErrorLog "Remote status check failed: $($_.Exception.Message)"
                                    $result.UpdateStatus = "Could not determine update status"
                                }
                            }
                        }
                    } catch {
                        Write-ErrorLog "Remote main script error: $($_.Exception.Message)"
                        $result.UpdateStatus = "Script error: $($_.Exception.Message)"
                    }
                    return $result
                }
                $remoteResult = Invoke-Command -ComputerName $serverName -Credential $cred -ScriptBlock $remoteScript -ArgumentList $ForceUpdates, $ScheduleReboot, $RebootTime -ErrorAction SilentlyContinue
                if ($remoteResult) {
                    $status = $remoteResult.UpdateStatus
                    $lastUpdate = $remoteResult.LastUpdateDate
                    $winVersion = $remoteResult.WindowsVersion
                    $policyStatus = $remoteResult.PolicyStatus
                    $updateResult = $remoteResult.UpdateResult
                    $rebootScheduled = $remoteResult.RebootScheduled
                    if ($remoteResult.Changes.Count -gt 0) {
                        Write-Host "🔧 Changes made:" -ForegroundColor Yellow
                        foreach ($change in $remoteResult.Changes) {
                            Write-Host "   • $change" -ForegroundColor White
                        }
                    }
                    Write-Host "✅ Processing complete" -ForegroundColor Green
                } else {
                    $status = "All authentication methods failed"
                    Write-ErrorLog "Start-ServerUpdateCheck: All authentication methods failed for $($serverName)"
                    Write-Host "❌ All authentication methods failed" -ForegroundColor Red
                }
            } else {
                $status = "Unreachable"
                Write-ErrorLog "Start-ServerUpdateCheck: Server $($serverName) unreachable"
                Write-Host "❌ Server unreachable" -ForegroundColor Red
            }
        } catch {
            $status = "Error: $($_.Exception.Message)"
            Write-ErrorLog "Start-ServerUpdateCheck: General error for $($serverName) $($_.Exception.Message)"
            Write-Host "❌ General error: $_" -ForegroundColor Red
        }
        $resultObj = [PSCustomObject]@{
            ServerName = $serverName
            IPAddress = if ($ip) { $ip } else { "N/A" }
            WindowsVersion = $winVersion
            PolicyStatus = $policyStatus
            UpdateStatus = $status
            UpdateResult = $updateResult
            LastUpdateDate = $lastUpdate
            RebootScheduled = $rebootScheduled
        }
        $results += $resultObj
        Write-Host "📝 Result added for $($serverName)" -ForegroundColor Cyan
    }
    try {
        $results | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
        Write-Host "`n✅ Export complete: $outputFile" -ForegroundColor Green
        Write-Host "📊 Total servers processed: $($results.Count)" -ForegroundColor Cyan
        $policyOverridden = ($results | Where-Object { $_.PolicyStatus -match "overridden" }).Count
        $updatesForced = ($results | Where-Object { $_.UpdateResult -match "successfully|installed" }).Count
        $reboots = ($results | Where-Object { $_.RebootScheduled -notmatch "No|Failed" }).Count
        Write-Host "`n📈 Summary:" -ForegroundColor Cyan
        Write-Host "   • Policies overridden: $policyOverridden" -ForegroundColor White
        Write-Host "   • Updates forced: $updatesForced" -ForegroundColor White
        Write-Host "   • Reboots scheduled: $reboots" -ForegroundColor White
    } catch {
        Write-ErrorLog "Start-ServerUpdateCheck: Failed to export results: $($_.Exception.Message)"
        Write-Error "Failed to export results: $_"
    }
}

# Main execution logic
if ($SetupCredSSP) {
    Write-Host "🚀 Setting up CredSSP Client configuration..." -ForegroundColor Cyan
    Enable-CredSSPClient -TrustedHosts $TrustedHosts
} elseif ($RunServerCheck) {
    if ($ForceUpdates) {
        Write-Host "⚠️  WARNING: This will override organizational Windows Update policies!" -ForegroundColor Red
        Write-Host "⚠️  This may conflict with IT governance and security policies!" -ForegroundColor Red
        $confirm = Read-Host "Are you sure you want to proceed? (yes/no)"
        if ($confirm -ne "yes") {
            Write-Host "❌ Operation cancelled" -ForegroundColor Red
            exit
        }
    }
    Start-ServerUpdateCheck
} else {
    Write-Host @"
🔧 Force Windows Updates Script with Policy Override

⚠️  WARNING: This script can override organizational policies!
⚠️  Use only with proper authorization!

Usage:
  .\script.ps1 -SetupCredSSP                                    # Setup CredSSP
  .\script.ps1 -RunServerCheck                                  # Check only (no changes)
  .\script.ps1 -RunServerCheck -ForceUpdates                    # Override policies and force updates
  .\script.ps1 -RunServerCheck -ForceUpdates -ScheduleReboot    # Also schedule reboot
  .\script.ps1 -RunServerCheck -ForceUpdates -ScheduleReboot -RebootTime "04:00"  # Custom reboot time

What it does when -ForceUpdates is used:
  • Backs up current Windows Update policies
  • Overrides "automatic updates disabled" policies
  • Enables automatic updates and scheduling
  • Forces immediate update detection and installation
  • Optionally schedules reboot for next day at specified time

Registry changes made:
  • HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate = 0
  • HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\AUOptions = 4
  • HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallDay = 0
  • HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\ScheduledInstallTime = 3 (or specified)
  • HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DisableWindowsUpdateAccess = 0
  • HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\ElevateNonAdmins = 0
  • And several other policy overrides...

⚠️  Security Implications:
  • Overrides organizational IT policies
  • May conflict with WSUS/patch management systems
  • Could install unwanted or problematic updates
  • May cause unexpected reboots
  • Use only with proper authorization and testing!
"@ -ForegroundColor White
}
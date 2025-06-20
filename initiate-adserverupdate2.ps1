# Force Windows Updates Script with Policy Override
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

function Write-ErrorLog {
    param([string]$Message)
    $logPath = "error.log"
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
        # Ensure path exists
        if (!(Test-Path $wuPath)) {
            New-Item -Path $wuPath -Force | Out-Null
        }

        # Set DisableWindowsUpdateAccess to 0 if not already
        $currentDisableAccess = (Get-ItemProperty -Path $wuPath -Name "DisableWindowsUpdateAccess" -ErrorAction SilentlyContinue)."DisableWindowsUpdateAccess"
        if ($currentDisableAccess -ne 0) {
            Set-ItemProperty -Path $wuPath -Name "DisableWindowsUpdateAccess" -Value 0 -Type DWord
            Write-Host "✅ Registry: DisableWindowsUpdateAccess set to 0." -ForegroundColor Green
            Write-ErrorLog "Registry: DisableWindowsUpdateAccess set to 0."
            $changed = $true
        } else {
            Write-Host "ℹ️  Registry: DisableWindowsUpdateAccess already set to 0." -ForegroundColor Yellow
        }

        # Set ElevateNonAdmins to 0 if not already
        $currentElevate = (Get-ItemProperty -Path $wuPath -Name "ElevateNonAdmins" -ErrorAction SilentlyContinue)."ElevateNonAdmins"
        if ($currentElevate -ne 0) {
            Set-ItemProperty -Path $wuPath -Name "ElevateNonAdmins" -Value 0 -Type DWord
            Write-Host "✅ Registry: ElevateNonAdmins set to 0." -ForegroundColor Green
            Write-ErrorLog "Registry: ElevateNonAdmins set to 0."
            $changed = $true
        } else {
            Write-Host "ℹ️  Registry: ElevateNonAdmins already set to 0." -ForegroundColor Yellow
        }

        # If any change was made, restart wuauserv
        if ($changed) {
            try {
                Set-Service -Name wuauserv -StartupType Automatic
                Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
                Start-Service -Name wuauserv
                Start-Sleep -Seconds 3
                Write-Host "🔄 Windows Update service (wuauserv) restarted after registry modification." -ForegroundColor Cyan
                Write-ErrorLog "Windows Update service (wuauserv) restarted after registry modification."
            } catch {
                Write-Host "❌ Could not restart wuauserv: $($_.Exception.Message)" -ForegroundColor Red
                Write-ErrorLog "Could not restart wuauserv: $($_.Exception.Message)"
            }
        }
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
        # --- Call new registry keys check/set here ---
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
        Write-Host "⚠️  CredSSP is not enabled on this client. Run the following command as Administrator:" -ForegroundColor Yellow
        Write-Host "    Enable-WSManCredSSP -Role Client -DelegateComputer '$TrustedHosts' -Force" -ForegroundColor White
        Write-ErrorLog "CredSSP is not enabled on this client. Command needed: Enable-WSManCredSSP -Role Client -DelegateComputer '$TrustedHosts' -Force"
        # Optionally exit here.
        # exit
    }
    $cred = Get-Credential -Message "Enter domain credentials for server access"
    $outputFile = "NON-AD-Prodservers-ForceUpdate.csv"
    $results = @()
    Write-Host "🔍 Retrieving servers from AD..." -ForegroundColor Cyan
    try {
        $servers = Get-ADComputer -Filter {
            Name -like "*TST*" -or Name -like "ACC*" -or Name -like "*DEV*" -or Name -like "*-ts*" -or Name -like "*ACC*"
        } -Server "nwk-dc101" -Properties Name, IPv4Address
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
                $scriptBlock = {
                    param($ForceUpdates, $ScheduleReboot, $RebootTime)
                    $result = @{
                        UpdateStatus = "Unknown"
                        LastUpdateDate = "N/A"
                        WindowsVersion = "Unknown"
                        PolicyStatus = "Unknown"
                        UpdateResult = "Unknown"
                        RebootScheduled = "No"
                        Changes = @()
                    }
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
                                Write-Host "✅ Registry: DisableWindowsUpdateAccess set to 0." -ForegroundColor Green
                                Write-ErrorLog "Registry: DisableWindowsUpdateAccess set to 0."
                                $changed = $true
                            } else {
                                Write-Host "ℹ️  Registry: DisableWindowsUpdateAccess already set to 0." -ForegroundColor Yellow
                            }
                            $currentElevate = (Get-ItemProperty -Path $wuPath -Name "ElevateNonAdmins" -ErrorAction SilentlyContinue)."ElevateNonAdmins"
                            if ($currentElevate -ne 0) {
                                Set-ItemProperty -Path $wuPath -Name "ElevateNonAdmins" -Value 0 -Type DWord
                                Write-Host "✅ Registry: ElevateNonAdmins set to 0." -ForegroundColor Green
                                Write-ErrorLog "Registry: ElevateNonAdmins set to 0."
                                $changed = $true
                            } else {
                                Write-Host "ℹ️  Registry: ElevateNonAdmins already set to 0." -ForegroundColor Yellow
                            }
                            if ($changed) {
                                try {
                                    Set-Service -Name wuauserv -StartupType Automatic
                                    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
                                    Start-Sleep -Seconds 2
                                    Start-Service -Name wuauserv
                                    Start-Sleep -Seconds 3
                                    Write-Host "🔄 Windows Update service (wuauserv) restarted after registry modification." -ForegroundColor Cyan
                                    Write-ErrorLog "Windows Update service (wuauserv) restarted after registry modification."
                                } catch {
                                    Write-Host "❌ Could not restart wuauserv: $($_.Exception.Message)" -ForegroundColor Red
                                    Write-ErrorLog "Could not restart wuauserv: $($_.Exception.Message)"
                                }
                            }
                        } catch {
                            Write-Host "❌ Error modifying Windows Update registry settings: $($_.Exception.Message)" -ForegroundColor Red
                            Write-ErrorLog "Error modifying Windows Update registry settings: $($_.Exception.Message)"
                        }
                    }
                    function Get-WindowsVersionFallback {
                        try {
                            $sysinfo = systeminfo | Select-String 'OS Name','OS Version'
                            $osName = ($sysinfo | Where-Object { $_ -like '*OS Name*' }) -replace '.*:\s*',''
                            $osVer  = ($sysinfo | Where-Object { $_ -like '*OS Version*' }) -replace '.*:\s*',''
                            return "$osName $osVer"
                        } catch {
                            Write-ErrorLog "Remote Get-WindowsVersionFallback failed: $($_.Exception.Message)"
                            return "Unknown"
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
                    try {
                        try {
                            $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
                            $result.WindowsVersion = "$($os.Caption) Build $($os.BuildNumber)"
                        } catch {
                            try {
                                $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
                                $result.WindowsVersion = "$($os.Caption) Build $($os.BuildNumber)"
                            } catch {
                                $result.WindowsVersion = Get-WindowsVersionFallback
                            }
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
                            $policyResult = Enable-WindowsUpdatesPolicy -ForceInstall $true -RebootTime $RebootTime
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
                $fullScriptBlock = [ScriptBlock]::Create(@"
                    function Write-ErrorLog {
                        param([string]`$Message)
                        `$logPath = 'error.log'
                        `$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                        Add-Content -Path `$logPath -Value ""`$timestamp `$Message""
                    }
                    $($scriptBlock.ToString())
                    & { $($scriptBlock.ToString()) } -ForceUpdates `$$ForceUpdates -ScheduleReboot `$$ScheduleReboot -RebootTime '$RebootTime'
"@)
                $remoteResult = $null
                $authMethods = @("Default", "Negotiate", "Kerberos", "Credssp")
                foreach ($auth in $authMethods) {
                    try {
                        Write-Host "🔄 Trying $auth authentication..." -ForegroundColor Yellow
                        $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck
                        $remoteResult = Invoke-Command -ComputerName $serverName -Credential $cred -Authentication $auth -ScriptBlock $fullScriptBlock -SessionOption $sessionOption -ErrorAction Stop
                        Write-Host "✅ Success with $auth" -ForegroundColor Green
                        break
                    } catch {
                        $errMsg = $_.Exception.Message
                        if ($errMsg -like "*CredSSP authentication is currently disabled*") {
                            Write-ErrorLog "CredSSP not enabled for $($serverName). 
To fix:
- On this client, run: Enable-WSManCredSSP -Role Client -DelegateComputer '$($serverName)' -Force
- On the server, run: Enable-WSManCredSSP -Role Server -Force
- In Group Policy (gpedit.msc), enable 'Allow Delegating Fresh Credentials' for WSMAN/$($serverName) or WSMAN/*."
                            Write-Host "❌ CredSSP not enabled for $($serverName). See error.log for required steps." -ForegroundColor Red
                        } else {
                            Write-ErrorLog "Start-ServerUpdateCheck: $auth failed on $($serverName): $errMsg"
                            Write-Host "❌ $auth failed: $_" -ForegroundColor Red
                        }
                        continue
                    }
                }
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
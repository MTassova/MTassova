param(
    [string]$DomainController = "nwk-dc101",
    [int]$ScheduledInstallTime = 3
)

# Import required modules
Import-Module ActiveDirectory

# Get credentials for AD operations
Write-Host "=== Windows Update Management Script ===" -ForegroundColor Green
Write-Host "Please provide credentials for Active Directory operations:" -ForegroundColor Yellow
$Credential = Get-Credential -Message "Enter AD credentials"

# Initialize log files
$LogPath = "C:\Temp\UpdateLogs"
if (!(Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force
    Write-Host "Created log directory: $LogPath" -ForegroundColor Green
}

$SuccessLog = "$LogPath\success.log"
$FailureLog = "$LogPath\failure.log"
$DetailedLog = "$LogPath\detailed.log"

# Function to write detailed logs
function Write-DetailedLog {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    Write-Host $LogEntry -ForegroundColor $(if($Level -eq "ERROR"){"Red"} elseif($Level -eq "WARNING"){"Yellow"} else{"White"})
    Add-Content -Path $DetailedLog -Value $LogEntry
}

Write-DetailedLog "=== Starting Windows Update Management Script ===" "INFO"
Write-DetailedLog "Domain Controller: $DomainController" "INFO"
Write-DetailedLog "Scheduled Install Time: $ScheduledInstallTime" "INFO"

# Create the update script that will be copied to target servers
$UpdateScriptContent = @"
param([int]`$ScheduledInstallTime = 3)

# Function to write logs
function Write-Log {
    param([string]`$Message, [string]`$Level = "INFO")
    `$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    `$LogEntry = "[`$Timestamp] [`$Level] `$Message"
    Write-Host `$LogEntry -ForegroundColor `$(if(`$Level -eq "ERROR"){"Red"} elseif(`$Level -eq "WARNING"){"Yellow"} else{"White"})
    Add-Content -Path "C:\Temp\update_execution.log" -Value `$LogEntry
}

# Function to get system information
function Get-SystemInfo {
    try {
        # Get Windows version
        `$OSInfo = Get-WmiObject -Class Win32_OperatingSystem
        `$WindowsVersion = "`$(`$OSInfo.Caption) `$(`$OSInfo.Version) Build `$(`$OSInfo.BuildNumber)"
        
        # Get last reboot date
        `$LastReboot = `$OSInfo.ConvertToDateTime(`$OSInfo.LastBootUpTime)
        
        # Get last Windows Update check date
        `$LastUpdateCheck = "Not Available"
        try {
            `$UpdateSession = New-Object -ComObject Microsoft.Update.Session
            `$UpdateSearcher = `$UpdateSession.CreateUpdateSearcher()
            `$UpdateHistory = `$UpdateSearcher.GetTotalHistoryCount()
            if (`$UpdateHistory -gt 0) {
                `$History = `$UpdateSearcher.QueryHistory(0, 1)
                if (`$History.Count -gt 0) {
                    `$LastUpdateCheck = `$History[0].Date
                }
            }
        } catch {
            # Try alternative method using Windows Update log
            try {
                `$WULog = Get-WinEvent -LogName "Microsoft-Windows-WindowsUpdateClient/Operational" -MaxEvents 1 -FilterXPath "*[System[EventID=19]]" -ErrorAction SilentlyContinue
                if (`$WULog) {
                    `$LastUpdateCheck = `$WULog.TimeCreated
                }
            } catch {
                `$LastUpdateCheck = "Unable to determine"
            }
        }
        
        return @{
            WindowsVersion = `$WindowsVersion
            LastReboot = `$LastReboot
            LastUpdateCheck = `$LastUpdateCheck
        }
    } catch {
        return @{
            WindowsVersion = "Unable to determine"
            LastReboot = "Unable to determine"
            LastUpdateCheck = "Unable to determine"
        }
    }
}

try {
    Write-Log "=== Starting Windows Update Configuration Script ===" "INFO"
    Write-Log "Server: `$env:COMPUTERNAME" "INFO"
    Write-Log "Scheduled Install Time: `$ScheduledInstallTime" "INFO"
    
    # Check if running as administrator
    `$CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    `$Principal = New-Object Security.Principal.WindowsPrincipal(`$CurrentUser)
    `$IsAdmin = `$Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    Write-Log "Current user: `$(`$CurrentUser.Name)" "INFO"
    Write-Log "Running as administrator: `$IsAdmin" "INFO"
    
    if (-not `$IsAdmin) {
        Write-Log "ERROR: Script must run as administrator for Windows Update operations" "ERROR"
        throw "Access denied - script must run with administrator privileges"
    }
    
    # Get system information
    Write-Log "Gathering system information..." "INFO"
    `$SystemInfo = Get-SystemInfo
    Write-Log "Windows Version: `$(`$SystemInfo.WindowsVersion)" "INFO"
    Write-Log "Last Reboot: `$(`$SystemInfo.LastReboot)" "INFO"
    Write-Log "Last Update Check: `$(`$SystemInfo.LastUpdateCheck)" "INFO"
    
    # Stop Windows Update service
    Write-Log "Stopping Windows Update service..." "INFO"
    Stop-Service -Name "wuauserv" -Force -ErrorAction Stop
    Write-Log "Windows Update service stopped successfully" "INFO"
    
    # Create registry paths if they don't exist
    Write-Log "Creating registry paths..." "INFO"
    `$RegPaths = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    )
    
    foreach (`$Path in `$RegPaths) {
        if (!(Test-Path `$Path)) {
            New-Item -Path `$Path -Force | Out-Null
            Write-Log "Created registry path: `$Path" "INFO"
        }
    }
    
    # Set registry values
    Write-Log "Configuring Windows Update registry settings..." "INFO"
    `$RegSettings = @{
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" = @{
            "NoAutoUpdate" = 0
            "AUOptions" = 4
            "ScheduledInstallDay" = 0
            "ScheduledInstallTime" = `$ScheduledInstallTime
        }
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" = @{
            "DisableWindowsUpdateAccess" = 0
            "ElevateNonAdmins" = 0
        }
    }
    
    foreach (`$Path in `$RegSettings.Keys) {
        foreach (`$Setting in `$RegSettings[`$Path].GetEnumerator()) {
            Set-ItemProperty -Path `$Path -Name `$Setting.Key -Value `$Setting.Value -Type DWord -Force
            Write-Log "Set `$Path\`$(`$Setting.Key) = `$(`$Setting.Value)" "INFO"
        }
    }
    
    # Set Windows Update service to start automatically
    Write-Log "Setting Windows Update service to start automatically..." "INFO"
    Set-Service -Name "wuauserv" -StartupType Automatic -ErrorAction Stop
    Write-Log "Windows Update service startup type set to Automatic" "INFO"
    
    # Start Windows Update service
    Write-Log "Starting Windows Update service..." "INFO"
    Start-Service -Name "wuauserv" -ErrorAction Stop
    Write-Log "Windows Update service started successfully" "INFO"
    
    # Force Windows Update check and install all available updates
    Write-Log "Forcing Windows Update check..." "INFO"
    `$UpdateSession = New-Object -ComObject Microsoft.Update.Session
    `$UpdateSearcher = `$UpdateSession.CreateUpdateSearcher()
    
    # Search for all available updates (not installed)
    `$SearchResult = `$UpdateSearcher.Search("IsInstalled=0")
    
    if (`$SearchResult.Updates.Count -gt 0) {
        Write-Log "Found `$(`$SearchResult.Updates.Count) updates available" "INFO"
        
        # Categorize updates
        `$ImportantUpdates = @()
        `$OptionalUpdates = @()
        `$AllUpdates = @()
        
        foreach (`$Update in `$SearchResult.Updates) {
            `$UpdateInfo = "Title: `$(`$Update.Title) | Size: `$([math]::Round(`$Update.MaxDownloadSize/1MB, 2)) MB"
            
            if (`$Update.AutoSelectOnWebSites) {
                `$ImportantUpdates += `$Update
                Write-Log "IMPORTANT: `$UpdateInfo" "INFO"
            } else {
                `$OptionalUpdates += `$Update
                Write-Log "OPTIONAL: `$UpdateInfo" "INFO"
            }
            `$AllUpdates += `$Update
        }
        
        Write-Log "Summary: `$(`$ImportantUpdates.Count) important updates, `$(`$OptionalUpdates.Count) optional updates" "INFO"
        
        if (`$AllUpdates.Count -gt 0) {
            # Create collection for all updates to download and install
            `$UpdatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl
            `$UpdatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
            
            # Add all updates to download collection
            foreach (`$Update in `$AllUpdates) {
                if (`$Update.EulaAccepted -eq `$false) {
                    `$Update.AcceptEula()
                    Write-Log "Accepted EULA for: `$(`$Update.Title)" "INFO"
                }
                `$UpdatesToDownload.Add(`$Update) | Out-Null
            }
            
            # Download all updates
            if (`$UpdatesToDownload.Count -gt 0) {
                Write-Log "Starting download of `$(`$UpdatesToDownload.Count) updates..." "INFO"
                `$Downloader = `$UpdateSession.CreateUpdateDownloader()
                `$Downloader.Updates = `$UpdatesToDownload
                
                try {
                    `$DownloadResult = `$Downloader.Download()
                    Write-Log "Download completed with result code: `$(`$DownloadResult.ResultCode)" "INFO"
                    
                    # Check download results
                    for (`$i = 0; `$i -lt `$UpdatesToDownload.Count; `$i++) {
                        `$Update = `$UpdatesToDownload.Item(`$i)
                        `$Result = `$DownloadResult.GetUpdateResult(`$i)
                        
                        if (`$Result.ResultCode -eq 2) {  # OperationResultCode.orcSucceeded
                            Write-Log "Successfully downloaded: `$(`$Update.Title)" "INFO"
                            `$UpdatesToInstall.Add(`$Update) | Out-Null
                        } else {
                            Write-Log "Failed to download: `$(`$Update.Title) - Result: `$(`$Result.ResultCode)" "WARNING"
                        }
                    }
                } catch {
                    Write-Log "Download error: `$(`$_.Exception.Message)" "ERROR"
                    # Still try to install any previously downloaded updates
                    foreach (`$Update in `$UpdatesToDownload) {
                        if (`$Update.IsDownloaded) {
                            `$UpdatesToInstall.Add(`$Update) | Out-Null
                        }
                    }
                }
            }
            
            # Install all downloaded updates
            if (`$UpdatesToInstall.Count -gt 0) {
                Write-Log "Starting installation of `$(`$UpdatesToInstall.Count) updates..." "INFO"
                `$Installer = `$UpdateSession.CreateUpdateInstaller()
                `$Installer.Updates = `$UpdatesToInstall
                
                # Force installation settings
                `$Installer.AllowSourcePrompts = `$false
                `$Installer.ForceQuiet = `$true
                
                try {
                    Write-Log "Forcing installation of all downloaded updates..." "INFO"
                    `$InstallationResult = `$Installer.Install()
                    Write-Log "Installation completed with result code: `$(`$InstallationResult.ResultCode)" "INFO"
                    
                    # Check installation results
                    `$SuccessCount = 0
                    `$FailCount = 0
                    for (`$i = 0; `$i -lt `$UpdatesToInstall.Count; `$i++) {
                        `$Update = `$UpdatesToInstall.Item(`$i)
                        `$Result = `$InstallationResult.GetUpdateResult(`$i)
                        
                        if (`$Result.ResultCode -eq 2) {  # OperationResultCode.orcSucceeded
                            Write-Log "Successfully installed: `$(`$Update.Title)" "INFO"
                            `$SuccessCount++
                        } elseif (`$Result.ResultCode -eq 3) {  # OperationResultCode.orcSucceededWithErrors
                            Write-Log "Installed with errors: `$(`$Update.Title)" "WARNING"
                            `$SuccessCount++
                        } else {
                            Write-Log "Failed to install: `$(`$Update.Title) - Result: `$(`$Result.ResultCode) - HResult: `$(`$Result.HResult)" "ERROR"
                            `$FailCount++
                        }
                    }
                    
                    Write-Log "Installation summary: `$SuccessCount successful, `$FailCount failed" "INFO"
                    
                    # Check if reboot is required
                    if (`$InstallationResult.RebootRequired) {
                        Write-Log "Reboot required after updates - scheduling restart in 2 minutes..." "WARNING"
                        shutdown /r /t 120 /c "Reboot required after Windows Updates - All available patches installed"
                    } else {
                        Write-Log "No reboot required after update installation" "INFO"
                    }
                    
                    # If some updates failed, try alternative installation method
                    if (`$FailCount -gt 0) {
                        Write-Log "Attempting alternative installation method for failed updates..." "INFO"
                        try {
                            # Use wuauclt to force installation
                            `$wuaucltResult = Start-Process -FilePath "wuauclt.exe" -ArgumentList "/detectnow", "/updatenow" -Wait -PassThru
                            Write-Log "wuauclt.exe executed with exit code: `$(`$wuaucltResult.ExitCode)" "INFO"
                            
                            # Also try usoclient
                            `$usoclientResult = Start-Process -FilePath "usoclient.exe" -ArgumentList "StartDownload", "StartInstall" -Wait -PassThru -ErrorAction SilentlyContinue
                            if (`$usoclientResult) {
                                Write-Log "usoclient.exe executed with exit code: `$(`$usoclientResult.ExitCode)" "INFO"
                            }
                        } catch {
                            Write-Log "Alternative installation method failed: `$(`$_.Exception.Message)" "WARNING"
                        }
                    }
                    
                } catch {
                    Write-Log "Installation error: `$(`$_.Exception.Message)" "ERROR"
                    
                    # Try alternative installation approaches
                    Write-Log "Attempting alternative installation methods..." "INFO"
                    
                    # Method 1: Use Windows Update AutoUpdate client
                    try {
                        Write-Log "Trying Windows Update AutoUpdate client..." "INFO"
                        `$AutoUpdate = New-Object -ComObject Microsoft.Update.AutoUpdate
                        `$AutoUpdate.DetectNow()
                        Start-Sleep -Seconds 10
                        Write-Log "AutoUpdate.DetectNow() completed" "INFO"
                    } catch {
                        Write-Log "AutoUpdate method failed: `$(`$_.Exception.Message)" "WARNING"
                    }
                    
                    # Method 2: Use command line tools
                    try {
                        Write-Log "Trying command line installation..." "INFO"
                        `$wuaucltResult = Start-Process -FilePath "wuauclt.exe" -ArgumentList "/detectnow", "/updatenow", "/resetauthorization" -Wait -PassThru
                        Write-Log "Command line installation completed with exit code: `$(`$wuaucltResult.ExitCode)" "INFO"
                    } catch {
                        Write-Log "Command line installation failed: `$(`$_.Exception.Message)" "WARNING"
                    }
                    
                    # Method 3: PowerShell Windows Update module (if available)
                    try {
                        Write-Log "Checking for PSWindowsUpdate module..." "INFO"
                        if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
                            Import-Module PSWindowsUpdate
                            Write-Log "Installing updates using PSWindowsUpdate module..." "INFO"
                            Get-WUInstall -AcceptAll -AutoReboot -Confirm:`$false
                            Write-Log "PSWindowsUpdate installation completed" "INFO"
                        } else {
                            Write-Log "PSWindowsUpdate module not available" "INFO"
                        }
                    } catch {
                        Write-Log "PSWindowsUpdate method failed: `$(`$_.Exception.Message)" "WARNING"
                    }
                    
                    throw "Failed to install updates: `$(`$_.Exception.Message)"
                }
            } else {
                Write-Log "No updates were successfully downloaded for installation" "WARNING"
                
                # Force Windows Update service to try again
                Write-Log "Forcing Windows Update service to retry..." "INFO"
                try {
                    Stop-Service -Name "wuauserv" -Force
                    Start-Sleep -Seconds 5
                    Start-Service -Name "wuauserv"
                    Start-Sleep -Seconds 10
                    
                    # Try to trigger update detection and installation
                    `$wuaucltResult = Start-Process -FilePath "wuauclt.exe" -ArgumentList "/detectnow", "/updatenow", "/resetauthorization" -Wait -PassThru
                    Write-Log "Forced Windows Update check completed with exit code: `$(`$wuaucltResult.ExitCode)" "INFO"
                } catch {
                    Write-Log "Failed to force Windows Update retry: `$(`$_.Exception.Message)" "WARNING"
                }
            }
        }
    } else {
        Write-Log "No updates available - system is up to date" "INFO"
    }
    
    # Force Windows Update service to check for more updates after installation
    Write-Log "Triggering final update check..." "INFO"
    try {
        `$UpdateSearcher2 = `$UpdateSession.CreateUpdateSearcher()
        `$SearchResult2 = `$UpdateSearcher2.Search("IsInstalled=0")
        if (`$SearchResult2.Updates.Count -gt 0) {
            Write-Log "Additional `$(`$SearchResult2.Updates.Count) updates found after installation" "INFO"
        } else {
            Write-Log "No additional updates found - system is fully updated" "INFO"
        }
    } catch {
        Write-Log "Could not perform final update check: `$(`$_.Exception.Message)" "WARNING"
    }
    
    Write-Log "=== Windows Update Configuration Script Completed Successfully ===" "INFO"
    
    # Return system information for logging
    return `$SystemInfo
    
} catch {
    Write-Log "ERROR: `$(`$_.Exception.Message)" "ERROR"
    Write-Log "Stack Trace: `$(`$_.ScriptStackTrace)" "ERROR"
    throw `$_.Exception.Message
}
"@

# Save the update script to a temporary location
$UpdateScriptPath = "$env:TEMP\WindowsUpdateScript.ps1"
Set-Content -Path $UpdateScriptPath -Value $UpdateScriptContent -Force
Write-DetailedLog "Created update script at: $UpdateScriptPath" "INFO"

try {
    # Get all AD servers
    Write-DetailedLog "Querying Active Directory for servers..." "INFO"
    $AllServers = Get-ADComputer -Filter {OperatingSystem -like "*Server*"} -Server $DomainController -Credential $Credential -Properties Name, OperatingSystem, LastLogonDate
    Write-DetailedLog "Found $($AllServers.Count) servers in Active Directory" "INFO"
    
    # Filter servers with TST, DEV, ACC in the name
     #$TargetServers = $AllServers | Where-Object { $_.Name -match "(TST|DEV|ACC)" }
    $TargetServers = $AllServers | Where-Object { $_.Name -match "(NWK-DC101|PRD-HAS-TSK102|BOB-TS103)" }

    Write-DetailedLog "Found $($TargetServers.Count) target servers matching criteria (TST, DEV, ACC)" "INFO"
    
    if ($TargetServers.Count -eq 0) {
        Write-DetailedLog "No target servers found matching criteria" "WARNING"
        exit 1
    }
    
    # Process each target server
    foreach ($Server in $TargetServers) {
        $ServerName = $Server.Name
        $StartTime = Get-Date
        Write-DetailedLog "=== Processing server: $ServerName ===" "INFO"
        
        try {
            # Test connectivity
            Write-DetailedLog "Testing connectivity to $ServerName..." "INFO"
            if (!(Test-Connection -ComputerName $ServerName -Count 1 -Quiet)) {
                throw "Server $ServerName is not reachable"
            }
            Write-DetailedLog "Successfully connected to $ServerName" "INFO"
            
            # Create C:\Temp directory if it doesn't exist
            Write-DetailedLog "Creating C:\Temp directory on $ServerName..." "INFO"
            Invoke-Command -ComputerName $ServerName -Credential $Credential -ScriptBlock {
                if (!(Test-Path "C:\Temp")) {
                    New-Item -ItemType Directory -Path "C:\Temp" -Force | Out-Null
                }
            }
            Write-DetailedLog "C:\Temp directory verified on $ServerName" "INFO"
            
            # Copy the update script to the server
            Write-DetailedLog "Copying update script to $ServerName..." "INFO"
            $RemoteScriptPath = "\\$ServerName\C$\Temp\WindowsUpdateScript.ps1"
            Copy-Item -Path $UpdateScriptPath -Destination $RemoteScriptPath -Force
            Write-DetailedLog "Successfully copied update script to $ServerName" "INFO"
            
            # Execute the update script on the remote server with elevated privileges
            Write-DetailedLog "Executing update script on $ServerName with elevated privileges..." "INFO"
            
            # Get and temporarily change execution policy, then restore it
            $SystemInfo = Invoke-Command -ComputerName $ServerName -Credential $Credential -ScriptBlock {
                param([int]$InstallTime)
                
                # Check if running as administrator
                $CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
                $Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)
                $IsAdmin = $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                
                Write-Host "Current user: $($CurrentUser.Name)"
                Write-Host "Running as administrator: $IsAdmin"
                
                if (-not $IsAdmin) {
                    Write-Host "Not running as administrator, attempting to elevate..."
                    
                    # Create a scheduled task to run the script with elevated privileges
                    $TaskName = "WindowsUpdateScript_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
                    $ScriptPath = "C:\Temp\WindowsUpdateScript.ps1"
                    $LogPath = "C:\Temp\elevated_execution.log"
                    
                    # Create the scheduled task
                    $Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy RemoteSigned -File `"$ScriptPath`" -ScheduledInstallTime $InstallTime > `"$LogPath`" 2>&1"
                    $Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
                    $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
                    $Task = New-ScheduledTask -Action $Action -Principal $Principal -Settings $Settings
                    
                    # Register and start the task
                    Register-ScheduledTask -TaskName $TaskName -InputObject $Task -Force | Out-Null
                    Write-Host "Created scheduled task: $TaskName"
                    
                    # Start the task and wait for completion
                    Start-ScheduledTask -TaskName $TaskName
                    Write-Host "Started scheduled task, waiting for completion..."
                    
                    # Wait for task to complete (max 30 minutes)
                    $timeout = 1800 # 30 minutes in seconds
                    $elapsed = 0
                    $interval = 10
                    
                    do {
                        Start-Sleep -Seconds $interval
                        $elapsed += $interval
                        $taskState = (Get-ScheduledTask -TaskName $TaskName).State
                        Write-Host "Task state: $taskState (elapsed: $elapsed seconds)"
                    } while ($taskState -eq "Running" -and $elapsed -lt $timeout)
                    
                    # Get task result
                    $taskInfo = Get-ScheduledTaskInfo -TaskName $TaskName
                    $lastRunTime = $taskInfo.LastRunTime
                    $lastTaskResult = $taskInfo.LastTaskResult
                    
                    Write-Host "Task completed. Last run: $lastRunTime, Result: $lastTaskResult"
                    
                    # Clean up the scheduled task
                    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
                    Write-Host "Cleaned up scheduled task: $TaskName"
                    
                    # Read the log file to get system info and results
                    if (Test-Path $LogPath) {
                        $ElevatedLog = Get-Content $LogPath -Raw
                        Write-Host "Elevated execution log:"
                        Write-Host $ElevatedLog
                        
                        # Try to extract system information from the log
                        $WindowsVersion = "Unknown"
                        $LastReboot = "Unknown"
                        $LastUpdateCheck = "Unknown"
                        
                        # Parse log for system information
                        if ($ElevatedLog -match "Windows Version: (.+)") {
                            $WindowsVersion = $matches[1]
                        }
                        if ($ElevatedLog -match "Last Reboot: (.+)") {
                            $LastReboot = $matches[1]
                        }
                        if ($ElevatedLog -match "Last Update Check: (.+)") {
                            $LastUpdateCheck = $matches[1]
                        }
                        
                        # Clean up log file
                        Remove-Item $LogPath -Force -ErrorAction SilentlyContinue
                        
                        return @{
                            WindowsVersion = $WindowsVersion
                            LastReboot = $LastReboot
                            LastUpdateCheck = $LastUpdateCheck
                            ExecutionMethod = "Elevated via Scheduled Task"
                            TaskResult = $lastTaskResult
                        }
                    } else {
                        throw "Elevated execution log not found - task may have failed"
                    }
                } else {
                    Write-Host "Already running as administrator, proceeding with direct execution..."
                    
                    # Get current execution policy
                    $CurrentPolicy = Get-ExecutionPolicy
                    Write-Host "Current execution policy: $CurrentPolicy"
                    
                    # Temporarily set execution policy to allow script execution
                    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
                    Write-Host "Temporarily set execution policy to RemoteSigned for this process"
                    
                    try {
                        # Execute the script and capture return value
                        $Result = & "C:\Temp\WindowsUpdateScript.ps1" -ScheduledInstallTime $InstallTime
                        return $Result
                    } finally {
                        # Restore original execution policy (this won't affect the current process as it's ending)
                        # The policy change was only for the current process scope
                        Write-Host "Script execution completed. Process-scoped policy will be automatically restored."
                    }
                }
            } -ArgumentList $ScheduledInstallTime
            
            # Log successful execution with system information
            $EndTime = Get-Date
            $Duration = $EndTime - $StartTime
            
            # Format system information for logging
            $WindowsVersion = if ($SystemInfo.WindowsVersion) { $SystemInfo.WindowsVersion } else { "Unknown" }
            $LastReboot = if ($SystemInfo.LastReboot) { $SystemInfo.LastReboot.ToString('yyyy-MM-dd HH:mm:ss') } else { "Unknown" }
            $LastUpdateCheck = if ($SystemInfo.LastUpdateCheck -and $SystemInfo.LastUpdateCheck -ne "Not Available" -and $SystemInfo.LastUpdateCheck -ne "Unable to determine") { 
                if ($SystemInfo.LastUpdateCheck -is [DateTime]) { 
                    $SystemInfo.LastUpdateCheck.ToString('yyyy-MM-dd HH:mm:ss') 
                } else { 
                    $SystemInfo.LastUpdateCheck.ToString() 
                }
            } else { "Unknown" }
            
            $SuccessEntry = "[$($EndTime.ToString('yyyy-MM-dd HH:mm:ss'))] SUCCESS: $ServerName - Duration: $($Duration.TotalMinutes.ToString('F2')) min - Windows: $WindowsVersion - Last Reboot: $LastReboot - Last Update Check: $LastUpdateCheck"
            Add-Content -Path $SuccessLog -Value $SuccessEntry
            Write-DetailedLog "Successfully executed update script on $ServerName" "INFO"
            Write-DetailedLog "System Info - Windows: $WindowsVersion, Last Reboot: $LastReboot, Last Update Check: $LastUpdateCheck" "INFO"
            
        } catch {
            # Log failed execution
            $EndTime = Get-Date
            $Duration = $EndTime - $StartTime
            $ErrorMessage = $_.Exception.Message
            $FailureEntry = "[$($EndTime.ToString('yyyy-MM-dd HH:mm:ss'))] FAILURE: $ServerName - Error: $ErrorMessage - Duration: $($Duration.TotalMinutes.ToString('F2')) minutes"
            Add-Content -Path $FailureLog -Value $FailureEntry
            Write-DetailedLog "Failed to process $ServerName`: $ErrorMessage" "ERROR"
        }
    }
    
    Write-DetailedLog "=== Script execution completed ===" "INFO"
    Write-DetailedLog "Check the following log files for results:" "INFO"
    Write-DetailedLog "  Success Log: $SuccessLog" "INFO"
    Write-DetailedLog "  Failure Log: $FailureLog" "INFO"
    Write-DetailedLog "  Detailed Log: $DetailedLog" "INFO"
    
} catch {
    Write-DetailedLog "CRITICAL ERROR: $($_.Exception.Message)" "ERROR"
    Write-DetailedLog "Stack Trace: $($_.ScriptStackTrace)" "ERROR"
    exit 1
}

# Clean up temporary files
Remove-Item -Path $UpdateScriptPath -Force -ErrorAction SilentlyContinue
Write-DetailedLog "Cleaned up temporary files" "INFO"
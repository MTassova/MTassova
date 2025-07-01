# Enhanced Force Windows Updates Script with Comprehensive Monitoring
# Added detailed logging, progress tracking, and error reporting
# ⚠️ WARNING: This script overrides organizational policies!
# Use only with proper authorization and understanding of implications

param(
    [switch]$SetupCredSSP,
    [switch]$RunServerCheck,
    [switch]$ForceUpdates,
    [switch]$ScheduleReboot,
    [string]$DCname = "nwk-dc101",
    [string]$TrustedHosts = "*",
    [string]$RebootTime = "03:00"
)

# Enhanced logging functions with structured output

function Test-DomainCredential {
    param(
        [System.Management.Automation.PSCredential]$Credential,
        [string]$DomainController = $DCname
    )
    
    try {
        # First attempt: Direct LDAP binding
        $ldapPath = "LDAP://$DomainController"
        $entry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath, 
            $Credential.UserName, 
            $Credential.GetNetworkCredential().Password)
        
        if ($entry.name -ne $null) {
            return @{
                Success = $true
                Message = "Successfully authenticated to domain controller $DomainController"
                Username = $Credential.UserName
            }
        }
        
        # If we get here without an exception but entry.name is null, authentication failed
        return @{
            Success = $false
            Message = "Authentication failed - Invalid credentials"
            Username = $Credential.UserName
        }
    }
    catch [System.Management.Automation.MethodInvocationException] {
        return @{
            Success = $false
            Message = "Authentication failed - Access Denied"
            Username = $Credential.UserName
        }
    }
    catch {
        return @{
            Success = $false
            Message = "Authentication failed - $($_.Exception.Message)"
            Username = $Credential.UserName
        }
    }
}

function Test-RemoteAuthentication {
     param (
        [Parameter(Mandatory=$true)]
        [string]$Server,

        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$Credential
    )


    try {
        $session = New-PSSession -ComputerName $Server -Credential $Credential -Authentication Credssp -ErrorAction Stop
        Remove-PSSession $session
        Write-Host "Authentication to $Server succeeded."
        return $true
    } catch {
        Write-Host "Authentication to $($Server) failed."
        Write-Host "Error Message: $($_.Exception.Message)"
        Write-Host "Stack Trace: $($_.Exception.StackTrace)"
        if ($_.Exception.InnerException) {
            Write-Host "Inner Exception: $($_.Exception.InnerException.Message)"
        }
        return $false
    }
}

function Write-DetailedLog {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [string]$Component = "MAIN",
        [string]$ServerName = "LOCAL"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logEntry = "$timestamp [$Level] [$Component] [$ServerName] $Message"
    
    # Write to appropriate log file based on level
    switch ($Level) {
        "ERROR" { 
            Add-Content -Path "error.log" -Value $logEntry -Encoding UTF8
            Write-Host $logEntry -ForegroundColor Red
        }
        "SUCCESS" { 
            Add-Content -Path "success.log" -Value $logEntry -Encoding UTF8
            Write-Host $logEntry -ForegroundColor Green
        }
        "WARNING" { 
            Add-Content -Path "warning.log" -Value $logEntry -Encoding UTF8
            Write-Host $logEntry -ForegroundColor Yellow
        }
        "PROGRESS" { 
            Add-Content -Path "progress.log" -Value $logEntry -Encoding UTF8
            Write-Host $logEntry -ForegroundColor Cyan
        }
        default { 
            Add-Content -Path "info.log" -Value $logEntry -Encoding UTF8
            Write-Host $logEntry -ForegroundColor White
        }
    }
    
    # Also write to master log
    Add-Content -Path "master.log" -Value $logEntry -Encoding UTF8
}

function Write-ErrorLog {
    param([string]$Message, [string]$Component = "MAIN", [string]$ServerName = "LOCAL")
    Write-DetailedLog -Message $Message -Level "ERROR" -Component $Component -ServerName $ServerName
}

function Write-SuccessLog {
    param([string]$Message, [string]$Component = "MAIN", [string]$ServerName = "LOCAL")
    Write-DetailedLog -Message $Message -Level "SUCCESS" -Component $Component -ServerName $ServerName
}

function Write-WarningLog {
    param([string]$Message, [string]$Component = "MAIN", [string]$ServerName = "LOCAL")
    Write-DetailedLog -Message $Message -Level "WARNING" -Component $Component -ServerName $ServerName
}

function Write-ProgressLog {
    param([string]$Message, [string]$Component = "MAIN", [string]$ServerName = "LOCAL")
    Write-DetailedLog -Message $Message -Level "PROGRESS" -Component $Component -ServerName $ServerName
}

# Enhanced Windows version detection with detailed logging


function Get-WindowsVersionDetailed {
    param([string]$ServerName = "LOCAL")
    
    Write-ProgressLog "Starting Windows version detection" -Component "VERSION_DETECT" -ServerName $ServerName
    $result = "Unknown"
    $methodUsed = "None"
    
    # Method 1: Using CimInstance (preferred method)
    try {
        Write-ProgressLog "Attempting CimInstance method for version detection" -Component "VERSION_DETECT" -ServerName $ServerName
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ($os) {
            $result = "$($os.Caption) Build $($os.BuildNumber)"
            $methodUsed = "CimInstance"
            Write-SuccessLog "Windows version determined via CimInstance: $result" -Component "VERSION_DETECT" -ServerName $ServerName
            return @{ Version = $result; Method = $methodUsed; Success = $true }
        }
    } catch {
        Write-ErrorLog "CimInstance version detection failed: $($_.Exception.Message)" -Component "VERSION_DETECT" -ServerName $ServerName
    }

    # Method 2: Using WMI
    try {
        Write-ProgressLog "Attempting WMI method for version detection" -Component "VERSION_DETECT" -ServerName $ServerName
        $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        if ($os) {
            $result = "$($os.Caption) Build $($os.BuildNumber)"
            $methodUsed = "WMI"
            Write-SuccessLog "Windows version determined via WMI: $result" -Component "VERSION_DETECT" -ServerName $ServerName
            return @{ Version = $result; Method = $methodUsed; Success = $true }
        }
    } catch {
        Write-ErrorLog "WMI version detection failed: $($_.Exception.Message)" -Component "VERSION_DETECT" -ServerName $ServerName
    }

    # Method 3: Using Registry
    try {
        Write-ProgressLog "Attempting Registry method for version detection" -Component "VERSION_DETECT" -ServerName $ServerName
        $currentVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop
        if ($currentVersion) {
            $productName = $currentVersion.ProductName
            $buildNumber = $currentVersion.CurrentBuildNumber
            $ubr = $currentVersion.UBR
            $result = "$productName Build $buildNumber.$ubr"
            $methodUsed = "Registry"
            Write-SuccessLog "Windows version determined via Registry: $result" -Component "VERSION_DETECT" -ServerName $ServerName
            return @{ Version = $result; Method = $methodUsed; Success = $true }
        }
    } catch {
        Write-ErrorLog "Registry version detection failed: $($_.Exception.Message)" -Component "VERSION_DETECT" -ServerName $ServerName
    }

    # Method 4: Using systeminfo command
    try {
        Write-ProgressLog "Attempting systeminfo method for version detection" -Component "VERSION_DETECT" -ServerName $ServerName
        $systemInfo = systeminfo | Select-String "OS Name:", "OS Version:"
        if ($systemInfo) {
            $osName = ($systemInfo[0] -split ":\s+")[1]
            $osVersion = ($systemInfo[1] -split ":\s+")[1]
            $result = "$osName $osVersion"
            $methodUsed = "SystemInfo"
            Write-SuccessLog "Windows version determined via systeminfo: $result" -Component "VERSION_DETECT" -ServerName $ServerName
            return @{ Version = $result; Method = $methodUsed; Success = $true }
        }
    } catch {
        Write-ErrorLog "Systeminfo version detection failed: $($_.Exception.Message)" -Component "VERSION_DETECT" -ServerName $ServerName
    }

    # Method 5: Using [Environment]::OSVersion
    try {
        Write-ProgressLog "Attempting Environment.OSVersion method for version detection" -Component "VERSION_DETECT" -ServerName $ServerName
        $osVersion = [Environment]::OSVersion
        if ($osVersion) {
            $result = "Windows $($osVersion.Version.Major).$($osVersion.Version.Minor) Build $($osVersion.Version.Build)"
            $methodUsed = "Environment.OSVersion"
            Write-SuccessLog "Windows version determined via Environment.OSVersion: $result" -Component "VERSION_DETECT" -ServerName $ServerName
            return @{ Version = $result; Method = $methodUsed; Success = $true }
        }
    } catch {
        Write-ErrorLog "Environment.OSVersion detection failed: $($_.Exception.Message)" -Component "VERSION_DETECT" -ServerName $ServerName
    }

    Write-ErrorLog "All Windows version detection methods failed" -Component "VERSION_DETECT" -ServerName $ServerName
    return @{ Version = $result; Method = $methodUsed; Success = $false }
}

# Enhanced reboot information detection with comprehensive logging
function Get-LastRebootInfo {
    param([string]$ServerName = "LOCAL")
    
    Write-ProgressLog "Starting last reboot detection using multiple methods" -Component "REBOOT_DETECT" -ServerName $ServerName
    $result = @{
        LastReboot = "Unknown"
        Method = "None"
        Success = $false
        UptimeDays = -1
        Details = @()
    }

    # Method 1: Try CIM Instance (Primary Method)
    try {
        Write-ProgressLog "Attempting CIM method for reboot detection" -Component "REBOOT_DETECT" -ServerName $ServerName
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ($os.LastBootUpTime) {
            $bootTime = $os.LastBootUpTime
            $result.LastReboot = $bootTime.ToString("yyyy-MM-dd HH:mm:ss")
            $result.UptimeDays = [math]::Round(((Get-Date) - $bootTime).TotalDays, 2)
            $result.Method = "CIM-Win32_OperatingSystem"
            $result.Success = $true
            $result.Details += "Boot time: $($bootTime)"
            $result.Details += "Uptime: $($result.UptimeDays) days"
            Write-SuccessLog "Reboot info via CIM: Last boot $($result.LastReboot), Uptime: $($result.UptimeDays) days" -Component "REBOOT_DETECT" -ServerName $ServerName
            return $result
        }
    } catch {
        Write-ErrorLog "CIM reboot detection failed: $($_.Exception.Message)" -Component "REBOOT_DETECT" -ServerName $ServerName
        $result.Details += "CIM failed: $($_.Exception.Message)"
    }

    # Method 2: Try WMI if Method 1 failed
    try {
        Write-ProgressLog "Attempting WMI method for reboot detection" -Component "REBOOT_DETECT" -ServerName $ServerName
        $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        if ($os.LastBootUpTime) {
            $bootTime = [Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)
            $result.LastReboot = $bootTime.ToString("yyyy-MM-dd HH:mm:ss")
            $result.UptimeDays = [math]::Round(((Get-Date) - $bootTime).TotalDays, 2)
            $result.Method = "WMI-Win32_OperatingSystem"
            $result.Success = $true
            $result.Details += "Boot time: $($bootTime)"
            $result.Details += "Uptime: $($result.UptimeDays) days"
            Write-SuccessLog "Reboot info via WMI: Last boot $($result.LastReboot), Uptime: $($result.UptimeDays) days" -Component "REBOOT_DETECT" -ServerName $ServerName
            return $result
        }
    } catch {
        Write-ErrorLog "WMI reboot detection failed: $($_.Exception.Message)" -Component "REBOOT_DETECT" -ServerName $ServerName
        $result.Details += "WMI failed: $($_.Exception.Message)"
    }

    # Method 3: Try SystemInfo parsing
    try {
        Write-ProgressLog "Attempting SystemInfo method for reboot detection" -Component "REBOOT_DETECT" -ServerName $ServerName
        $systemInfo = systeminfo /fo csv | ConvertFrom-Csv
        $bootTimeString = $systemInfo.'System Boot Time'
        if ($bootTimeString -and $bootTimeString -ne "N/A") {
            $bootTime = [DateTime]::Parse($bootTimeString)
            $result.LastReboot = $bootTime.ToString("yyyy-MM-dd HH:mm:ss")
            $result.UptimeDays = [math]::Round(((Get-Date) - $bootTime).TotalDays, 2)
            $result.Method = "SystemInfo-CSV"
            $result.Success = $true
            $result.Details += "Boot time: $($bootTime)"
            $result.Details += "Uptime: $($result.UptimeDays) days"
            Write-SuccessLog "Reboot info via SystemInfo: Last boot $($result.LastReboot), Uptime: $($result.UptimeDays) days" -Component "REBOOT_DETECT" -ServerName $ServerName
            return $result
        }
    } catch {
        Write-ErrorLog "SystemInfo reboot detection failed: $($_.Exception.Message)" -Component "REBOOT_DETECT" -ServerName $ServerName
        $result.Details += "SystemInfo failed: $($_.Exception.Message)"
    }

    # Method 4: Try Event Log (System startup events)
    try {
        Write-ProgressLog "Attempting Event Log method for reboot detection" -Component "REBOOT_DETECT" -ServerName $ServerName
        $events = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            ID = @(6005, 6009, 1074)  # System startup and shutdown events
        } -MaxEvents 10 -ErrorAction Stop | Sort-Object TimeCreated -Descending
        
        $startupEvent = $events | Where-Object { $_.Id -eq 6005 } | Select-Object -First 1
        if ($startupEvent) {
            $bootTime = $startupEvent.TimeCreated
            $result.LastReboot = $bootTime.ToString("yyyy-MM-dd HH:mm:ss")
            $result.UptimeDays = [math]::Round(((Get-Date) - $bootTime).TotalDays, 2)
            $result.Method = "EventLog-System-6005"
            $result.Success = $true
            $result.Details += "Boot time from Event ID 6005: $($bootTime)"
            $result.Details += "Uptime: $($result.UptimeDays) days"
            Write-SuccessLog "Reboot info via Event Log: Last boot $($result.LastReboot), Uptime: $($result.UptimeDays) days" -Component "REBOOT_DETECT" -ServerName $ServerName
            return $result
        }
    } catch {
        Write-ErrorLog "Event Log reboot detection failed: $($_.Exception.Message)" -Component "REBOOT_DETECT" -ServerName $ServerName
        $result.Details += "Event Log failed: $($_.Exception.Message)"
    }

    # Method 5: Try Net Statistics
    try {
        Write-ProgressLog "Attempting Net Statistics method for reboot detection" -Component "REBOOT_DETECT" -ServerName $ServerName
        $netStats = net statistics server 2>$null
        $statsLine = $netStats | Select-String "Statistics since"
        if ($statsLine) {
            $statsString = $statsLine.ToString()
            if ($statsString -match "Statistics since (.+)") {
                $bootTime = [DateTime]::Parse($matches[1])
                $result.LastReboot = $bootTime.ToString("yyyy-MM-dd HH:mm:ss")
                $result.UptimeDays = [math]::Round(((Get-Date) - $bootTime).TotalDays, 2)
                $result.Method = "NetStatistics-Server"
                $result.Success = $true
                $result.Details += "Boot time from Net Statistics: $($bootTime)"
                $result.Details += "Uptime: $($result.UptimeDays) days"
                Write-SuccessLog "Reboot info via Net Statistics: Last boot $($result.LastReboot), Uptime: $($result.UptimeDays) days" -Component "REBOOT_DETECT" -ServerName $ServerName
                return $result
            }
        }
    } catch {
        Write-ErrorLog "Net Statistics reboot detection failed: $($_.Exception.Message)" -Component "REBOOT_DETECT" -ServerName $ServerName
        $result.Details += "Net Statistics failed: $($_.Exception.Message)"
    }

    # If all methods failed, log detailed failure information
    Write-ErrorLog "All reboot detection methods failed for server $ServerName" -Component "REBOOT_DETECT" -ServerName $ServerName
    Write-ErrorLog "Failed methods details: $($result.Details -join '; ')" -Component "REBOOT_DETECT" -ServerName $ServerName
    return $result
}

function Enable-CredSSPClient {
    param([string]$TrustedHosts = "*")
    Write-ProgressLog "Starting CredSSP Client configuration for hosts: $TrustedHosts" -Component "CREDSSP"
    try {
        Enable-WSManCredSSP -Role Client -DelegateComputer $TrustedHosts -Force
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
        if (!(Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
            Write-ProgressLog "Created CredSSP registry path: $regPath" -Component "CREDSSP"
        }
        Set-ItemProperty -Path $regPath -Name "AllowFreshCredentials" -Value 1
        Set-ItemProperty -Path $regPath -Name "ConcatenateDefaults_AllowFresh" -Value 1
        $credPath = "$regPath\AllowFreshCredentials"
        if (!(Test-Path $credPath)) {
            New-Item -Path $credPath -Force | Out-Null
        }
        Set-ItemProperty -Path $credPath -Name "1" -Value "wsman/$TrustedHosts"
        Write-SuccessLog "CredSSP Client enabled successfully for $TrustedHosts" -Component "CREDSSP"
        return $true
    } catch {
        Write-ErrorLog "Enable-CredSSPClient failed: $($_.Exception.Message)" -Component "CREDSSP"
        return $false
    }
}

function Set-WindowsUpdateRegistryKeys {
    param([string]$ServerName = "LOCAL")
    Write-ProgressLog "Starting Windows Update registry configuration" -Component "REGISTRY" -ServerName $ServerName
    $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $changes = @()
    
    try {
        if (!(Test-Path $wuPath)) {
            New-Item -Path $wuPath -Force | Out-Null
            $changes += "Created Windows Update registry path: $wuPath"
            Write-ProgressLog "Created Windows Update registry path: $wuPath" -Component "REGISTRY" -ServerName $ServerName
        }
        
        $currentDisableAccess = (Get-ItemProperty -Path $wuPath -Name "DisableWindowsUpdateAccess" -ErrorAction SilentlyContinue)."DisableWindowsUpdateAccess"
        Write-ProgressLog "Current DisableWindowsUpdateAccess value: $currentDisableAccess" -Component "REGISTRY" -ServerName $ServerName
        
        if ($currentDisableAccess -ne 0) {
            Set-ItemProperty -Path $wuPath -Name "DisableWindowsUpdateAccess" -Value 0 -Type DWord
            $changes += "DisableWindowsUpdateAccess set to 0 (was: $currentDisableAccess)"
            Write-SuccessLog "Registry modified: DisableWindowsUpdateAccess set to 0 (was: $currentDisableAccess)" -Component "REGISTRY" -ServerName $ServerName
        } else {
            Write-ProgressLog "Registry check: DisableWindowsUpdateAccess already set to 0" -Component "REGISTRY" -ServerName $ServerName
        }
        
        $currentElevate = (Get-ItemProperty -Path $wuPath -Name "ElevateNonAdmins" -ErrorAction SilentlyContinue)."ElevateNonAdmins"
        Write-ProgressLog "Current ElevateNonAdmins value: $currentElevate" -Component "REGISTRY" -ServerName $ServerName
        
        if ($currentElevate -ne 0) {
            Set-ItemProperty -Path $wuPath -Name "ElevateNonAdmins" -Value 0 -Type DWord
            $changes += "ElevateNonAdmins set to 0 (was: $currentElevate)"
            Write-SuccessLog "Registry modified: ElevateNonAdmins set to 0 (was: $currentElevate)" -Component "REGISTRY" -ServerName $ServerName
        } else {
            Write-ProgressLog "Registry check: ElevateNonAdmins already set to 0" -Component "REGISTRY" -ServerName $ServerName
        }
        
        if ($changes.Count -gt 0) {
            Write-ProgressLog "Registry changes detected, restarting Windows Update service" -Component "REGISTRY" -ServerName $ServerName
            try {
                $serviceStatus = Get-Service -Name wuauserv
                Write-ProgressLog "Windows Update service current status: $($serviceStatus.Status)" -Component "REGISTRY" -ServerName $ServerName
                
                Set-Service -Name wuauserv -StartupType Automatic
                Write-ProgressLog "Windows Update service startup type set to Automatic" -Component "REGISTRY" -ServerName $ServerName
                
                Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
                Write-ProgressLog "Windows Update service stopped" -Component "REGISTRY" -ServerName $ServerName
                
                Start-Sleep -Seconds 2
                
                Start-Service -Name wuauserv
                Write-ProgressLog "Windows Update service started" -Component "REGISTRY" -ServerName $ServerName
                
                Start-Sleep -Seconds 3
                
                $newServiceStatus = Get-Service -Name wuauserv
                Write-SuccessLog "Windows Update service restart completed. New status: $($newServiceStatus.Status)" -Component "REGISTRY" -ServerName $ServerName
                $changes += "Windows Update service restarted successfully"
            } catch {
                Write-ErrorLog "Could not restart Windows Update service: $($_.Exception.Message)" -Component "REGISTRY" -ServerName $ServerName
                $changes += "Failed to restart Windows Update service: $($_.Exception.Message)"
            }
        }
        
        Write-SuccessLog "Windows Update registry configuration completed. Changes made: $($changes -join '; ')" -Component "REGISTRY" -ServerName $ServerName
        return @{ Success = $true; Changes = $changes }
    } catch {
        Write-ErrorLog "Error modifying Windows Update registry settings: $($_.Exception.Message)" -Component "REGISTRY" -ServerName $ServerName
        return @{ Success = $false; Changes = $changes; Error = $_.Exception.Message }
    }
}

function Enable-WindowsUpdatesPolicy {
    param(
        [bool]$ForceInstall = $false,
        [string]$RebootTime = "03:00",
        [string]$ServerName = "LOCAL"
    )
    
    Write-ProgressLog "Starting Windows Update policy configuration. ForceInstall: $ForceInstall, RebootTime: $RebootTime" -Component "POLICY" -ServerName $ServerName
    
    $result = @{
        Success = $false
        Message = ""
        Changes = @()
        BackupPath = ""
    }
    
    try {
        $auPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        
                # Backup current policies
        $backupPath = "HKLM:\SOFTWARE\BackupWindowsUpdatePolicies_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        if (Test-Path $auPath) {
            try {
                Copy-Item -Path $auPath -Destination $backupPath -Recurse -Force
                $result.Changes += "Backed up current policies to $backupPath"
                $result.BackupPath = $backupPath
                Write-SuccessLog "Current policies backed up to: $backupPath" -Component "POLICY" -ServerName $ServerName
            } catch {
                Write-WarningLog "Failed to backup policies: $($_.Exception.Message)" -Component "POLICY" -ServerName $ServerName
            }
        }

        $backupFile = "C:\BackupWindowsUpdatePolicies_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
try {
    $exportCmd = "reg.exe export `"HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`" `"$backupFile`" /y"
    Invoke-Expression $exportCmd
    $result.Changes += "Backed up current policies to $backupFile"
    $result.BackupPath = $backupFile
    Write-SuccessLog "Current policies backed up to: $backupFile" -Component "POLICY" -ServerName $ServerName
} catch {
    Write-WarningLog "Failed to backup policies: $($_.Exception.Message)" -Component "POLICY" -ServerName $ServerName
}



        # Log current policy values before changes
        $currentPolicies = @{}
        try {
            $currentPolicies.NoAutoUpdate = (Get-ItemProperty -Path $auPath -Name "NoAutoUpdate" -ErrorAction SilentlyContinue)."NoAutoUpdate"
            $currentPolicies.AUOptions = (Get-ItemProperty -Path $auPath -Name "AUOptions" -ErrorAction SilentlyContinue)."AUOptions"
            $currentPolicies.UseWUServer = (Get-ItemProperty -Path $auPath -Name "UseWUServer" -ErrorAction SilentlyContinue)."UseWUServer"
            Write-ProgressLog "Current policy values - NoAutoUpdate: $($currentPolicies.NoAutoUpdate), AUOptions: $($currentPolicies.AUOptions), UseWUServer: $($currentPolicies.UseWUServer)" -Component "POLICY" -ServerName $ServerName
        } catch {
            Write-WarningLog "Could not read current policy values: $($_.Exception.Message)" -Component "POLICY" -ServerName $ServerName
        }

        # Apply new policy settings
        Set-ItemProperty -Path $auPath -Name "NoAutoUpdate" -Value 0 -Type DWord
        $result.Changes += "Enabled automatic updates (NoAutoUpdate=0, was: $($currentPolicies.NoAutoUpdate))"
        Write-ProgressLog "Set NoAutoUpdate to 0 (was: $($currentPolicies.NoAutoUpdate))" -Component "POLICY" -ServerName $ServerName

        Set-ItemProperty -Path $auPath -Name "AUOptions" -Value 4 -Type DWord
        $result.Changes += "Set AUOptions to 4 (auto download and schedule install, was: $($currentPolicies.AUOptions))"
        Write-ProgressLog "Set AUOptions to 4 (was: $($currentPolicies.AUOptions))" -Component "POLICY" -ServerName $ServerName

        Set-ItemProperty -Path $auPath -Name "ScheduledInstallDay" -Value 0 -Type DWord
        $result.Changes += "Set scheduled install day to daily"

        $hour = [int]$RebootTime.Split(':')[0]
        Set-ItemProperty -Path $auPath -Name "ScheduledInstallTime" -Value $hour -Type DWord
        $result.Changes += "Set scheduled install time to $hour:00"
        Write-ProgressLog "Set scheduled install time to $hour:00" -Component "POLICY" -ServerName $ServerName

        Set-ItemProperty -Path $auPath -Name "NoAutoRebootWithLoggedOnUsers" -Value 0 -Type DWord
        $result.Changes += "Enabled automatic reboot"

        Set-ItemProperty -Path $auPath -Name "RebootWarningTimeoutEnabled" -Value 1 -Type DWord
        Set-ItemProperty -Path $auPath -Name "RebootWarningTimeout" -Value 15 -Type DWord
        $result.Changes += "Set reboot warning to 15 minutes"

        Remove-ItemProperty -Path $wuPath -Name "DisableWindowsUpdateAccess" -ErrorAction SilentlyContinue
        $result.Changes += "Removed DisableWindowsUpdateAccess restriction"

        Set-ItemProperty -Path $auPath -Name "UseWUServer" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        $result.Changes += "Disabled WSUS-only restriction (UseWUServer=0, was: $($currentPolicies.UseWUServer))"
        Write-ProgressLog "Set UseWUServer to 0 (was: $($currentPolicies.UseWUServer))" -Component "POLICY" -ServerName $ServerName

        if ($ForceInstall) {
            Set-ItemProperty -Path $auPath -Name "DetectionFrequencyEnabled" -Value 1 -Type DWord
            Set-ItemProperty -Path $auPath -Name "DetectionFrequency" -Value 1 -Type DWord
            $result.Changes += "Enabled frequent update detection (1 hour)"
            Write-ProgressLog "Enabled frequent update detection (1 hour)" -Component "POLICY" -ServerName $ServerName
        }

        # Windows Update for Business settings
        Set-ItemProperty -Path $wuPath -Name "DeferQualityUpdates" -Value 0 -Type DWord
        Set-ItemProperty -Path $wuPath -Name "DeferQualityUpdatesPeriodInDays" -Value 3 -Type DWord
        Set-ItemProperty -Path $wuPath -Name "SetComplianceDeadline" -Value 1 -Type DWord
        Set-ItemProperty -Path $wuPath -Name "ComplianceDeadlineGracePeriod" -Value 3 -Type DWord
        Set-ItemProperty -Path $wuPath -Name "QualityUpdateDeadlineInDays" -Value 3 -Type DWord
        Set-ItemProperty -Path $wuPath -Name "FeatureUpdateDeadlineInDays" -Value 3 -Type DWord
        $result.Changes += "Configured Windows Update for Business settings"
        Write-ProgressLog "Configured Windows Update for Business settings" -Component "POLICY" -ServerName $ServerName

        # Apply registry changes
        $registryResult = Set-WindowsUpdateRegistryKeys -ServerName $ServerName
        if ($registryResult.Success) {
            $result.Changes += $registryResult.Changes
        } else {
            Write-WarningLog "Registry configuration had issues: $($registryResult.Error)" -Component "POLICY" -ServerName $ServerName
        }

        $result.Success = $true
        $result.Message = "Windows Update policies modified successfully"
        Write-SuccessLog "Windows Update policies configured successfully. Changes: $($result.Changes.Count)" -Component "POLICY" -ServerName $ServerName
        
    } catch {
        Write-ErrorLog "Enable-WindowsUpdatesPolicy failed: $($_.Exception.Message)" -Component "POLICY" -ServerName $ServerName
        $result.Success = $false
        $result.Message = "Failed to modify policies: $($_.Exception.Message)"
    }
    
    return $result
}

function Force-WindowsUpdateInstallation {
    param(
        [string]$ServerName = "LOCAL",
        [switch]$NoReboot
    )

    $result = @{
        Success = $false
        Message = ""
        UpdatesFound = 0
        UpdatesInstalled = 0
        MethodsAttempted = @()
        Errors = @()
        RebootRequired = $false
    }

    Write-Host "🔄 Starting Windows Update installation process..." -ForegroundColor Yellow
    
    # 1. Configure Windows Update Service
    try {
        $wuauserv = Get-Service -Name wuauserv
        if ($wuauserv.StartType -ne 'Automatic') {
            Set-Service -Name wuauserv -StartupType Automatic
            $result.Message += "Set Windows Update service to Automatic. "
        }
        
        if ($wuauserv.Status -ne 'Running') {
            Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
            Start-Service -Name wuauserv
            Start-Sleep -Seconds 3
            $result.Message += "Windows Update service restarted. "
        }
    } catch {
        $result.Errors += "Service configuration failed: $($_.Exception.Message)"
        Write-ErrorLog "Force-WindowsUpdateInstallation: Service configuration failed: $($_.Exception.Message)"
    }

    # 2. Try PSWindowsUpdate module first (most reliable method)
    try {
        $result.MethodsAttempted += "PSWindowsUpdate"
        if (!(Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Install-Module -Name PSWindowsUpdate -Force -AllowClobber -Scope CurrentUser -ErrorAction Stop
            Import-Module PSWindowsUpdate -Force
        }

        $updates = Get-WindowsUpdate -AcceptAll -IgnoreReboot
        $result.UpdatesFound = ($updates | Measure-Object).Count

        if ($result.UpdatesFound -gt 0) {
            Write-Host "📦 Found $($result.UpdatesFound) updates using PSWindowsUpdate" -ForegroundColor Green
            foreach ($update in $updates) {
                Write-Host "  • $($update.Title)" -ForegroundColor White
            }

            $installResult = Install-WindowsUpdate -AcceptAll -IgnoreReboot -Verbose
            $result.UpdatesInstalled = ($installResult | Where-Object {$_.Result -eq "Installed"} | Measure-Object).Count
            $result.Success = $true
            $result.Message += "Updates installed using PSWindowsUpdate. "
            $result.RebootRequired = $installResult.RebootRequired
            return $result
        }
    } catch {
        $result.Errors += "PSWindowsUpdate method failed: $($_.Exception.Message)"
        Write-ErrorLog "Force-WindowsUpdateInstallation: PSWindowsUpdate failed: $($_.Exception.Message)"
        # Continue to next method
    }

    # 3. Try Windows Update Agent COM API
    try {
        $result.MethodsAttempted += "COM API"
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        
        Write-Host "🔍 Searching for available updates using WUA API..." -ForegroundColor Cyan
        $searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
        $result.UpdatesFound = $searchResult.Updates.Count

        if ($searchResult.Updates.Count -gt 0) {
            Write-Host "📦 Found $($searchResult.Updates.Count) updates to install" -ForegroundColor Green
            $updatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl

            foreach ($update in $searchResult.Updates) {
                $update.AcceptEula()
                $updatesToInstall.Add($update) | Out-Null
                Write-Host "  • $($update.Title)" -ForegroundColor White
            }

            Write-Host "⬇️  Downloading updates..." -ForegroundColor Cyan
            $downloader = $updateSession.CreateUpdateDownloader()
            $downloader.Updates = $updatesToInstall
            $downloadResult = $downloader.Download()

            if ($downloadResult.ResultCode -eq 2) { # orcSucceeded
                Write-Host "✅ Updates downloaded successfully" -ForegroundColor Green
                Write-Host "⚙️  Installing updates..." -ForegroundColor Cyan

                $installer = $updateSession.CreateUpdateInstaller()
                $installer.Updates = $updatesToInstall
                $installResult = $installer.Install()

                $result.UpdatesInstalled = ($updatesToInstall | Where-Object {$installResult.GetUpdateResult($_).ResultCode -eq 2} | Measure-Object).Count
                
                if ($installResult.ResultCode -eq 2) { # orcSucceeded
                    $result.Success = $true
                    $result.Message += "Updates installed successfully via COM API. "
                    $result.RebootRequired = $installResult.RebootRequired
                } else {
                    throw "Installation failed with code: $($installResult.ResultCode)"
                }
            } else {
                throw "Download failed with code: $($downloadResult.ResultCode)"
            }
        } else {
            $result.Success = $true
            $result.Message += "No updates available via COM API. "
        }
    } catch {
        $result.Errors += "COM API method failed: $($_.Exception.Message)"
        Write-ErrorLog "Force-WindowsUpdateInstallation: COM API failed: $($_.Exception.Message)"
    }

    # 4. Try UsoClient (Windows 10/Server 2016+)
    if (-not $result.Success) {
        try {
            $result.MethodsAttempted += "UsoClient"
            $usoClientPath = "$env:SystemRoot\System32\UsoClient.exe"
            
            if (Test-Path $usoClientPath) {
                Write-Host "🔄 Attempting update using UsoClient..." -ForegroundColor Cyan
                Start-Process -FilePath $usoClientPath -ArgumentList "StartScan" -Wait -NoNewWindow
                Start-Sleep -Seconds 30
                Start-Process -FilePath $usoClientPath -ArgumentList "StartDownload" -Wait -NoNewWindow
                Start-Sleep -Seconds 30
                Start-Process -FilePath $usoClientPath -ArgumentList "StartInstall" -Wait -NoNewWindow
                
                $result.Success = $true
                $result.Message += "Updates initiated via UsoClient. "
                # Note: UsoClient doesn't provide direct feedback about updates installed
            }
        } catch {
            $result.Errors += "UsoClient method failed: $($_.Exception.Message)"
            Write-ErrorLog "Force-WindowsUpdateInstallation: UsoClient failed: $($_.Exception.Message)"
        }
    }

    # 5. Final attempt with wuauclt (Legacy systems)
    if (-not $result.Success) {
        try {
            $result.MethodsAttempted += "WUAUCLT"
            Write-Host "🔄 Attempting update using WUAUCLT..." -ForegroundColor Cyan
            Start-Process "wuauclt.exe" -ArgumentList "/detectnow /updatenow" -Wait -NoNewWindow
            Start-Sleep -Seconds 60
            $result.Message += "Updates initiated via WUAUCLT. "
            $result.Success = $true
        } catch {
            $result.Errors += "WUAUCLT method failed: $($_.Exception.Message)"
            Write-ErrorLog "Force-WindowsUpdateInstallation: WUAUCLT failed: $($_.Exception.Message)"
        }
    }

    # Final status check
    if (-not $result.Success) {
        $result.Message = "All update methods failed. "
        Write-ErrorLog "Force-WindowsUpdateInstallation: All methods failed. Errors: $($result.Errors -join '; ')"
    }

    # Return detailed results
    $result | Add-Member -NotePropertyName "TimeStamp" -NotePropertyValue (Get-Date)
    Write-Host "`n📊 Update Process Summary:" -ForegroundColor Cyan
    Write-Host "Success: $($result.Success)" -ForegroundColor $(if ($result.Success) { "Green" } else { "Red" })
    Write-Host "Updates Found: $($result.UpdatesFound)" -ForegroundColor White
    Write-Host "Updates Installed: $($result.UpdatesInstalled)" -ForegroundColor White
    Write-Host "Methods Attempted: $($result.MethodsAttempted -join ', ')" -ForegroundColor White
    Write-Host "Reboot Required: $($result.RebootRequired)" -ForegroundColor $(if ($result.RebootRequired) { "Yellow" } else { "Green" })
    if ($result.Errors.Count -gt 0) {
        Write-Host "`nErrors Encountered:" -ForegroundColor Red
        $result.Errors | ForEach-Object { Write-Host "- $_" -ForegroundColor Red }
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

    # Modify the credential collection and validation part in your script
    Write-Host "`n🔐 Please enter domain credentials..." -ForegroundColor Cyan
    $maxAttempts = 3
    $attempt = 1

do {
    if ($attempt -gt 1) {
        Write-Host "`n⚠️ Attempt $attempt of $maxAttempts" -ForegroundColor Yellow
    }
    
    $cred = Get-Credential -Message "Enter domain credentials for server access (Attempt $attempt of $maxAttempts)"
    
    if ($null -eq $cred) {
        Write-Host "❌ Credential entry cancelled by user" -ForegroundColor Red
        return
    }

    Write-Host "`n🔄 Validating credentials..." -ForegroundColor Cyan
    $authResult = Test-DomainCredential -Credential $cred -DomainController "nwk-dc101"
    
    if ($authResult.Success) {
        Write-Host "✅ Authentication successful!" -ForegroundColor Green
        Write-Host "👤 Logged in as: $($authResult.Username)" -ForegroundColor Green
        Write-Host "🔵 $($authResult.Message)" -ForegroundColor Green
        break
    }
    else {
        Write-Host "❌ Authentication failed!" -ForegroundColor Red
        Write-Host "⚠️ $($authResult.Message)" -ForegroundColor Yellow
        
        if ($attempt -ge $maxAttempts) {
            Write-Host "`n❌ Maximum authentication attempts reached. Exiting script." -ForegroundColor Red
            return
        }
    }
    
    $attempt++
} while ($attempt -le $maxAttempts)

# Only continue if authentication was successful
if (-not $authResult.Success) {
    return
}

    $outputFile = "NON-AD-Prodservers-ForceUpdate.csv"
    $results = @()
    Write-Host "🔍 Retrieving servers from AD..." -ForegroundColor Cyan
   $patterns = @('*TST*', 'ACC*', '*DEV*', '*-TS*', '*ACC*','TST*','ALG*','*CIC*','VWS*')
   #$patterns = @('PAR-TST-*')
# Dynamically construct the filter string
$filterString = ($patterns | ForEach-Object { "Name -like '$_'" }) -join ' -or '

try {
    $servers = Get-ADComputer -Filter $filterString -Server $DCname -Properties Name, IPv4Address
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

        Write-Host "`n🔍 Running authentication diagnostics..." -ForegroundColor Cyan
        $authDiagnostics = Test-RemoteAuthentication -Server $serverName -Credential $cred
        
        # Log the diagnostic results
        Write-Host "`n📋 Authentication Diagnostic Results:" -ForegroundColor Yellow
        foreach ($test in $authDiagnostics.Tests) {
            $color = if ($test.Result) { "Green" } else { "Red" }
            Write-Host "  $($test.Name): $(if ($test.Result) { '✅' } else { '❌' }) - $($test.Message)" -ForegroundColor $color
        }

         
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


                        if (-not $updateSuccess) {
        # Fallback 1: Try PowerShell Update cmdlets (if available)
        try {
            Import-Module PSWindowsUpdate -ErrorAction Stop
            Install-WindowsUpdate -AcceptAll -AutoReboot -IgnoreReboot -ErrorAction Stop
            $updateSuccess = $true
        } catch {
            $errorDetails += "PSWindowsUpdate cmdlets failed: $($_.Exception.Message)"
        }
    }

        if (-not $updateSuccess) {
            # Fallback 2: Try wuauclt.exe
            try {
                Start-Process -FilePath "wuauclt.exe" -ArgumentList "/detectnow /updatenow" -NoNewWindow -Wait
                Start-Sleep -Seconds 10
                $updateSuccess = $true  # This doesn't guarantee update, just triggers it
            } catch {
                $errorDetails += "wuauclt.exe failed: $($_.Exception.Message)"
            }
        }

        if (-not $updateSuccess) {
            # Fallback 3: Try usoclient.exe (Windows 10+)
            try {
                Start-Process -FilePath "usoclient.exe" -ArgumentList "StartScan" -NoNewWindow -Wait
                Start-Process -FilePath "usoclient.exe" -ArgumentList "StartDownload" -NoNewWindow -Wait
                Start-Process -FilePath "usoclient.exe" -ArgumentList "StartInstall" -NoNewWindow -Wait
                $updateSuccess = $true
            } catch {
                $errorDetails += "usoclient.exe failed: $($_.Exception.Message)"
            }
        }

        if (-not $updateSuccess) {
            $errorDetails += "All force update methods failed."
        }

        # Always log details if nothing works
        if (-not $updateSuccess) {
            $logPath = "error.log"
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Add-Content -Path $logPath -Value "$timestamp [ERROR] [UPDATE] [$env:COMPUTERNAME] Force update failed. Details: $($errorDetails -join '; ')"
        }

        return @{
            UpdateSuccess = $updateSuccess
            ErrorDetails = $errorDetails
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

        # Ensure update is downloaded
        if (-not $update.IsDownloaded) {
            $updateDownloader = $update.Session.CreateUpdateDownloader()
            $singleUpdateColl = New-Object -ComObject Microsoft.Update.UpdateColl
            $singleUpdateColl.Add($update) | Out-Null
            $updateDownloader.Updates = $singleUpdateColl
            $downloadResult = $updateDownloader.Download()
            if ($downloadResult.ResultCode -ne 2) {
                throw "Download failed (code $($downloadResult.ResultCode))"
            }
        }

        # Install the update
        $installer = New-Object -ComObject Microsoft.Update.Installer
        $singleUpdateColl = New-Object -ComObject Microsoft.Update.UpdateColl
        $singleUpdateColl.Add($update) | Out-Null
        $installer.Updates = $singleUpdateColl
        $installResult = $installer.Install()

        if ($installResult.ResultCode -eq 2) {
            Write-SuccessLog "Update installed: $($update.Title)" -Component "UPDATE"
            $result.Details += "Update installed: $($update.Title)"
        } else {
            $failMsg = "Install failed for $($update.Title): Code $($installResult.ResultCode)"
            Write-ErrorLog $failMsg -Component "UPDATE"
            $result.Details += $failMsg
        }
    } catch {
        $failMsg = "Update failed: $($update.Title): $($_.Exception.Message)"
        Write-ErrorLog $failMsg -Component "UPDATE"
        $result.Details += $failMsg
        Write-Host "    ⚠️ Failed to install update" -ForegroundColor Yellow
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
                                if ($updateResult.Success) {
                                    Write-Host "Updates completed successfully using $($updateResult.MethodUsed)" -ForegroundColor Green
                                    } else {
                                        Write-Host "Update process failed: $($updateResult.Message)" -ForegroundColor Red
                                        }

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
            if (-not $remoteResult.UpdateSuccess) {
              Write-ErrorLog "Server $($serverName) : Force update failed. Details: $($remoteResult.ErrorDetails -join '; ')" -Component "UPDATE" -ServerName $serverName
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
} # <--- CLOSES function Start-ServerUpdateCheck

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
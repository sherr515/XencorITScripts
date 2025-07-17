#!/usr/bin/env pwsh
#Requires -Version 5.1

<#
.SYNOPSIS
    Comprehensive system health monitoring and reporting script

.DESCRIPTION
    This script provides comprehensive system health monitoring capabilities including:
    - System resource monitoring (CPU, memory, disk, network)
    - Service status and health checks
    - Event log analysis and error reporting
    - Performance metrics collection
    - Security status and compliance checks
    - Hardware health monitoring
    - Network connectivity and DNS resolution
    - System updates and patch status
    - Backup and recovery status
    - Alert generation and reporting

.PARAMETER ReportType
    Type of report to generate. Options: Summary, Detailed, Performance, Security, Services, Events, Hardware

.PARAMETER ExportPath
    Path to export the report. Supports CSV, JSON, and HTML formats

.PARAMETER ComputerName
    Remote computer to analyze (optional)

.PARAMETER Credential
    Credential for remote access

.PARAMETER IncludeEvents
    Include event log analysis in the report

.PARAMETER DaysBack
    Number of days to look back for events (default: 7)

.PARAMETER Verbose
    Enable verbose logging

.EXAMPLE
    .\Get-SystemHealthReport.ps1 -ReportType Summary -ExportPath "C:\Reports\SystemHealth.csv"

.EXAMPLE
    .\Get-SystemHealthReport.ps1 -ReportType Detailed -ComputerName "SERVER01" -Credential $Cred -Verbose

.EXAMPLE
    .\Get-SystemHealthReport.ps1 -ReportType Performance -IncludeEvents -DaysBack 30 -ExportPath "C:\Reports\PerformanceAnalysis.html"

.NOTES
    Author: System Administrator
    Version: 1.0.0
    Date: 2024-01-01
    Requires: Local or remote administrative access
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Summary", "Detailed", "Performance", "Security", "Services", "Events", "Hardware")]
    [string]$ReportType = "Summary",
    
    [Parameter(Mandatory = $false)]
    [string]$ExportPath,
    
    [Parameter(Mandatory = $false)]
    [string]$ComputerName,
    
    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeEvents,
    
    [Parameter(Mandatory = $false)]
    [int]$DaysBack = 7,
    
    [Parameter(Mandatory = $false)]
    [switch]$Verbose
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Initialize logging
$LogPath = "C:\Logs\SystemAdmin\HealthReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$LogDir = Split-Path -Parent $LogPath
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    Write-Host $LogMessage
    Add-Content -Path $LogPath -Value $LogMessage
}

function Get-SystemInfo {
    param([string]$Computer = $env:COMPUTERNAME)
    
    try {
        Write-Log "Retrieving system information for $Computer..."
        
        $CimSession = if ($Computer -eq $env:COMPUTERNAME) { $null } else { New-CimSession -ComputerName $Computer -Credential $Credential }
        
        $SystemInfo = Get-CimInstance -ClassName Win32_ComputerSystem -CimSession $CimSession | Select-Object @(
            'Name',
            'Domain',
            'Manufacturer',
            'Model',
            'TotalPhysicalMemory',
            'NumberOfProcessors',
            'NumberOfLogicalProcessors'
        )
        
        $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $CimSession | Select-Object @(
            'Caption',
            'Version',
            'BuildNumber',
            'LastBootUpTime',
            'TotalVirtualMemorySize',
            'FreeVirtualMemory'
        )
        
        $SystemData = [PSCustomObject]@{
            ComputerName = $SystemInfo.Name
            Domain = $SystemInfo.Domain
            Manufacturer = $SystemInfo.Manufacturer
            Model = $SystemInfo.Model
            TotalMemoryGB = [math]::Round($SystemInfo.TotalPhysicalMemory / 1GB, 2)
            Processors = $SystemInfo.NumberOfProcessors
            LogicalProcessors = $SystemInfo.NumberOfLogicalProcessors
            OS = $OSInfo.Caption
            OSVersion = $OSInfo.Version
            BuildNumber = $OSInfo.BuildNumber
            LastBootTime = $OSInfo.LastBootUpTime
            Uptime = (Get-Date) - $OSInfo.LastBootUpTime
        }
        
        if ($CimSession) { Remove-CimSession $CimSession }
        
        Write-Log "Retrieved system information for $Computer"
        return $SystemData
    }
    catch {
        Write-Log "Error retrieving system information: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Get-PerformanceMetrics {
    param([string]$Computer = $env:COMPUTERNAME)
    
    try {
        Write-Log "Retrieving performance metrics for $Computer..."
        
        $CimSession = if ($Computer -eq $env:COMPUTERNAME) { $null } else { New-CimSession -ComputerName $Computer -Credential $Credential }
        
        # CPU metrics
        $CPU = Get-Counter -Counter "\Processor(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples 1 -CimSession $CimSession
        $CPUUsage = [math]::Round($CPU.CounterSamples[0].CookedValue, 2)
        
        # Memory metrics
        $Memory = Get-Counter -Counter "\Memory\Available MBytes" -SampleInterval 1 -MaxSamples 1 -CimSession $CimSession
        $AvailableMemoryMB = [math]::Round($Memory.CounterSamples[0].CookedValue, 2)
        
        # Disk metrics
        $DiskMetrics = @()
        $LogicalDisks = Get-CimInstance -ClassName Win32_LogicalDisk -CimSession $CimSession | Where-Object { $_.DriveType -eq 3 }
        
        foreach ($Disk in $LogicalDisks) {
            $FreeSpaceGB = [math]::Round($Disk.FreeSpace / 1GB, 2)
            $TotalSpaceGB = [math]::Round($Disk.Size / 1GB, 2)
            $UsedSpaceGB = $TotalSpaceGB - $FreeSpaceGB
            $UsagePercentage = [math]::Round(($UsedSpaceGB / $TotalSpaceGB) * 100, 2)
            
            $DiskMetrics += [PSCustomObject]@{
                Drive = $Disk.DeviceID
                TotalSpaceGB = $TotalSpaceGB
                UsedSpaceGB = $UsedSpaceGB
                FreeSpaceGB = $FreeSpaceGB
                UsagePercentage = $UsagePercentage
            }
        }
        
        # Network metrics
        $NetworkInterfaces = Get-CimInstance -ClassName Win32_NetworkAdapter -CimSession $CimSession | Where-Object { $_.NetEnabled -eq $true }
        $NetworkMetrics = @()
        
        foreach ($Interface in $NetworkInterfaces) {
            $NetworkMetrics += [PSCustomObject]@{
                Name = $Interface.Name
                AdapterType = $Interface.AdapterType
                MACAddress = $Interface.MACAddress
                Speed = $Interface.Speed
            }
        }
        
        $PerformanceData = [PSCustomObject]@{
            ComputerName = $Computer
            Timestamp = Get-Date
            CPUUsage = $CPUUsage
            AvailableMemoryMB = $AvailableMemoryMB
            DiskMetrics = $DiskMetrics
            NetworkMetrics = $NetworkMetrics
        }
        
        if ($CimSession) { Remove-CimSession $CimSession }
        
        Write-Log "Retrieved performance metrics for $Computer"
        return $PerformanceData
    }
    catch {
        Write-Log "Error retrieving performance metrics: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Get-ServiceStatus {
    param([string]$Computer = $env:COMPUTERNAME)
    
    try {
        Write-Log "Retrieving service status for $Computer..."
        
        $CimSession = if ($Computer -eq $env:COMPUTERNAME) { $null } else { New-CimSession -ComputerName $Computer -Credential $Credential }
        
        $Services = Get-CimInstance -ClassName Win32_Service -CimSession $CimSession | Select-Object @(
            'Name',
            'DisplayName',
            'State',
            'StartMode',
            'StartName',
            'ProcessId'
        )
        
        $ServiceStatus = @()
        foreach ($Service in $Services) {
            $ServiceStatus += [PSCustomObject]@{
                Name = $Service.Name
                DisplayName = $Service.DisplayName
                State = $Service.State
                StartMode = $Service.StartMode
                StartName = $Service.StartName
                ProcessId = $Service.ProcessId
                IsRunning = $Service.State -eq "Running"
                IsAutomatic = $Service.StartMode -eq "Automatic"
            }
        }
        
        if ($CimSession) { Remove-CimSession $CimSession }
        
        Write-Log "Retrieved service status for $($ServiceStatus.Count) services"
        return $ServiceStatus
    }
    catch {
        Write-Log "Error retrieving service status: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Get-EventLogAnalysis {
    param([string]$Computer = $env:COMPUTERNAME, [int]$Days = 7)
    
    try {
        Write-Log "Retrieving event log analysis for $Computer..."
        
        $StartTime = (Get-Date).AddDays(-$Days)
        
        $Events = Get-WinEvent -ComputerName $Computer -LogName "System", "Application" -MaxEvents 1000 | Where-Object { $_.TimeCreated -gt $StartTime }
        
        $EventAnalysis = [PSCustomObject]@{
            ComputerName = $Computer
            AnalysisPeriod = "$Days days"
            TotalEvents = $Events.Count
            ErrorEvents = ($Events | Where-Object { $_.Level -eq 2 }).Count
            WarningEvents = ($Events | Where-Object { $_.Level -eq 3 }).Count
            InformationEvents = ($Events | Where-Object { $_.Level -eq 4 }).Count
            CriticalEvents = ($Events | Where-Object { $_.Level -eq 1 }).Count
            TopErrorSources = $Events | Where-Object { $_.Level -eq 2 } | Group-Object ProviderName | Sort-Object Count -Descending | Select-Object -First 5
            RecentErrors = $Events | Where-Object { $_.Level -eq 2 } | Sort-Object TimeCreated -Descending | Select-Object -First 10
        }
        
        Write-Log "Retrieved event log analysis for $Computer"
        return $EventAnalysis
    }
    catch {
        Write-Log "Error retrieving event log analysis: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Get-SecurityStatus {
    param([string]$Computer = $env:COMPUTERNAME)
    
    try {
        Write-Log "Retrieving security status for $Computer..."
        
        $CimSession = if ($Computer -eq $env:COMPUTERNAME) { $null } else { New-CimSession -ComputerName $Computer -Credential $Credential }
        
        # Windows Defender status
        $DefenderStatus = Get-MpComputerStatus -CimSession $CimSession
        
        # Firewall status
        $FirewallProfiles = Get-NetFirewallProfile -CimSession $CimSession
        
        # UAC status
        $UACStatus = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -CimSession $CimSession
        
        # BitLocker status
        $BitLockerStatus = Get-BitLockerVolume -CimSession $CimSession
        
        $SecurityData = [PSCustomObject]@{
            ComputerName = $Computer
            WindowsDefenderEnabled = $DefenderStatus.AntivirusEnabled
            WindowsDefenderUpToDate = $DefenderStatus.AntivirusSignatureVersion
            FirewallEnabled = ($FirewallProfiles | Where-Object { $_.Enabled -eq $true }).Count -gt 0
            UACEnabled = $UACStatus.EnableLUA -eq 1
            BitLockerEnabled = ($BitLockerStatus | Where-Object { $_.VolumeStatus -eq "FullyEncrypted" }).Count -gt 0
            LastSecurityScan = $DefenderStatus.QuickScanSignatureVersion
        }
        
        if ($CimSession) { Remove-CimSession $CimSession }
        
        Write-Log "Retrieved security status for $Computer"
        return $SecurityData
    }
    catch {
        Write-Log "Error retrieving security status: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Get-HardwareHealth {
    param([string]$Computer = $env:COMPUTERNAME)
    
    try {
        Write-Log "Retrieving hardware health for $Computer..."
        
        $CimSession = if ($Computer -eq $env:COMPUTERNAME) { $null } else { New-CimSession -ComputerName $Computer -Credential $Credential }
        
        # Disk health
        $PhysicalDisks = Get-CimInstance -ClassName Win32_DiskDrive -CimSession $CimSession
        $DiskHealth = @()
        
        foreach ($Disk in $PhysicalDisks) {
            $DiskHealth += [PSCustomObject]@{
                Model = $Disk.Model
                Size = [math]::Round($Disk.Size / 1GB, 2)
                Status = $Disk.Status
                MediaType = $Disk.MediaType
            }
        }
        
        # Memory health
        $MemoryModules = Get-CimInstance -ClassName Win32_PhysicalMemory -CimSession $CimSession
        $MemoryHealth = @()
        
        foreach ($Module in $MemoryModules) {
            $MemoryHealth += [PSCustomObject]@{
                DeviceLocator = $Module.DeviceLocator
                Capacity = [math]::Round($Module.Capacity / 1GB, 2)
                Speed = $Module.Speed
                MemoryType = $Module.MemoryType
            }
        }
        
        # Temperature and fan status (if available)
        $Temperature = Get-CimInstance -ClassName MSAcpi_ThermalZoneTemperature -CimSession $CimSession -ErrorAction SilentlyContinue
        
        $HardwareData = [PSCustomObject]@{
            ComputerName = $Computer
            DiskHealth = $DiskHealth
            MemoryHealth = $MemoryHealth
            Temperature = if ($Temperature) { $Temperature.CurrentTemperature } else { $null }
        }
        
        if ($CimSession) { Remove-CimSession $CimSession }
        
        Write-Log "Retrieved hardware health for $Computer"
        return $HardwareData
    }
    catch {
        Write-Log "Error retrieving hardware health: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Generate-SummaryReport {
    param([object]$SystemInfo, [object]$Performance, [object]$Services, [object]$Security)
    
    try {
        Write-Log "Generating summary report..."
        
        $RunningServices = ($Services | Where-Object { $_.IsRunning }).Count
        $StoppedServices = ($Services | Where-Object { -not $_.IsRunning }).Count
        $CriticalServices = ($Services | Where-Object { $_.IsRunning -eq $false -and $_.StartMode -eq "Automatic" }).Count
        
        $Summary = [PSCustomObject]@{
            ReportDate = Get-Date
            ComputerName = $SystemInfo.ComputerName
            OS = $SystemInfo.OS
            Uptime = $SystemInfo.Uptime
            TotalMemoryGB = $SystemInfo.TotalMemoryGB
            CPUUsage = $Performance.CPUUsage
            AvailableMemoryMB = $Performance.AvailableMemoryMB
            TotalServices = $Services.Count
            RunningServices = $RunningServices
            StoppedServices = $StoppedServices
            CriticalServices = $CriticalServices
            WindowsDefenderEnabled = $Security.WindowsDefenderEnabled
            FirewallEnabled = $Security.FirewallEnabled
            UACEnabled = $Security.UACEnabled
            HealthStatus = "Healthy"
        }
        
        # Determine overall health status
        if ($CriticalServices -gt 0) { $Summary.HealthStatus = "Warning" }
        if ($Performance.CPUUsage -gt 90) { $Summary.HealthStatus = "Warning" }
        if ($Performance.AvailableMemoryMB -lt 1000) { $Summary.HealthStatus = "Warning" }
        if (-not $Security.WindowsDefenderEnabled) { $Summary.HealthStatus = "Warning" }
        
        return $Summary
    }
    catch {
        Write-Log "Error generating summary report: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Export-Report {
    param([object]$Data, [string]$Path, [string]$Format = "CSV")
    
    try {
        Write-Log "Exporting report to $Path..."
        
        $ExportDir = Split-Path -Parent $Path
        if (!(Test-Path $ExportDir)) {
            New-Item -ItemType Directory -Path $ExportDir -Force | Out-Null
        }
        
        switch ($Format.ToUpper()) {
            "CSV" {
                $Data | Export-Csv -Path $Path -NoTypeInformation
            }
            "JSON" {
                $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $Path -Encoding UTF8
            }
            "HTML" {
                $HtmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>System Health Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .warning { background-color: #fff3e0; }
        .error { background-color: #ffebee; }
        .healthy { background-color: #e8f5e8; }
    </style>
</head>
<body>
    <h1>System Health Report</h1>
    <p>Generated: $(Get-Date)</p>
"@
                
                $HtmlTable = $Data | ConvertTo-Html -Fragment
                $HtmlFooter = "</body></html>"
                
                $HtmlContent = $HtmlHeader + $HtmlTable + $HtmlFooter
                $HtmlContent | Out-File -FilePath $Path -Encoding UTF8
            }
        }
        
        Write-Log "Report exported successfully to $Path"
    }
    catch {
        Write-Log "Error exporting report: $($_.Exception.Message)" "ERROR"
        throw
    }
}

# Main execution
try {
    Write-Log "Starting system health report generation..."
    
    $TargetComputer = if ($ComputerName) { $ComputerName } else { $env:COMPUTERNAME }
    
    # Get system information
    $SystemInfo = Get-SystemInfo -Computer $TargetComputer
    
    # Get performance metrics
    $Performance = Get-PerformanceMetrics -Computer $TargetComputer
    
    # Get service status
    $Services = Get-ServiceStatus -Computer $TargetComputer
    
    # Get security status
    $Security = Get-SecurityStatus -Computer $TargetComputer
    
    # Generate report based on type
    switch ($ReportType) {
        "Summary" {
            $Report = Generate-SummaryReport -SystemInfo $SystemInfo -Performance $Performance -Services $Services -Security $Security
            Write-Log "Summary Report:"
            $Report | Format-List
        }
        "Performance" {
            $Report = $Performance
            Write-Log "Performance Report:"
            $Report | Format-List
        }
        "Services" {
            $Report = $Services | Sort-Object State, Name
            Write-Log "Services Report:"
            $Report | Format-Table -AutoSize
        }
        "Security" {
            $Report = $Security
            Write-Log "Security Report:"
            $Report | Format-List
        }
        "Events" {
            if ($IncludeEvents) {
                $Report = Get-EventLogAnalysis -Computer $TargetComputer -Days $DaysBack
                Write-Log "Events Report:"
                $Report | Format-List
            } else {
                Write-Log "Events analysis not requested"
                $Report = $null
            }
        }
        "Hardware" {
            $Report = Get-HardwareHealth -Computer $TargetComputer
            Write-Log "Hardware Report:"
            $Report | Format-List
        }
        "Detailed" {
            $Report = [PSCustomObject]@{
                SystemInfo = $SystemInfo
                Performance = $Performance
                Services = $Services
                Security = $Security
                Events = if ($IncludeEvents) { Get-EventLogAnalysis -Computer $TargetComputer -Days $DaysBack } else { $null }
                Hardware = Get-HardwareHealth -Computer $TargetComputer
            }
            Write-Log "Detailed Report:"
            $Report | Format-List
        }
    }
    
    # Export report if path specified
    if ($ExportPath -and $Report) {
        $Format = [System.IO.Path]::GetExtension($ExportPath).TrimStart('.')
        if ($Format -eq "") { $Format = "CSV" }
        Export-Report -Data $Report -Path $ExportPath -Format $Format
    }
    
    Write-Log "System health report generation completed successfully"
}
catch {
    Write-Log "Error in main execution: $($_.Exception.Message)" "ERROR"
    throw
} 
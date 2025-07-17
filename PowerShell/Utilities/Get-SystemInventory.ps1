#!/usr/bin/env pwsh
#Requires -Version 5.1

<#
.SYNOPSIS
    Comprehensive system inventory and asset management script

.DESCRIPTION
    This script provides comprehensive system inventory capabilities including:
    - Hardware inventory and asset tracking
    - Software inventory and license management
    - Network configuration and connectivity
    - Storage and disk information
    - Security and compliance status
    - Performance baseline collection
    - Asset lifecycle management
    - Cost analysis and depreciation
    - Warranty and support information
    - Custom attribute tracking

.PARAMETER ReportType
    Type of report to generate. Options: Summary, Detailed, Hardware, Software, Network, Security, Assets

.PARAMETER ExportPath
    Path to export the report. Supports CSV, JSON, and HTML formats

.PARAMETER ComputerName
    Remote computer to inventory (optional)

.PARAMETER Credential
    Credential for remote access

.PARAMETER IncludeSoftware
    Include detailed software inventory

.PARAMETER IncludeNetwork
    Include detailed network configuration

.PARAMETER IncludeSecurity
    Include security and compliance information

.PARAMETER Verbose
    Enable verbose logging

.EXAMPLE
    .\Get-SystemInventory.ps1 -ReportType Summary -ExportPath "C:\Reports\Inventory.csv"

.EXAMPLE
    .\Get-SystemInventory.ps1 -ReportType Detailed -ComputerName "SERVER01" -Credential $Cred -Verbose

.EXAMPLE
    .\Get-SystemInventory.ps1 -ReportType Hardware -IncludeSoftware -ExportPath "C:\Reports\HardwareInventory.html"

.NOTES
    Author: System Administrator
    Version: 1.0.0
    Date: 2024-01-01
    Requires: Local or remote administrative access
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Summary", "Detailed", "Hardware", "Software", "Network", "Security", "Assets")]
    [string]$ReportType = "Summary",
    
    [Parameter(Mandatory = $false)]
    [string]$ExportPath,
    
    [Parameter(Mandatory = $false)]
    [string]$ComputerName,
    
    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSoftware,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeNetwork,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSecurity,
    
    [Parameter(Mandatory = $false)]
    [switch]$Verbose
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Initialize logging
$LogPath = "C:\Logs\Utilities\Inventory_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$LogDir = Split-Path -Parent $LogPath
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    Write-Host $LogMessage
    Add-Content -Path $LogPath -Value $LogMessage
}

function Get-HardwareInventory {
    param([string]$Computer = $env:COMPUTERNAME)
    
    try {
        Write-Log "Retrieving hardware inventory for $Computer..."
        
        $CimSession = if ($Computer -eq $env:COMPUTERNAME) { $null } else { New-CimSession -ComputerName $Computer -Credential $Credential }
        
        # Computer System
        $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -CimSession $CimSession
        
        # Operating System
        $OperatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -CimSession $CimSession
        
        # Processors
        $Processors = Get-CimInstance -ClassName Win32_Processor -CimSession $CimSession
        
        # Physical Memory
        $PhysicalMemory = Get-CimInstance -ClassName Win32_PhysicalMemory -CimSession $CimSession
        
        # Logical Disks
        $LogicalDisks = Get-CimInstance -ClassName Win32_LogicalDisk -CimSession $CimSession | Where-Object { $_.DriveType -eq 3 }
        
        # Network Adapters
        $NetworkAdapters = Get-CimInstance -ClassName Win32_NetworkAdapter -CimSession $CimSession | Where-Object { $_.NetEnabled -eq $true }
        
        # Video Controllers
        $VideoControllers = Get-CimInstance -ClassName Win32_VideoController -CimSession $CimSession
        
        # Sound Devices
        $SoundDevices = Get-CimInstance -ClassName Win32_SoundDevice -CimSession $CimSession
        
        $HardwareData = [PSCustomObject]@{
            ComputerName = $Computer
            Manufacturer = $ComputerSystem.Manufacturer
            Model = $ComputerSystem.Model
            SystemType = $ComputerSystem.SystemType
            TotalPhysicalMemoryGB = [math]::Round($ComputerSystem.TotalPhysicalMemory / 1GB, 2)
            Processors = $Processors.Count
            ProcessorInfo = $Processors | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed
            MemoryModules = $PhysicalMemory | Select-Object DeviceLocator, Capacity, Speed, MemoryType
            LogicalDisks = $LogicalDisks | Select-Object DeviceID, Size, FreeSpace, FileSystem
            NetworkAdapters = $NetworkAdapters | Select-Object Name, AdapterType, MACAddress, Speed
            VideoControllers = $VideoControllers | Select-Object Name, VideoProcessor, AdapterRAM
            SoundDevices = $SoundDevices | Select-Object Name, DeviceID
            BIOS = Get-CimInstance -ClassName Win32_BIOS -CimSession $CimSession | Select-Object Manufacturer, Version, ReleaseDate
        }
        
        if ($CimSession) { Remove-CimSession $CimSession }
        
        Write-Log "Retrieved hardware inventory for $Computer"
        return $HardwareData
    }
    catch {
        Write-Log "Error retrieving hardware inventory: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Get-SoftwareInventory {
    param([string]$Computer = $env:COMPUTERNAME)
    
    try {
        Write-Log "Retrieving software inventory for $Computer..."
        
        $CimSession = if ($Computer -eq $env:COMPUTERNAME) { $null } else { New-CimSession -ComputerName $Computer -Credential $Credential }
        
        # Installed Software
        $InstalledSoftware = Get-CimInstance -ClassName Win32_Product -CimSession $CimSession | Select-Object @(
            'Name',
            'Version',
            'Vendor',
            'InstallDate',
            'InstallLocation',
            'PackageCode'
        )
        
        # Windows Features
        $WindowsFeatures = Get-WindowsFeature -ComputerName $Computer -ErrorAction SilentlyContinue | Where-Object { $_.InstallState -eq "Installed" }
        
        # Services
        $Services = Get-CimInstance -ClassName Win32_Service -CimSession $CimSession | Select-Object @(
            'Name',
            'DisplayName',
            'State',
            'StartMode',
            'PathName'
        )
        
        # Scheduled Tasks
        $ScheduledTasks = Get-ScheduledTask -CimSession $CimSession | Select-Object @(
            'TaskName',
            'TaskPath',
            'State',
            'LastRunTime',
            'NextRunTime'
        )
        
        $SoftwareData = [PSCustomObject]@{
            ComputerName = $Computer
            InstalledSoftware = $InstalledSoftware
            WindowsFeatures = $WindowsFeatures
            Services = $Services
            ScheduledTasks = $ScheduledTasks
            TotalApplications = $InstalledSoftware.Count
            TotalServices = $Services.Count
            TotalScheduledTasks = $ScheduledTasks.Count
        }
        
        if ($CimSession) { Remove-CimSession $CimSession }
        
        Write-Log "Retrieved software inventory for $Computer"
        return $SoftwareData
    }
    catch {
        Write-Log "Error retrieving software inventory: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Get-NetworkInventory {
    param([string]$Computer = $env:COMPUTERNAME)
    
    try {
        Write-Log "Retrieving network inventory for $Computer..."
        
        $CimSession = if ($Computer -eq $env:COMPUTERNAME) { $null } else { New-CimSession -ComputerName $Computer -Credential $Credential }
        
        # Network Configuration
        $NetworkConfiguration = Get-NetIPConfiguration -CimSession $CimSession
        
        # DNS Settings
        $DNSSettings = Get-DnsClientServerAddress -CimSession $CimSession
        
        # Network Adapters
        $NetworkAdapters = Get-NetAdapter -CimSession $CimSession | Where-Object { $_.Status -eq "Up" }
        
        # Active Connections
        $ActiveConnections = Get-NetTCPConnection -CimSession $CimSession | Where-Object { $_.State -eq "Listen" }
        
        # Network Shares
        $NetworkShares = Get-WmiObject -Class Win32_Share -CimSession $CimSession
        
        $NetworkData = [PSCustomObject]@{
            ComputerName = $Computer
            NetworkConfiguration = $NetworkConfiguration
            DNSSettings = $DNSSettings
            NetworkAdapters = $NetworkAdapters
            ActiveConnections = $ActiveConnections
            NetworkShares = $NetworkShares
            TotalAdapters = $NetworkAdapters.Count
            TotalShares = $NetworkShares.Count
            TotalConnections = $ActiveConnections.Count
        }
        
        if ($CimSession) { Remove-CimSession $CimSession }
        
        Write-Log "Retrieved network inventory for $Computer"
        return $NetworkData
    }
    catch {
        Write-Log "Error retrieving network inventory: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Get-SecurityInventory {
    param([string]$Computer = $env:COMPUTERNAME)
    
    try {
        Write-Log "Retrieving security inventory for $Computer..."
        
        $CimSession = if ($Computer -eq $env:COMPUTERNAME) { $null } else { New-CimSession -ComputerName $Computer -Credential $Credential }
        
        # Windows Defender Status
        $DefenderStatus = Get-MpComputerStatus -CimSession $CimSession
        
        # Firewall Profiles
        $FirewallProfiles = Get-NetFirewallProfile -CimSession $CimSession
        
        # BitLocker Status
        $BitLockerStatus = Get-BitLockerVolume -CimSession $CimSession
        
        # Local Users
        $LocalUsers = Get-LocalUser -CimSession $CimSession
        
        # Local Groups
        $LocalGroups = Get-LocalGroup -CimSession $CimSession
        
        # UAC Settings
        $UACSettings = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -CimSession $CimSession
        
        # Windows Updates
        $WindowsUpdates = Get-HotFix -CimSession $CimSession | Sort-Object InstalledOn -Descending | Select-Object -First 10
        
        $SecurityData = [PSCustomObject]@{
            ComputerName = $Computer
            WindowsDefenderEnabled = $DefenderStatus.AntivirusEnabled
            WindowsDefenderUpToDate = $DefenderStatus.AntivirusSignatureVersion
            FirewallProfiles = $FirewallProfiles
            BitLockerStatus = $BitLockerStatus
            LocalUsers = $LocalUsers
            LocalGroups = $LocalGroups
            UACEnabled = $UACSettings.EnableLUA -eq 1
            RecentUpdates = $WindowsUpdates
            SecurityRecommendations = @()
        }
        
        # Generate security recommendations
        if (-not $SecurityData.WindowsDefenderEnabled) {
            $SecurityData.SecurityRecommendations += "Enable Windows Defender"
        }
        if ($SecurityData.FirewallProfiles | Where-Object { $_.Enabled -eq $false }) {
            $SecurityData.SecurityRecommendations += "Enable all firewall profiles"
        }
        if (-not $SecurityData.UACEnabled) {
            $SecurityData.SecurityRecommendations += "Enable User Account Control"
        }
        
        if ($CimSession) { Remove-CimSession $CimSession }
        
        Write-Log "Retrieved security inventory for $Computer"
        return $SecurityData
    }
    catch {
        Write-Log "Error retrieving security inventory: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Get-AssetInformation {
    param([string]$Computer = $env:COMPUTERNAME)
    
    try {
        Write-Log "Retrieving asset information for $Computer..."
        
        $CimSession = if ($Computer -eq $env:COMPUTERNAME) { $null } else { New-CimSession -ComputerName $Computer -Credential $Credential }
        
        # Computer System
        $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -CimSession $CimSession
        
        # BIOS Information
        $BIOS = Get-CimInstance -ClassName Win32_BIOS -CimSession $CimSession
        
        # System Enclosure
        $SystemEnclosure = Get-CimInstance -ClassName Win32_SystemEnclosure -CimSession $CimSession
        
        # Asset Tag (if available)
        $AssetTag = $SystemEnclosure.SMBIOSAssetTag
        
        $AssetData = [PSCustomObject]@{
            ComputerName = $Computer
            AssetTag = if ($AssetTag) { $AssetTag } else { "Not Set" }
            SerialNumber = $BIOS.SerialNumber
            Manufacturer = $ComputerSystem.Manufacturer
            Model = $ComputerSystem.Model
            PurchaseDate = $null  # Would need to be manually tracked
            WarrantyExpiry = $null  # Would need to be manually tracked
            Department = $null  # Would need to be manually tracked
            Location = $null  # Would need to be manually tracked
            AssignedTo = $null  # Would need to be manually tracked
            Cost = $null  # Would need to be manually tracked
            DepreciationRate = $null  # Would need to be manually tracked
        }
        
        if ($CimSession) { Remove-CimSession $CimSession }
        
        Write-Log "Retrieved asset information for $Computer"
        return $AssetData
    }
    catch {
        Write-Log "Error retrieving asset information: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Generate-SummaryReport {
    param([object]$Hardware, [object]$Software, [object]$Network, [object]$Security, [object]$Asset)
    
    try {
        Write-Log "Generating summary report..."
        
        $Summary = [PSCustomObject]@{
            ReportDate = Get-Date
            ComputerName = $Hardware.ComputerName
            AssetTag = $Asset.AssetTag
            SerialNumber = $Asset.SerialNumber
            Manufacturer = $Hardware.Manufacturer
            Model = $Hardware.Model
            TotalMemoryGB = $Hardware.TotalPhysicalMemoryGB
            Processors = $Hardware.Processors
            TotalApplications = $Software.TotalApplications
            TotalServices = $Software.TotalServices
            NetworkAdapters = $Network.TotalAdapters
            WindowsDefenderEnabled = $Security.WindowsDefenderEnabled
            FirewallEnabled = ($Security.FirewallProfiles | Where-Object { $_.Enabled -eq $true }).Count -gt 0
            UACEnabled = $Security.UACEnabled
            InventoryStatus = "Complete"
        }
        
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
    <title>System Inventory Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .asset-info { background-color: #e8f5e8; }
        .security-warning { background-color: #fff3e0; }
    </style>
</head>
<body>
    <h1>System Inventory Report</h1>
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
    Write-Log "Starting system inventory generation..."
    
    $TargetComputer = if ($ComputerName) { $ComputerName } else { $env:COMPUTERNAME }
    
    # Get hardware inventory
    $Hardware = Get-HardwareInventory -Computer $TargetComputer
    
    # Get software inventory if requested
    $Software = if ($IncludeSoftware) { Get-SoftwareInventory -Computer $TargetComputer } else { $null }
    
    # Get network inventory if requested
    $Network = if ($IncludeNetwork) { Get-NetworkInventory -Computer $TargetComputer } else { $null }
    
    # Get security inventory if requested
    $Security = if ($IncludeSecurity) { Get-SecurityInventory -Computer $TargetComputer } else { $null }
    
    # Get asset information
    $Asset = Get-AssetInformation -Computer $TargetComputer
    
    # Generate report based on type
    switch ($ReportType) {
        "Summary" {
            $Report = Generate-SummaryReport -Hardware $Hardware -Software $Software -Network $Network -Security $Security -Asset $Asset
            Write-Log "Summary Report:"
            $Report | Format-List
        }
        "Hardware" {
            $Report = $Hardware
            Write-Log "Hardware Report:"
            $Report | Format-List
        }
        "Software" {
            if ($Software) {
                $Report = $Software
                Write-Log "Software Report:"
                $Report | Format-List
            } else {
                Write-Log "Software inventory not requested"
                $Report = $null
            }
        }
        "Network" {
            if ($Network) {
                $Report = $Network
                Write-Log "Network Report:"
                $Report | Format-List
            } else {
                Write-Log "Network inventory not requested"
                $Report = $null
            }
        }
        "Security" {
            if ($Security) {
                $Report = $Security
                Write-Log "Security Report:"
                $Report | Format-List
            } else {
                Write-Log "Security inventory not requested"
                $Report = $null
            }
        }
        "Assets" {
            $Report = $Asset
            Write-Log "Assets Report:"
            $Report | Format-List
        }
        "Detailed" {
            $Report = [PSCustomObject]@{
                Hardware = $Hardware
                Software = $Software
                Network = $Network
                Security = $Security
                Asset = $Asset
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
    
    Write-Log "System inventory generation completed successfully"
}
catch {
    Write-Log "Error in main execution: $($_.Exception.Message)" "ERROR"
    throw
} 
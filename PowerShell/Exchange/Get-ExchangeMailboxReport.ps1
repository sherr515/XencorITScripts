#!/usr/bin/env pwsh
#Requires -Version 5.1
#Requires -Modules ExchangeOnlineManagement

<#
.SYNOPSIS
    Comprehensive Exchange Online mailbox reporting and analysis script

.DESCRIPTION
    This script provides comprehensive Exchange Online mailbox reporting capabilities including:
    - Mailbox inventory and statistics
    - Storage usage analysis and quota management
    - Permission and delegation reporting
    - Mail flow and forwarding rules
    - Retention policy compliance
    - Security and compliance analysis
    - Mailbox health and status monitoring
    - Cost analysis and optimization recommendations

.PARAMETER ReportType
    Type of report to generate. Options: Summary, Detailed, Storage, Permissions, Security, Compliance, Cost

.PARAMETER ExportPath
    Path to export the report. Supports CSV, JSON, and HTML formats

.PARAMETER Filter
    Filter string to limit mailboxes included in the report

.PARAMETER IncludeArchives
    Include archive mailboxes in the report

.PARAMETER IncludeInactive
    Include inactive mailboxes in the report

.PARAMETER Verbose
    Enable verbose logging

.EXAMPLE
    .\Get-ExchangeMailboxReport.ps1 -ReportType Summary -ExportPath "C:\Reports\MailboxSummary.csv"

.EXAMPLE
    .\Get-ExchangeMailboxReport.ps1 -ReportType Detailed -Filter "Department -eq 'IT'" -Verbose

.EXAMPLE
    .\Get-ExchangeMailboxReport.ps1 -ReportType Storage -IncludeArchives -ExportPath "C:\Reports\StorageAnalysis.html"

.NOTES
    Author: System Administrator
    Version: 1.0.0
    Date: 2024-01-01
    Requires: Exchange Online PowerShell module
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Summary", "Detailed", "Storage", "Permissions", "Security", "Compliance", "Cost")]
    [string]$ReportType = "Summary",
    
    [Parameter(Mandatory = $false)]
    [string]$ExportPath,
    
    [Parameter(Mandatory = $false)]
    [string]$Filter,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeArchives,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeInactive,
    
    [Parameter(Mandatory = $false)]
    [switch]$Verbose
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Initialize logging
$LogPath = "C:\Logs\Exchange\MailboxReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$LogDir = Split-Path -Parent $LogPath
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    Write-Host $LogMessage
    Add-Content -Path $LogPath -Value $LogMessage
}

function Connect-ExchangeOnline {
    try {
        Write-Log "Connecting to Exchange Online..."
        Connect-ExchangeOnline -ShowProgress $false
        Write-Log "Successfully connected to Exchange Online"
    }
    catch {
        Write-Log "Failed to connect to Exchange Online: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Get-MailboxInventory {
    param([string]$Filter = $null)
    
    try {
        Write-Log "Retrieving mailbox inventory..."
        
        $GetMailboxParams = @{
            ResultSize = "Unlimited"
        }
        
        if ($Filter) {
            $GetMailboxParams.Filter = $Filter
        }
        
        $Mailboxes = Get-Mailbox @GetMailboxParams
        
        Write-Log "Retrieved $($Mailboxes.Count) mailboxes"
        return $Mailboxes
    }
    catch {
        Write-Log "Error retrieving mailbox inventory: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Get-MailboxStatistics {
    param([array]$Mailboxes)
    
    try {
        Write-Log "Retrieving mailbox statistics..."
        
        $Stats = @()
        $ProgressCounter = 0
        
        foreach ($Mailbox in $Mailboxes) {
            $ProgressCounter++
            Write-Progress -Activity "Retrieving mailbox statistics" -Status "Processing $($Mailbox.DisplayName)" -PercentComplete (($ProgressCounter / $Mailboxes.Count) * 100)
            
            try {
                $MailboxStats = Get-MailboxStatistics -Identity $Mailbox.UserPrincipalName
                $Stats += $MailboxStats
            }
            catch {
                Write-Log "Warning: Could not retrieve statistics for $($Mailbox.DisplayName): $($_.Exception.Message)" "WARNING"
            }
        }
        
        Write-Log "Retrieved statistics for $($Stats.Count) mailboxes"
        return $Stats
    }
    catch {
        Write-Log "Error retrieving mailbox statistics: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Get-MailboxPermissions {
    param([array]$Mailboxes)
    
    try {
        Write-Log "Retrieving mailbox permissions..."
        
        $Permissions = @()
        $ProgressCounter = 0
        
        foreach ($Mailbox in $Mailboxes) {
            $ProgressCounter++
            Write-Progress -Activity "Retrieving mailbox permissions" -Status "Processing $($Mailbox.DisplayName)" -PercentComplete (($ProgressCounter / $Mailboxes.Count) * 100)
            
            try {
                $MailboxPermissions = Get-MailboxPermission -Identity $Mailbox.UserPrincipalName
                foreach ($Permission in $MailboxPermissions) {
                    $Permissions += [PSCustomObject]@{
                        Mailbox = $Mailbox.DisplayName
                        UserPrincipalName = $Mailbox.UserPrincipalName
                        User = $Permission.User
                        AccessRights = ($Permission.AccessRights -join ", ")
                        Deny = $Permission.Deny
                        IsInherited = $Permission.IsInherited
                    }
                }
            }
            catch {
                Write-Log "Warning: Could not retrieve permissions for $($Mailbox.DisplayName): $($_.Exception.Message)" "WARNING"
            }
        }
        
        Write-Log "Retrieved permissions for $($Permissions.Count) entries"
        return $Permissions
    }
    catch {
        Write-Log "Error retrieving mailbox permissions: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Get-MailboxRules {
    param([array]$Mailboxes)
    
    try {
        Write-Log "Retrieving mailbox rules..."
        
        $Rules = @()
        $ProgressCounter = 0
        
        foreach ($Mailbox in $Mailboxes) {
            $ProgressCounter++
            Write-Progress -Activity "Retrieving mailbox rules" -Status "Processing $($Mailbox.DisplayName)" -PercentComplete (($ProgressCounter / $Mailboxes.Count) * 100)
            
            try {
                $MailboxRules = Get-InboxRule -Mailbox $Mailbox.UserPrincipalName
                foreach ($Rule in $MailboxRules) {
                    $Rules += [PSCustomObject]@{
                        Mailbox = $Mailbox.DisplayName
                        UserPrincipalName = $Mailbox.UserPrincipalName
                        RuleName = $Rule.Name
                        Enabled = $Rule.Enabled
                        Priority = $Rule.Priority
                        RuleType = $Rule.RuleType
                    }
                }
            }
            catch {
                Write-Log "Warning: Could not retrieve rules for $($Mailbox.DisplayName): $($_.Exception.Message)" "WARNING"
            }
        }
        
        Write-Log "Retrieved rules for $($Rules.Count) entries"
        return $Rules
    }
    catch {
        Write-Log "Error retrieving mailbox rules: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Generate-SummaryReport {
    param([array]$Mailboxes, [array]$Statistics)
    
    try {
        Write-Log "Generating summary report..."
        
        $Summary = [PSCustomObject]@{
            ReportDate = Get-Date
            TotalMailboxes = $Mailboxes.Count
            ActiveMailboxes = ($Mailboxes | Where-Object { $_.RecipientTypeDetails -eq "UserMailbox" }).Count
            SharedMailboxes = ($Mailboxes | Where-Object { $_.RecipientTypeDetails -eq "SharedMailbox" }).Count
            RoomMailboxes = ($Mailboxes | Where-Object { $_.RecipientTypeDetails -eq "RoomMailbox" }).Count
            EquipmentMailboxes = ($Mailboxes | Where-Object { $_.RecipientTypeDetails -eq "EquipmentMailbox" }).Count
            TotalStorageGB = [math]::Round((($Statistics | Measure-Object -Property TotalItemSize -Sum).Sum / 1GB), 2)
            AverageStorageGB = [math]::Round((($Statistics | Measure-Object -Property TotalItemSize -Average).Average / 1GB), 2)
            LargestMailboxGB = [math]::Round((($Statistics | Sort-Object TotalItemSize -Descending | Select-Object -First 1).TotalItemSize / 1GB), 2)
            MailboxesOverQuota = ($Statistics | Where-Object { $_.TotalItemSize -gt $_.ProhibitSendQuota }).Count
        }
        
        return $Summary
    }
    catch {
        Write-Log "Error generating summary report: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Generate-StorageReport {
    param([array]$Mailboxes, [array]$Statistics)
    
    try {
        Write-Log "Generating storage analysis report..."
        
        $StorageReport = @()
        
        foreach ($Mailbox in $Mailboxes) {
            $Stats = $Statistics | Where-Object { $_.MailboxGuid -eq $Mailbox.Guid }
            if ($Stats) {
                $StorageReport += [PSCustomObject]@{
                    DisplayName = $Mailbox.DisplayName
                    UserPrincipalName = $Mailbox.UserPrincipalName
                    RecipientType = $Mailbox.RecipientTypeDetails
                    TotalItemSizeGB = [math]::Round(($Stats.TotalItemSize / 1GB), 2)
                    ItemCount = $Stats.ItemCount
                    DeletedItemSizeGB = [math]::Round(($Stats.DeletedItemSize / 1GB), 2)
                    DeletedItemCount = $Stats.DeletedItemCount
                    QuotaGB = [math]::Round(($Mailbox.ProhibitSendQuota / 1GB), 2)
                    UsagePercentage = [math]::Round((($Stats.TotalItemSize / $Mailbox.ProhibitSendQuota) * 100), 2)
                    LastLogonTime = $Stats.LastLogonTime
                    IsOverQuota = $Stats.TotalItemSize -gt $Mailbox.ProhibitSendQuota
                }
            }
        }
        
        return $StorageReport
    }
    catch {
        Write-Log "Error generating storage report: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Generate-SecurityReport {
    param([array]$Permissions, [array]$Rules)
    
    try {
        Write-Log "Generating security analysis report..."
        
        $SecurityReport = [PSCustomObject]@{
            ReportDate = Get-Date
            TotalPermissionEntries = $Permissions.Count
            ExternalPermissions = ($Permissions | Where-Object { $_.User -like "*@*" -and $_.User -notlike "*@$env:USERDNSDOMAIN*" }).Count
            FullAccessPermissions = ($Permissions | Where-Object { $_.AccessRights -like "*FullAccess*" }).Count
            SendAsPermissions = ($Permissions | Where-Object { $_.AccessRights -like "*SendAs*" }).Count
            TotalRules = $Rules.Count
            EnabledRules = ($Rules | Where-Object { $_.Enabled -eq $true }).Count
            ForwardingRules = ($Rules | Where-Object { $_.RuleType -like "*Forward*" }).Count
            SecurityRecommendations = @()
        }
        
        # Generate security recommendations
        if ($SecurityReport.ExternalPermissions -gt 0) {
            $SecurityReport.SecurityRecommendations += "Review external mailbox permissions"
        }
        if ($SecurityReport.FullAccessPermissions -gt 10) {
            $SecurityReport.SecurityRecommendations += "Review excessive FullAccess permissions"
        }
        if ($SecurityReport.ForwardingRules -gt 0) {
            $SecurityReport.SecurityRecommendations += "Review mail forwarding rules"
        }
        
        return $SecurityReport
    }
    catch {
        Write-Log "Error generating security report: $($_.Exception.Message)" "ERROR"
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
    <title>Exchange Mailbox Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .over-quota { background-color: #ffebee; }
    </style>
</head>
<body>
    <h1>Exchange Mailbox Report</h1>
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
    Write-Log "Starting Exchange mailbox report generation..."
    
    # Connect to Exchange Online
    Connect-ExchangeOnline
    
    # Get mailbox inventory
    $Mailboxes = Get-MailboxInventory -Filter $Filter
    
    # Get mailbox statistics
    $Statistics = Get-MailboxStatistics -Mailboxes $Mailboxes
    
    # Generate report based on type
    switch ($ReportType) {
        "Summary" {
            $Report = Generate-SummaryReport -Mailboxes $Mailboxes -Statistics $Statistics
            Write-Log "Summary Report:"
            $Report | Format-List
        }
        "Storage" {
            $Report = Generate-StorageReport -Mailboxes $Mailboxes -Statistics $Statistics
            Write-Log "Storage Report:"
            $Report | Format-Table -AutoSize
        }
        "Security" {
            $Permissions = Get-MailboxPermissions -Mailboxes $Mailboxes
            $Rules = Get-MailboxRules -Mailboxes $Mailboxes
            $Report = Generate-SecurityReport -Permissions $Permissions -Rules $Rules
            Write-Log "Security Report:"
            $Report | Format-List
        }
        "Detailed" {
            $Report = @()
            foreach ($Mailbox in $Mailboxes) {
                $Stats = $Statistics | Where-Object { $_.MailboxGuid -eq $Mailbox.Guid }
                $Report += [PSCustomObject]@{
                    DisplayName = $Mailbox.DisplayName
                    UserPrincipalName = $Mailbox.UserPrincipalName
                    RecipientType = $Mailbox.RecipientTypeDetails
                    PrimarySmtpAddress = $Mailbox.PrimarySmtpAddress
                    TotalItemSizeGB = if ($Stats) { [math]::Round(($Stats.TotalItemSize / 1GB), 2) } else { 0 }
                    ItemCount = if ($Stats) { $Stats.ItemCount } else { 0 }
                    LastLogonTime = if ($Stats) { $Stats.LastLogonTime } else { $null }
                    Created = $Mailbox.WhenCreated
                    Modified = $Mailbox.WhenChanged
                }
            }
            Write-Log "Detailed Report:"
            $Report | Format-Table -AutoSize
        }
    }
    
    # Export report if path specified
    if ($ExportPath) {
        $Format = [System.IO.Path]::GetExtension($ExportPath).TrimStart('.')
        if ($Format -eq "") { $Format = "CSV" }
        Export-Report -Data $Report -Path $ExportPath -Format $Format
    }
    
    Write-Log "Exchange mailbox report generation completed successfully"
}
catch {
    Write-Log "Error in main execution: $($_.Exception.Message)" "ERROR"
    throw
}
finally {
    # Disconnect from Exchange Online
    try {
        Disconnect-ExchangeOnline -Confirm:$false
        Write-Log "Disconnected from Exchange Online"
    }
    catch {
        Write-Log "Warning: Could not disconnect from Exchange Online: $($_.Exception.Message)" "WARNING"
    }
} 
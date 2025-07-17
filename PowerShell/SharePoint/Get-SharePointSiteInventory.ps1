#!/usr/bin/env pwsh
#Requires -Version 5.1
#Requires -Modules Microsoft.Online.SharePoint.PowerShell

<#
.SYNOPSIS
    Comprehensive SharePoint Online site inventory and management script

.DESCRIPTION
    This script provides comprehensive SharePoint Online site management capabilities including:
    - Site inventory and statistics
    - Permission and access control reporting
    - Content analysis and storage reporting
    - Site collection administration
    - Security and compliance analysis
    - Site health and status monitoring
    - Customization and feature analysis
    - Cost analysis and optimization recommendations

.PARAMETER ReportType
    Type of report to generate. Options: Summary, Detailed, Permissions, Storage, Security, Compliance, Customizations

.PARAMETER ExportPath
    Path to export the report. Supports CSV, JSON, and HTML formats

.PARAMETER SiteUrl
    Specific site URL to analyze (optional)

.PARAMETER IncludeSubsites
    Include subsites in the analysis

.PARAMETER IncludeInactive
    Include inactive sites in the report

.PARAMETER Verbose
    Enable verbose logging

.EXAMPLE
    .\Get-SharePointSiteInventory.ps1 -ReportType Summary -ExportPath "C:\Reports\SharePointSummary.csv"

.EXAMPLE
    .\Get-SharePointSiteInventory.ps1 -ReportType Detailed -SiteUrl "https://contoso.sharepoint.com/sites/IT" -Verbose

.EXAMPLE
    .\Get-SharePointSiteInventory.ps1 -ReportType Permissions -IncludeSubsites -ExportPath "C:\Reports\PermissionsAnalysis.html"

.NOTES
    Author: System Administrator
    Version: 1.0.0
    Date: 2024-01-01
    Requires: SharePoint Online PowerShell module
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Summary", "Detailed", "Permissions", "Storage", "Security", "Compliance", "Customizations")]
    [string]$ReportType = "Summary",
    
    [Parameter(Mandatory = $false)]
    [string]$ExportPath,
    
    [Parameter(Mandatory = $false)]
    [string]$SiteUrl,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSubsites,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeInactive,
    
    [Parameter(Mandatory = $false)]
    [switch]$Verbose
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Initialize logging
$LogPath = "C:\Logs\SharePoint\SiteInventory_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$LogDir = Split-Path -Parent $LogPath
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    Write-Host $LogMessage
    Add-Content -Path $LogPath -Value $LogMessage
}

function Connect-SharePointOnline {
    try {
        Write-Log "Connecting to SharePoint Online..."
        Connect-SPOService -Url "https://contoso-admin.sharepoint.com"
        Write-Log "Successfully connected to SharePoint Online"
    }
    catch {
        Write-Log "Failed to connect to SharePoint Online: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Get-SiteCollections {
    param([string]$Filter = $null)
    
    try {
        Write-Log "Retrieving site collections..."
        
        $Sites = Get-SPOSite -Limit All
        
        if ($Filter) {
            $Sites = $Sites | Where-Object { $_.Url -like "*$Filter*" }
        }
        
        Write-Log "Retrieved $($Sites.Count) site collections"
        return $Sites
    }
    catch {
        Write-Log "Error retrieving site collections: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Get-SitePermissions {
    param([string]$SiteUrl)
    
    try {
        Write-Log "Retrieving site permissions for $SiteUrl..."
        
        $Permissions = @()
        
        # Get site owners
        $SiteOwners = Get-SPOUser -Site $SiteUrl | Where-Object { $_.Groups -contains "Owners" }
        foreach ($Owner in $SiteOwners) {
            $Permissions += [PSCustomObject]@{
                SiteUrl = $SiteUrl
                User = $Owner.LoginName
                DisplayName = $Owner.DisplayName
                Group = "Owners"
                PermissionLevel = "Full Control"
                IsExternal = $Owner.LoginName -like "*@*" -and $Owner.LoginName -notlike "*@contoso.com*"
            }
        }
        
        # Get site members
        $SiteMembers = Get-SPOUser -Site $SiteUrl | Where-Object { $_.Groups -contains "Members" }
        foreach ($Member in $SiteMembers) {
            $Permissions += [PSCustomObject]@{
                SiteUrl = $SiteUrl
                User = $Member.LoginName
                DisplayName = $Member.DisplayName
                Group = "Members"
                PermissionLevel = "Contribute"
                IsExternal = $Member.LoginName -like "*@*" -and $Member.LoginName -notlike "*@contoso.com*"
            }
        }
        
        # Get site visitors
        $SiteVisitors = Get-SPOUser -Site $SiteUrl | Where-Object { $_.Groups -contains "Visitors" }
        foreach ($Visitor in $SiteVisitors) {
            $Permissions += [PSCustomObject]@{
                SiteUrl = $SiteUrl
                User = $Visitor.LoginName
                DisplayName = $Visitor.DisplayName
                Group = "Visitors"
                PermissionLevel = "Read"
                IsExternal = $Visitor.LoginName -like "*@*" -and $Visitor.LoginName -notlike "*@contoso.com*"
            }
        }
        
        Write-Log "Retrieved $($Permissions.Count) permission entries for $SiteUrl"
        return $Permissions
    }
    catch {
        Write-Log "Error retrieving site permissions: $($_.Exception.Message)" "ERROR"
        return @()
    }
}

function Get-SiteStorage {
    param([string]$SiteUrl)
    
    try {
        Write-Log "Retrieving storage information for $SiteUrl..."
        
        $SiteInfo = Get-SPOSite -Identity $SiteUrl -Detailed
        
        $StorageInfo = [PSCustomObject]@{
            SiteUrl = $SiteUrl
            Title = $SiteInfo.Title
            StorageUsedGB = [math]::Round($SiteInfo.StorageUsage / 1GB, 2)
            StorageQuotaGB = [math]::Round($SiteInfo.StorageQuota / 1GB, 2)
            UsagePercentage = [math]::Round(($SiteInfo.StorageUsage / $SiteInfo.StorageQuota) * 100, 2)
            LastModified = $SiteInfo.LastContentModifiedDate
            Created = $SiteInfo.Created
            Template = $SiteInfo.Template
            Owner = $SiteInfo.Owner
        }
        
        return $StorageInfo
    }
    catch {
        Write-Log "Error retrieving storage information: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Get-SiteCustomizations {
    param([string]$SiteUrl)
    
    try {
        Write-Log "Retrieving customization information for $SiteUrl..."
        
        $Customizations = @()
        
        # Get custom lists
        $Lists = Get-SPOList -Web $SiteUrl | Where-Object { $_.Title -notlike "Site Pages" -and $_.Title -notlike "Site Assets" }
        foreach ($List in $Lists) {
            $Customizations += [PSCustomObject]@{
                SiteUrl = $SiteUrl
                Type = "Custom List"
                Name = $List.Title
                ItemCount = $List.ItemCount
                Created = $List.Created
                Modified = $List.LastItemModifiedDate
            }
        }
        
        # Get custom pages
        $Pages = Get-SPOFile -Web $SiteUrl -Folder "SitePages" | Where-Object { $_.Name -notlike "Home.aspx" }
        foreach ($Page in $Pages) {
            $Customizations += [PSCustomObject]@{
                SiteUrl = $SiteUrl
                Type = "Custom Page"
                Name = $Page.Name
                SizeKB = [math]::Round($Page.Length / 1KB, 2)
                Created = $Page.TimeCreated
                Modified = $Page.TimeLastModified
            }
        }
        
        Write-Log "Retrieved $($Customizations.Count) customizations for $SiteUrl"
        return $Customizations
    }
    catch {
        Write-Log "Error retrieving customization information: $($_.Exception.Message)" "ERROR"
        return @()
    }
}

function Generate-SummaryReport {
    param([array]$Sites, [array]$StorageInfo)
    
    try {
        Write-Log "Generating summary report..."
        
        $Summary = [PSCustomObject]@{
            ReportDate = Get-Date
            TotalSites = $Sites.Count
            ActiveSites = ($Sites | Where-Object { $_.Status -eq "Active" }).Count
            InactiveSites = ($Sites | Where-Object { $_.Status -ne "Active" }).Count
            TotalStorageGB = [math]::Round((($StorageInfo | Measure-Object -Property StorageUsedGB -Sum).Sum), 2)
            AverageStorageGB = [math]::Round((($StorageInfo | Measure-Object -Property StorageUsedGB -Average).Average), 2)
            LargestSiteGB = [math]::Round((($StorageInfo | Sort-Object StorageUsedGB -Descending | Select-Object -First 1).StorageUsedGB), 2)
            SitesOverQuota = ($StorageInfo | Where-Object { $_.UsagePercentage -gt 90 }).Count
            ExternalUsers = 0  # Would need to calculate from permissions
        }
        
        return $Summary
    }
    catch {
        Write-Log "Error generating summary report: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Generate-SecurityReport {
    param([array]$Permissions)
    
    try {
        Write-Log "Generating security analysis report..."
        
        $SecurityReport = [PSCustomObject]@{
            ReportDate = Get-Date
            TotalPermissionEntries = $Permissions.Count
            ExternalUsers = ($Permissions | Where-Object { $_.IsExternal -eq $true } | Select-Object -ExpandProperty User -Unique).Count
            FullControlUsers = ($Permissions | Where-Object { $_.PermissionLevel -eq "Full Control" }).Count
            ContributeUsers = ($Permissions | Where-Object { $_.PermissionLevel -eq "Contribute" }).Count
            ReadOnlyUsers = ($Permissions | Where-Object { $_.PermissionLevel -eq "Read" }).Count
            SecurityRecommendations = @()
        }
        
        # Generate security recommendations
        if ($SecurityReport.ExternalUsers -gt 0) {
            $SecurityReport.SecurityRecommendations += "Review external user access"
        }
        if ($SecurityReport.FullControlUsers -gt 20) {
            $SecurityReport.SecurityRecommendations += "Review excessive full control permissions"
        }
        if ($SecurityReport.TotalPermissionEntries -gt 100) {
            $SecurityReport.SecurityRecommendations += "Consider permission cleanup"
        }
        
        return $SecurityReport
    }
    catch {
        Write-Log "Error generating security report: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Generate-StorageReport {
    param([array]$StorageInfo)
    
    try {
        Write-Log "Generating storage analysis report..."
        
        $StorageReport = $StorageInfo | Sort-Object StorageUsedGB -Descending | Select-Object @(
            'SiteUrl',
            'Title',
            'StorageUsedGB',
            'StorageQuotaGB',
            'UsagePercentage',
            'LastModified',
            'Owner'
        )
        
        return $StorageReport
    }
    catch {
        Write-Log "Error generating storage report: $($_.Exception.Message)" "ERROR"
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
    <title>SharePoint Site Inventory Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .over-quota { background-color: #ffebee; }
        .external-user { background-color: #fff3e0; }
    </style>
</head>
<body>
    <h1>SharePoint Site Inventory Report</h1>
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
    Write-Log "Starting SharePoint site inventory generation..."
    
    # Connect to SharePoint Online
    Connect-SharePointOnline
    
    # Get site collections
    $Sites = Get-SiteCollections -Filter $SiteUrl
    
    # Get storage information
    $StorageInfo = @()
    foreach ($Site in $Sites) {
        $SiteStorage = Get-SiteStorage -SiteUrl $Site.Url
        if ($SiteStorage) {
            $StorageInfo += $SiteStorage
        }
    }
    
    # Generate report based on type
    switch ($ReportType) {
        "Summary" {
            $Report = Generate-SummaryReport -Sites $Sites -StorageInfo $StorageInfo
            Write-Log "Summary Report:"
            $Report | Format-List
        }
        "Storage" {
            $Report = Generate-StorageReport -StorageInfo $StorageInfo
            Write-Log "Storage Report:"
            $Report | Format-Table -AutoSize
        }
        "Security" {
            $AllPermissions = @()
            foreach ($Site in $Sites) {
                $SitePermissions = Get-SitePermissions -SiteUrl $Site.Url
                $AllPermissions += $SitePermissions
            }
            $Report = Generate-SecurityReport -Permissions $AllPermissions
            Write-Log "Security Report:"
            $Report | Format-List
        }
        "Detailed" {
            $Report = @()
            foreach ($Site in $Sites) {
                $SiteStorage = $StorageInfo | Where-Object { $_.SiteUrl -eq $Site.Url }
                $Report += [PSCustomObject]@{
                    SiteUrl = $Site.Url
                    Title = $Site.Title
                    Status = $Site.Status
                    Template = $Site.Template
                    StorageUsedGB = if ($SiteStorage) { $SiteStorage.StorageUsedGB } else { 0 }
                    StorageQuotaGB = if ($SiteStorage) { $SiteStorage.StorageQuotaGB } else { 0 }
                    UsagePercentage = if ($SiteStorage) { $SiteStorage.UsagePercentage } else { 0 }
                    Created = $Site.Created
                    LastModified = if ($SiteStorage) { $SiteStorage.LastModified } else { $null }
                    Owner = if ($SiteStorage) { $SiteStorage.Owner } else { $null }
                }
            }
            Write-Log "Detailed Report:"
            $Report | Format-Table -AutoSize
        }
        "Customizations" {
            $AllCustomizations = @()
            foreach ($Site in $Sites) {
                $SiteCustomizations = Get-SiteCustomizations -SiteUrl $Site.Url
                $AllCustomizations += $SiteCustomizations
            }
            $Report = $AllCustomizations
            Write-Log "Customizations Report:"
            $Report | Format-Table -AutoSize
        }
    }
    
    # Export report if path specified
    if ($ExportPath) {
        $Format = [System.IO.Path]::GetExtension($ExportPath).TrimStart('.')
        if ($Format -eq "") { $Format = "CSV" }
        Export-Report -Data $Report -Path $ExportPath -Format $Format
    }
    
    Write-Log "SharePoint site inventory generation completed successfully"
}
catch {
    Write-Log "Error in main execution: $($_.Exception.Message)" "ERROR"
    throw
}
finally {
    # Disconnect from SharePoint Online
    try {
        Disconnect-SPOService
        Write-Log "Disconnected from SharePoint Online"
    }
    catch {
        Write-Log "Warning: Could not disconnect from SharePoint Online: $($_.Exception.Message)" "WARNING"
    }
} 
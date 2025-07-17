# =============================================================================
# Get-ADUserReport.ps1
# =============================================================================
# Purpose: Generate comprehensive Active Directory user reports
# Author: System Administrator
# Version: 1.0.0
# Date: $(Get-Date -Format "yyyy-MM-dd")
# =============================================================================

<#
.SYNOPSIS
    Generates comprehensive Active Directory user reports with detailed information.

.DESCRIPTION
    This script provides detailed reporting capabilities for Active Directory users including:
    - User account information and status
    - Group memberships and permissions
    - Last login and password information
    - Account lockout and security status
    - Organizational unit structure
    - Custom attributes and properties

.PARAMETER SearchBase
    The LDAP path to search for users. Defaults to the domain root.

.PARAMETER Filter
    Custom LDAP filter for user selection. Defaults to all enabled users.

.PARAMETER Properties
    Array of specific properties to retrieve. Defaults to common user properties.

.PARAMETER ExportPath
    Path to export the report. Supports CSV, HTML, and XML formats.

.PARAMETER ReportType
    Type of report to generate: Basic, Detailed, Security, or All.

.PARAMETER IncludeDisabled
    Include disabled user accounts in the report.

.PARAMETER IncludeExpired
    Include expired user accounts in the report.

.PARAMETER Verbose
    Enable verbose output for detailed logging.

.EXAMPLE
    .\Get-ADUserReport.ps1 -ReportType Detailed -ExportPath "C:\Reports\ADUsers.csv"

.EXAMPLE
    .\Get-ADUserReport.ps1 -Filter "Department -eq 'IT'" -ReportType Security

.EXAMPLE
    .\Get-ADUserReport.ps1 -SearchBase "OU=Users,DC=contoso,DC=com" -IncludeDisabled

.NOTES
    Requires Active Directory PowerShell module
    Requires appropriate permissions to read AD user objects
    Supports Windows PowerShell 5.1 and PowerShell Core 6.0+
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$SearchBase = (Get-ADDomain).DistinguishedName,
    
    [Parameter(Mandatory = $false)]
    [string]$Filter = "Enabled -eq $true",
    
    [Parameter(Mandatory = $false)]
    [string[]]$Properties = @(
        "SamAccountName",
        "DisplayName",
        "GivenName",
        "Surname",
        "EmailAddress",
        "Department",
        "Title",
        "Company",
        "Office",
        "TelephoneNumber",
        "Mobile",
        "Manager",
        "MemberOf",
        "LastLogonDate",
        "PasswordLastSet",
        "PasswordExpired",
        "LockedOut",
        "AccountExpirationDate",
        "Created",
        "Modified",
        "DistinguishedName",
        "UserPrincipalName",
        "Description",
        "EmployeeID",
        "EmployeeNumber",
        "Division",
        "EmployeeType",
        "CostCenter",
        "Manager",
        "DirectReports",
        "HomeDirectory",
        "HomeDrive",
        "ScriptPath",
        "ProfilePath",
        "LogonScript",
        "LogonWorkstations",
        "PrimaryGroup",
        "SID",
        "ObjectGUID",
        "ObjectClass",
        "CanonicalName",
        "TrustedForDelegation",
        "TrustedToAuthForDelegation",
        "UseDESKeyOnly",
        "PreAuthNotRequired",
        "HomedirRequired",
        "PasswordNotRequired",
        "SmartCardLogonRequired",
        "DontExpirePassword",
        "MNSLogonAccount",
        "DontRequirePreAuth",
        "PasswordExpired",
        "TrustedForDelegation",
        "TrustedToAuthForDelegation",
        "UseDESKeyOnly",
        "PreAuthNotRequired",
        "HomedirRequired",
        "PasswordNotRequired",
        "SmartCardLogonRequired",
        "DontExpirePassword",
        "MNSLogonAccount",
        "DontRequirePreAuth"
    ),
    
    [Parameter(Mandatory = $false)]
    [string]$ExportPath = ".\ADUserReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Basic", "Detailed", "Security", "All")]
    [string]$ReportType = "Detailed",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeDisabled,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeExpired,
    
    [Parameter(Mandatory = $false)]
    [switch]$Verbose
)

# =============================================================================
# SCRIPT CONFIGURATION
# =============================================================================

# Set error action preference
$ErrorActionPreference = "Stop"

# Import required modules
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "✓ Active Directory module loaded successfully" -ForegroundColor Green
} catch {
    Write-Error "Failed to load Active Directory module. Please ensure it is installed."
    exit 1
}

# =============================================================================
# FUNCTIONS
# =============================================================================

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        default { Write-Host $logMessage -ForegroundColor White }
    }
}

function Get-UserSecurityInfo {
    param(
        [Microsoft.ActiveDirectory.Management.ADUser]$User
    )
    
    $securityInfo = @{
        LockedOut = $User.LockedOut
        PasswordExpired = $User.PasswordExpired
        PasswordNeverExpires = $User.PasswordNeverExpires
        SmartCardLogonRequired = $User.SmartCardLogonRequired
        TrustedForDelegation = $User.TrustedForDelegation
        TrustedToAuthForDelegation = $User.TrustedToAuthForDelegation
        UseDESKeyOnly = $User.UseDESKeyOnly
        PreAuthNotRequired = $User.PreAuthNotRequired
        HomedirRequired = $User.HomedirRequired
        PasswordNotRequired = $User.PasswordNotRequired
        DontExpirePassword = $User.DontExpirePassword
        MNSLogonAccount = $User.MNSLogonAccount
        DontRequirePreAuth = $User.DontRequirePreAuth
        AccountExpirationDate = $User.AccountExpirationDate
        LastLogonDate = $User.LastLogonDate
        PasswordLastSet = $User.PasswordLastSet
    }
    
    return $securityInfo
}

function Get-UserGroupMemberships {
    param(
        [Microsoft.ActiveDirectory.Management.ADUser]$User
    )
    
    try {
        $groups = Get-ADPrincipalGroupMembership -Identity $User.SamAccountName
        $groupNames = $groups | ForEach-Object { $_.Name }
        return ($groupNames -join "; ")
    } catch {
        return "Error retrieving groups"
    }
}

function Get-UserManagerInfo {
    param(
        [Microsoft.ActiveDirectory.Management.ADUser]$User
    )
    
    if ($User.Manager) {
        try {
            $manager = Get-ADUser -Identity $User.Manager -Properties DisplayName, EmailAddress
            return "$($manager.DisplayName) ($($manager.EmailAddress))"
        } catch {
            return $User.Manager
        }
    } else {
        return "No Manager"
    }
}

function Get-UserDirectReports {
    param(
        [Microsoft.ActiveDirectory.Management.ADUser]$User
    )
    
    try {
        $directReports = Get-ADUser -Filter "Manager -eq '$($User.DistinguishedName)'" -Properties DisplayName
        $reportNames = $directReports | ForEach-Object { $_.DisplayName }
        return ($reportNames -join "; ")
    } catch {
        return "Error retrieving direct reports"
    }
}

function Export-Report {
    param(
        [array]$Data,
        [string]$Path,
        [string]$Format
    )
    
    $extension = [System.IO.Path]::GetExtension($Path).ToLower()
    
    switch ($extension) {
        ".csv" {
            $Data | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
            Write-Log "Report exported to CSV: $Path" -Level "SUCCESS"
        }
        ".html" {
            $htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>Active Directory User Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; font-weight: bold; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .header { background-color: #4CAF50; color: white; padding: 15px; }
        .timestamp { color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Active Directory User Report</h1>
        <p class="timestamp">Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
    </div>
"@
            
            $htmlTable = $Data | ConvertTo-Html -Fragment
            $htmlFooter = "</body></html>"
            
            $htmlContent = $htmlHeader + $htmlTable + $htmlFooter
            $htmlContent | Out-File -FilePath $Path -Encoding UTF8
            
            Write-Log "Report exported to HTML: $Path" -Level "SUCCESS"
        }
        ".xml" {
            $Data | Export-Clixml -Path $Path
            Write-Log "Report exported to XML: $Path" -Level "SUCCESS"
        }
        default {
            $Data | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
            Write-Log "Report exported to CSV: $Path" -Level "SUCCESS"
        }
    }
}

# =============================================================================
# MAIN SCRIPT
# =============================================================================

Write-Log "Starting Active Directory User Report Generation" -Level "INFO"
Write-Log "Search Base: $SearchBase" -Level "INFO"
Write-Log "Filter: $Filter" -Level "INFO"
Write-Log "Report Type: $ReportType" -Level "INFO"

# Build filter based on parameters
$finalFilter = $Filter

if (-not $IncludeDisabled) {
    $finalFilter = "($Filter) -and (Enabled -eq `$true)"
}

if (-not $IncludeExpired) {
    $finalFilter = "($finalFilter) -and (AccountExpirationDate -gt `$null -or AccountExpirationDate -gt (Get-Date))"
}

Write-Log "Final Filter: $finalFilter" -Level "INFO"

# Get users based on report type
try {
    Write-Log "Retrieving Active Directory users..." -Level "INFO"
    
    $users = Get-ADUser -Filter $finalFilter -SearchBase $SearchBase -Properties $Properties
    
    Write-Log "Found $($users.Count) users" -Level "SUCCESS"
    
} catch {
    Write-Log "Error retrieving users: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}

# Initialize report data array
$reportData = @()

# Process each user
foreach ($user in $users) {
    Write-Log "Processing user: $($user.SamAccountName)" -Level "INFO"
    
    # Create base user object
    $userReport = [PSCustomObject]@{
        SamAccountName = $user.SamAccountName
        DisplayName = $user.DisplayName
        GivenName = $user.GivenName
        Surname = $user.Surname
        EmailAddress = $user.EmailAddress
        Department = $user.Department
        Title = $user.Title
        Company = $user.Company
        Office = $user.Office
        TelephoneNumber = $user.TelephoneNumber
        Mobile = $user.Mobile
        EmployeeID = $user.EmployeeID
        EmployeeNumber = $user.EmployeeNumber
        Division = $user.Division
        EmployeeType = $user.EmployeeType
        CostCenter = $user.CostCenter
        Description = $user.Description
        DistinguishedName = $user.DistinguishedName
        UserPrincipalName = $user.UserPrincipalName
        Enabled = $user.Enabled
        Created = $user.Created
        Modified = $user.Modified
        LastLogonDate = $user.LastLogonDate
        PasswordLastSet = $user.PasswordLastSet
        AccountExpirationDate = $user.AccountExpirationDate
        HomeDirectory = $user.HomeDirectory
        HomeDrive = $user.HomeDrive
        ScriptPath = $user.ScriptPath
        ProfilePath = $user.ProfilePath
        LogonScript = $user.LogonScript
        LogonWorkstations = $user.LogonWorkstations
        PrimaryGroup = $user.PrimaryGroup
        SID = $user.SID
        ObjectGUID = $user.ObjectGUID
        CanonicalName = $user.CanonicalName
    }
    
    # Add manager information
    $userReport | Add-Member -NotePropertyName "Manager" -NotePropertyValue (Get-UserManagerInfo -User $user)
    
    # Add direct reports
    $userReport | Add-Member -NotePropertyName "DirectReports" -NotePropertyValue (Get-UserDirectReports -User $user)
    
    # Add group memberships
    $userReport | Add-Member -NotePropertyName "GroupMemberships" -NotePropertyValue (Get-UserGroupMemberships -User $user)
    
    # Add security information for detailed reports
    if ($ReportType -in @("Detailed", "Security", "All")) {
        $securityInfo = Get-UserSecurityInfo -User $user
        
        $userReport | Add-Member -NotePropertyName "LockedOut" -NotePropertyValue $securityInfo.LockedOut
        $userReport | Add-Member -NotePropertyName "PasswordExpired" -NotePropertyValue $securityInfo.PasswordExpired
        $userReport | Add-Member -NotePropertyName "PasswordNeverExpires" -NotePropertyValue $securityInfo.PasswordNeverExpires
        $userReport | Add-Member -NotePropertyName "SmartCardLogonRequired" -NotePropertyValue $securityInfo.SmartCardLogonRequired
        $userReport | Add-Member -NotePropertyName "TrustedForDelegation" -NotePropertyValue $securityInfo.TrustedForDelegation
        $userReport | Add-Member -NotePropertyName "TrustedToAuthForDelegation" -NotePropertyValue $securityInfo.TrustedToAuthForDelegation
        $userReport | Add-Member -NotePropertyName "UseDESKeyOnly" -NotePropertyValue $securityInfo.UseDESKeyOnly
        $userReport | Add-Member -NotePropertyName "PreAuthNotRequired" -NotePropertyValue $securityInfo.PreAuthNotRequired
        $userReport | Add-Member -NotePropertyName "HomedirRequired" -NotePropertyValue $securityInfo.HomedirRequired
        $userReport | Add-Member -NotePropertyName "PasswordNotRequired" -NotePropertyValue $securityInfo.PasswordNotRequired
        $userReport | Add-Member -NotePropertyName "DontExpirePassword" -NotePropertyValue $securityInfo.DontExpirePassword
        $userReport | Add-Member -NotePropertyName "MNSLogonAccount" -NotePropertyValue $securityInfo.MNSLogonAccount
        $userReport | Add-Member -NotePropertyName "DontRequirePreAuth" -NotePropertyValue $securityInfo.DontRequirePreAuth
    }
    
    # Add calculated properties
    $userReport | Add-Member -NotePropertyName "DaysSinceLastLogon" -NotePropertyValue (
        if ($user.LastLogonDate) { (Get-Date) - $user.LastLogonDate | ForEach-Object { $_.Days } } else { "Never" }
    )
    
    $userReport | Add-Member -NotePropertyName "DaysSincePasswordSet" -NotePropertyValue (
        if ($user.PasswordLastSet) { (Get-Date) - $user.PasswordLastSet | ForEach-Object { $_.Days } } else { "Unknown" }
    )
    
    $accountStatus = if ($user.LockedOut) { "Locked" }
        elseif ($user.PasswordExpired) { "Password Expired" }
        elseif (-not $user.Enabled) { "Disabled" }
        elseif ($user.AccountExpirationDate -and $user.AccountExpirationDate -lt (Get-Date)) { "Expired" }
        else { "Active" }
    
    $userReport | Add-Member -NotePropertyName "AccountStatus" -NotePropertyValue $accountStatus
    
    # Add to report data
    $reportData += $userReport
}

# Generate summary statistics
$summary = @{
    TotalUsers = $reportData.Count
    EnabledUsers = ($reportData | Where-Object { $_.Enabled -eq $true }).Count
    DisabledUsers = ($reportData | Where-Object { $_.Enabled -eq $false }).Count
    LockedUsers = ($reportData | Where-Object { $_.LockedOut -eq $true }).Count
    ExpiredPasswordUsers = ($reportData | Where-Object { $_.PasswordExpired -eq $true }).Count
    NeverLoggedInUsers = ($reportData | Where-Object { $_.DaysSinceLastLogon -eq "Never" }).Count
    UsersWithManagers = ($reportData | Where-Object { $_.Manager -ne "No Manager" }).Count
    UsersInGroups = ($reportData | Where-Object { $_.GroupMemberships -ne "" }).Count
}

# Display summary
Write-Log "=== REPORT SUMMARY ===" -Level "INFO"
Write-Log "Total Users: $($summary.TotalUsers)" -Level "INFO"
Write-Log "Enabled Users: $($summary.EnabledUsers)" -Level "SUCCESS"
Write-Log "Disabled Users: $($summary.DisabledUsers)" -Level "WARNING"
Write-Log "Locked Users: $($summary.LockedUsers)" -Level "WARNING"
Write-Log "Expired Password Users: $($summary.ExpiredPasswordUsers)" -Level "WARNING"
Write-Log "Never Logged In Users: $($summary.NeverLoggedInUsers)" -Level "WARNING"
Write-Log "Users With Managers: $($summary.UsersWithManagers)" -Level "INFO"
Write-Log "Users In Groups: $($summary.UsersInGroups)" -Level "INFO"

# Export report
try {
    Export-Report -Data $reportData -Path $ExportPath -Format ([System.IO.Path]::GetExtension($ExportPath))
    
    Write-Log "Report generation completed successfully!" -Level "SUCCESS"
    Write-Log "Report location: $ExportPath" -Level "INFO"
    
    # Display sample data
    if ($Verbose) {
        Write-Log "=== SAMPLE DATA ===" -Level "INFO"
        $reportData | Select-Object -First 5 | Format-Table -AutoSize
    }
    
} catch {
    Write-Log "Error exporting report: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}

# =============================================================================
# SCRIPT COMPLETION
# =============================================================================

Write-Log "Active Directory User Report script completed successfully" -Level "SUCCESS"
Write-Log "Total processing time: $((Get-Date) - $scriptStartTime)" -Level "INFO" 
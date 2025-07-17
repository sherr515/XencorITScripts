# =============================================================================
# Set-ADUserBulkOperations.ps1
# =============================================================================
# Purpose: Perform bulk operations on Active Directory users
# Author: System Administrator
# Version: 1.0.0
# Date: $(Get-Date -Format "yyyy-MM-dd")
# =============================================================================

<#
.SYNOPSIS
    Performs bulk operations on Active Directory users with comprehensive logging and error handling.

.DESCRIPTION
    This script provides bulk operations for Active Directory user management including:
    - Bulk user creation from CSV files
    - Bulk user updates and modifications
    - Bulk group membership management
    - Bulk password operations
    - Bulk account enable/disable operations
    - Bulk attribute updates
    - Bulk user deletion and cleanup

.PARAMETER Operation
    The type of bulk operation to perform: Create, Update, Delete, Enable, Disable, 
    AddToGroup, RemoveFromGroup, SetPassword, Unlock, Move, or Export.

.PARAMETER InputFile
    Path to the CSV file containing user data for bulk operations.

.PARAMETER OutputFile
    Path for the output file (for export operations).

.PARAMETER SearchBase
    The LDAP path to search for users. Defaults to the domain root.

.PARAMETER Filter
    Custom LDAP filter for user selection.

.PARAMETER GroupName
    Name of the group for group membership operations.

.PARAMETER Password
    Password for bulk password operations.

.PARAMETER ForcePasswordChange
    Force users to change password at next logon.

.PARAMETER WhatIf
    Show what would happen without making changes.

.PARAMETER Confirm
    Prompt for confirmation before making changes.

.PARAMETER LogFile
    Path to the log file for detailed operation logging.

.EXAMPLE
    .\Set-ADUserBulkOperations.ps1 -Operation Create -InputFile "users.csv" -WhatIf

.EXAMPLE
    .\Set-ADUserBulkOperations.ps1 -Operation AddToGroup -GroupName "IT_Users" -Filter "Department -eq 'IT'"

.EXAMPLE
    .\Set-ADUserBulkOperations.ps1 -Operation Update -InputFile "updates.csv" -LogFile "bulk_operations.log"

.EXAMPLE
    .\Set-ADUserBulkOperations.ps1 -Operation Export -Filter "Enabled -eq `$true" -OutputFile "active_users.csv"

.NOTES
    Requires Active Directory PowerShell module
    Requires appropriate permissions to modify AD user objects
    Supports Windows PowerShell 5.1 and PowerShell Core 6.0+
    CSV files should have headers matching AD attribute names
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Create", "Update", "Delete", "Enable", "Disable", "AddToGroup", "RemoveFromGroup", "SetPassword", "Unlock", "Move", "Export")]
    [string]$Operation,
    
    [Parameter(Mandatory = $false)]
    [string]$InputFile,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputFile,
    
    [Parameter(Mandatory = $false)]
    [string]$SearchBase = (Get-ADDomain).DistinguishedName,
    
    [Parameter(Mandatory = $false)]
    [string]$Filter = "Enabled -eq `$true",
    
    [Parameter(Mandatory = $false)]
    [string]$GroupName,
    
    [Parameter(Mandatory = $false)]
    [SecureString]$Password,
    
    [Parameter(Mandatory = $false)]
    [switch]$ForcePasswordChange,
    
    [Parameter(Mandatory = $false)]
    [string]$LogFile = ".\ADBulkOperations_$(Get-Date -Format 'yyyyMMdd_HHmmss').log",
    
    [Parameter(Mandatory = $false)]
    [switch]$WhatIf,
    
    [Parameter(Mandatory = $false)]
    [switch]$Confirm
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

# Initialize logging
$scriptStartTime = Get-Date
$logMessages = @()

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Add to log array
    $logMessages += $logMessage
    
    # Write to console
    switch ($Level) {
        "ERROR" { Write-Host $logMessage -ForegroundColor Red }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        default { Write-Host $logMessage -ForegroundColor White }
    }
}

function Save-LogFile {
    param([string]$LogPath)
    
    try {
        $logMessages | Out-File -FilePath $LogPath -Encoding UTF8
        Write-Host "✓ Log file saved: $LogPath" -ForegroundColor Green
    } catch {
        Write-Error "Failed to save log file: $($_.Exception.Message)"
    }
}

# =============================================================================
# VALIDATION FUNCTIONS
# =============================================================================

function Test-InputFile {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) {
        Write-Log "Input file not found: $FilePath" -Level "ERROR"
        return $false
    }
    
    if ([System.IO.Path]::GetExtension($FilePath) -ne ".csv") {
        Write-Log "Input file must be a CSV file" -Level "ERROR"
        return $false
    }
    
    try {
        $csvData = Import-Csv -Path $FilePath -ErrorAction Stop
        if ($csvData.Count -eq 0) {
            Write-Log "CSV file is empty" -Level "ERROR"
            return $false
        }
        
        Write-Log "Input file validated: $($csvData.Count) records found" -Level "SUCCESS"
        return $true
    } catch {
        Write-Log "Error reading CSV file: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Test-RequiredParameters {
    switch ($Operation) {
        "Create" {
            if (-not $InputFile) {
                Write-Log "InputFile is required for Create operation" -Level "ERROR"
                return $false
            }
            if (-not (Test-InputFile -FilePath $InputFile)) {
                return $false
            }
        }
        "Update" {
            if (-not $InputFile) {
                Write-Log "InputFile is required for Update operation" -Level "ERROR"
                return $false
            }
            if (-not (Test-InputFile -FilePath $InputFile)) {
                return $false
            }
        }
        "AddToGroup" {
            if (-not $GroupName) {
                Write-Log "GroupName is required for AddToGroup operation" -Level "ERROR"
                return $false
            }
            try {
                Get-ADGroup -Identity $GroupName -ErrorAction Stop | Out-Null
            } catch {
                Write-Log "Group not found: $GroupName" -Level "ERROR"
                return $false
            }
        }
        "RemoveFromGroup" {
            if (-not $GroupName) {
                Write-Log "GroupName is required for RemoveFromGroup operation" -Level "ERROR"
                return $false
            }
            try {
                Get-ADGroup -Identity $GroupName -ErrorAction Stop | Out-Null
            } catch {
                Write-Log "Group not found: $GroupName" -Level "ERROR"
                return $false
            }
        }
        "SetPassword" {
            if (-not $Password) {
                Write-Log "Password is required for SetPassword operation" -Level "ERROR"
                return $false
            }
        }
        "Export" {
            if (-not $OutputFile) {
                Write-Log "OutputFile is required for Export operation" -Level "ERROR"
                return $false
            }
        }
    }
    
    return $true
}

# =============================================================================
# OPERATION FUNCTIONS
# =============================================================================

function New-ADUserBulk {
    param([string]$InputFile)
    
    Write-Log "Starting bulk user creation..." -Level "INFO"
    
    $csvData = Import-Csv -Path $InputFile
    $successCount = 0
    $errorCount = 0
    $errors = @()
    
    foreach ($userData in $csvData) {
        try {
            # Validate required fields
            if (-not $userData.SamAccountName -or -not $userData.GivenName -or -not $userData.Surname) {
                throw "Missing required fields: SamAccountName, GivenName, or Surname"
            }
            
            # Check if user already exists
            $existingUser = Get-ADUser -Filter "SamAccountName -eq '$($userData.SamAccountName)'" -ErrorAction SilentlyContinue
            if ($existingUser) {
                throw "User already exists: $($userData.SamAccountName)"
            }
            
            # Prepare user parameters
            $newUserParams = @{
                SamAccountName = $userData.SamAccountName
                GivenName = $userData.GivenName
                Surname = $userData.Surname
                Name = "$($userData.GivenName) $($userData.Surname)"
                DisplayName = "$($userData.GivenName) $($userData.Surname)"
                UserPrincipalName = "$($userData.SamAccountName)@$((Get-ADDomain).DNSRoot)"
                AccountPassword = (ConvertTo-SecureString -String $userData.Password -AsPlainText -Force)
                Enabled = $true
                ChangePasswordAtLogon = $true
            }
            
            # Add optional parameters
            if ($userData.Department) { $newUserParams.Department = $userData.Department }
            if ($userData.Title) { $newUserParams.Title = $userData.Title }
            if ($userData.Company) { $newUserParams.Company = $userData.Company }
            if ($userData.Office) { $newUserParams.Office = $userData.Office }
            if ($userData.TelephoneNumber) { $newUserParams.TelephoneNumber = $userData.TelephoneNumber }
            if ($userData.EmailAddress) { $newUserParams.EmailAddress = $userData.EmailAddress }
            if ($userData.Description) { $newUserParams.Description = $userData.Description }
            if ($userData.EmployeeID) { $newUserParams.EmployeeID = $userData.EmployeeID }
            if ($userData.Division) { $newUserParams.Division = $userData.Division }
            if ($userData.EmployeeType) { $newUserParams.EmployeeType = $userData.EmployeeType }
            if ($userData.CostCenter) { $newUserParams.CostCenter = $userData.CostCenter }
            
            # Create user
            if ($WhatIf) {
                Write-Log "WHATIF: Would create user $($userData.SamAccountName)" -Level "INFO"
            } else {
                New-ADUser @newUserParams -ErrorAction Stop
                Write-Log "Created user: $($userData.SamAccountName)" -Level "SUCCESS"
                $successCount++
            }
            
        } catch {
            $errorMsg = "Error creating user $($userData.SamAccountName): $($_.Exception.Message)"
            Write-Log $errorMsg -Level "ERROR"
            $errors += $errorMsg
            $errorCount++
        }
    }
    
    Write-Log "Bulk user creation completed. Success: $successCount, Errors: $errorCount" -Level "INFO"
    return @{ Success = $successCount; Errors = $errorCount; ErrorDetails = $errors }
}

function Set-ADUserBulkUpdate {
    param([string]$InputFile)
    
    Write-Log "Starting bulk user updates..." -Level "INFO"
    
    $csvData = Import-Csv -Path $InputFile
    $successCount = 0
    $errorCount = 0
    $errors = @()
    
    foreach ($userData in $csvData) {
        try {
            # Validate required fields
            if (-not $userData.SamAccountName) {
                throw "Missing required field: SamAccountName"
            }
            
            # Check if user exists
            $existingUser = Get-ADUser -Identity $userData.SamAccountName -ErrorAction Stop
            if (-not $existingUser) {
                throw "User not found: $($userData.SamAccountName)"
            }
            
            # Prepare update parameters
            $updateParams = @{}
            
            # Add parameters that exist in CSV
            $properties = @("GivenName", "Surname", "DisplayName", "Department", "Title", "Company", 
                          "Office", "TelephoneNumber", "EmailAddress", "Description", "EmployeeID", 
                          "Division", "EmployeeType", "CostCenter", "Mobile", "HomeDirectory", 
                          "HomeDrive", "ScriptPath", "ProfilePath", "LogonScript")
            
            foreach ($prop in $properties) {
                if ($userData.$prop) {
                    $updateParams[$prop] = $userData.$prop
                }
            }
            
            # Update user
            if ($WhatIf) {
                Write-Log "WHATIF: Would update user $($userData.SamAccountName)" -Level "INFO"
            } else {
                Set-ADUser -Identity $userData.SamAccountName -Replace $updateParams -ErrorAction Stop
                Write-Log "Updated user: $($userData.SamAccountName)" -Level "SUCCESS"
                $successCount++
            }
            
        } catch {
            $errorMsg = "Error updating user $($userData.SamAccountName): $($_.Exception.Message)"
            Write-Log $errorMsg -Level "ERROR"
            $errors += $errorMsg
            $errorCount++
        }
    }
    
    Write-Log "Bulk user updates completed. Success: $successCount, Errors: $errorCount" -Level "INFO"
    return @{ Success = $successCount; Errors = $errorCount; ErrorDetails = $errors }
}

function Add-ADUserToGroupBulk {
    param([string]$GroupName, [string]$Filter)
    
    Write-Log "Starting bulk group addition..." -Level "INFO"
    
    try {
        $users = Get-ADUser -Filter $Filter -SearchBase $SearchBase
        $successCount = 0
        $errorCount = 0
        $errors = @()
        
        foreach ($user in $users) {
            try {
                if ($WhatIf) {
                    Write-Log "WHATIF: Would add user $($user.SamAccountName) to group $GroupName" -Level "INFO"
                } else {
                    Add-ADGroupMember -Identity $GroupName -Members $user.SamAccountName -ErrorAction Stop
                    Write-Log "Added user $($user.SamAccountName) to group $GroupName" -Level "SUCCESS"
                    $successCount++
                }
            } catch {
                $errorMsg = "Error adding user $($user.SamAccountName) to group $GroupName`: $($_.Exception.Message)"
                Write-Log $errorMsg -Level "ERROR"
                $errors += $errorMsg
                $errorCount++
            }
        }
        
        Write-Log "Bulk group addition completed. Success: $successCount, Errors: $errorCount" -Level "INFO"
        return @{ Success = $successCount; Errors = $errorCount; ErrorDetails = $errors }
        
    } catch {
        Write-Log "Error retrieving users: $($_.Exception.Message)" -Level "ERROR"
        return @{ Success = 0; Errors = 1; ErrorDetails = @($_.Exception.Message) }
    }
}

function Remove-ADUserFromGroupBulk {
    param([string]$GroupName, [string]$Filter)
    
    Write-Log "Starting bulk group removal..." -Level "INFO"
    
    try {
        $users = Get-ADUser -Filter $Filter -SearchBase $SearchBase
        $successCount = 0
        $errorCount = 0
        $errors = @()
        
        foreach ($user in $users) {
            try {
                if ($WhatIf) {
                    Write-Log "WHATIF: Would remove user $($user.SamAccountName) from group $GroupName" -Level "INFO"
                } else {
                    Remove-ADGroupMember -Identity $GroupName -Members $user.SamAccountName -ErrorAction Stop
                    Write-Log "Removed user $($user.SamAccountName) from group $GroupName" -Level "SUCCESS"
                    $successCount++
                }
            } catch {
                $errorMsg = "Error removing user $($user.SamAccountName) from group $GroupName`: $($_.Exception.Message)"
                Write-Log $errorMsg -Level "ERROR"
                $errors += $errorMsg
                $errorCount++
            }
        }
        
        Write-Log "Bulk group removal completed. Success: $successCount, Errors: $errorCount" -Level "INFO"
        return @{ Success = $successCount; Errors = $errorCount; ErrorDetails = $errors }
        
    } catch {
        Write-Log "Error retrieving users: $($_.Exception.Message)" -Level "ERROR"
        return @{ Success = 0; Errors = 1; ErrorDetails = @($_.Exception.Message) }
    }
}

function Set-ADUserPasswordBulk {
    param([SecureString]$Password, [string]$Filter, [bool]$ForceChange)
    
    Write-Log "Starting bulk password operations..." -Level "INFO"
    
    try {
        $users = Get-ADUser -Filter $Filter -SearchBase $SearchBase
        $successCount = 0
        $errorCount = 0
        $errors = @()
        
        foreach ($user in $users) {
            try {
                if ($WhatIf) {
                    Write-Log "WHATIF: Would set password for user $($user.SamAccountName)" -Level "INFO"
                } else {
                    Set-ADAccountPassword -Identity $user.SamAccountName -NewPassword $Password -ErrorAction Stop
                    
                    if ($ForceChange) {
                        Set-ADUser -Identity $user.SamAccountName -ChangePasswordAtLogon $true
                    }
                    
                    Write-Log "Set password for user $($user.SamAccountName)" -Level "SUCCESS"
                    $successCount++
                }
            } catch {
                $errorMsg = "Error setting password for user $($user.SamAccountName): $($_.Exception.Message)"
                Write-Log $errorMsg -Level "ERROR"
                $errors += $errorMsg
                $errorCount++
            }
        }
        
        Write-Log "Bulk password operations completed. Success: $successCount, Errors: $errorCount" -Level "INFO"
        return @{ Success = $successCount; Errors = $errorCount; ErrorDetails = $errors }
        
    } catch {
        Write-Log "Error retrieving users: $($_.Exception.Message)" -Level "ERROR"
        return @{ Success = 0; Errors = 1; ErrorDetails = @($_.Exception.Message) }
    }
}

function Unlock-ADUserBulk {
    param([string]$Filter)
    
    Write-Log "Starting bulk user unlock..." -Level "INFO"
    
    try {
        $users = Get-ADUser -Filter $Filter -SearchBase $SearchBase
        $successCount = 0
        $errorCount = 0
        $errors = @()
        
        foreach ($user in $users) {
            try {
                if ($WhatIf) {
                    Write-Log "WHATIF: Would unlock user $($user.SamAccountName)" -Level "INFO"
                } else {
                    Unlock-ADAccount -Identity $user.SamAccountName -ErrorAction Stop
                    Write-Log "Unlocked user $($user.SamAccountName)" -Level "SUCCESS"
                    $successCount++
                }
            } catch {
                $errorMsg = "Error unlocking user $($user.SamAccountName): $($_.Exception.Message)"
                Write-Log $errorMsg -Level "ERROR"
                $errors += $errorMsg
                $errorCount++
            }
        }
        
        Write-Log "Bulk user unlock completed. Success: $successCount, Errors: $errorCount" -Level "INFO"
        return @{ Success = $successCount; Errors = $errorCount; ErrorDetails = $errors }
        
    } catch {
        Write-Log "Error retrieving users: $($_.Exception.Message)" -Level "ERROR"
        return @{ Success = 0; Errors = 1; ErrorDetails = @($_.Exception.Message) }
    }
}

function Enable-ADUserBulk {
    param([string]$Filter)
    
    Write-Log "Starting bulk user enable..." -Level "INFO"
    
    try {
        $users = Get-ADUser -Filter $Filter -SearchBase $SearchBase
        $successCount = 0
        $errorCount = 0
        $errors = @()
        
        foreach ($user in $users) {
            try {
                if ($WhatIf) {
                    Write-Log "WHATIF: Would enable user $($user.SamAccountName)" -Level "INFO"
                } else {
                    Enable-ADAccount -Identity $user.SamAccountName -ErrorAction Stop
                    Write-Log "Enabled user $($user.SamAccountName)" -Level "SUCCESS"
                    $successCount++
                }
            } catch {
                $errorMsg = "Error enabling user $($user.SamAccountName): $($_.Exception.Message)"
                Write-Log $errorMsg -Level "ERROR"
                $errors += $errorMsg
                $errorCount++
            }
        }
        
        Write-Log "Bulk user enable completed. Success: $successCount, Errors: $errorCount" -Level "INFO"
        return @{ Success = $successCount; Errors = $errorCount; ErrorDetails = $errors }
        
    } catch {
        Write-Log "Error retrieving users: $($_.Exception.Message)" -Level "ERROR"
        return @{ Success = 0; Errors = 1; ErrorDetails = @($_.Exception.Message) }
    }
}

function Disable-ADUserBulk {
    param([string]$Filter)
    
    Write-Log "Starting bulk user disable..." -Level "INFO"
    
    try {
        $users = Get-ADUser -Filter $Filter -SearchBase $SearchBase
        $successCount = 0
        $errorCount = 0
        $errors = @()
        
        foreach ($user in $users) {
            try {
                if ($WhatIf) {
                    Write-Log "WHATIF: Would disable user $($user.SamAccountName)" -Level "INFO"
                } else {
                    Disable-ADAccount -Identity $user.SamAccountName -ErrorAction Stop
                    Write-Log "Disabled user $($user.SamAccountName)" -Level "SUCCESS"
                    $successCount++
                }
            } catch {
                $errorMsg = "Error disabling user $($user.SamAccountName): $($_.Exception.Message)"
                Write-Log $errorMsg -Level "ERROR"
                $errors += $errorMsg
                $errorCount++
            }
        }
        
        Write-Log "Bulk user disable completed. Success: $successCount, Errors: $errorCount" -Level "INFO"
        return @{ Success = $successCount; Errors = $errorCount; ErrorDetails = $errors }
        
    } catch {
        Write-Log "Error retrieving users: $($_.Exception.Message)" -Level "ERROR"
        return @{ Success = 0; Errors = 1; ErrorDetails = @($_.Exception.Message) }
    }
}

function Export-ADUserBulk {
    param([string]$Filter, [string]$OutputFile)
    
    Write-Log "Starting bulk user export..." -Level "INFO"
    
    try {
        $users = Get-ADUser -Filter $Filter -SearchBase $SearchBase -Properties *
        
        $exportData = $users | ForEach-Object {
            [PSCustomObject]@{
                SamAccountName = $_.SamAccountName
                DisplayName = $_.DisplayName
                GivenName = $_.GivenName
                Surname = $_.Surname
                EmailAddress = $_.EmailAddress
                Department = $_.Department
                Title = $_.Title
                Company = $_.Company
                Office = $_.Office
                TelephoneNumber = $_.TelephoneNumber
                Mobile = $_.Mobile
                Enabled = $_.Enabled
                LastLogonDate = $_.LastLogonDate
                PasswordLastSet = $_.PasswordLastSet
                AccountExpirationDate = $_.AccountExpirationDate
                LockedOut = $_.LockedOut
                DistinguishedName = $_.DistinguishedName
                UserPrincipalName = $_.UserPrincipalName
                Description = $_.Description
                EmployeeID = $_.EmployeeID
                Division = $_.Division
                EmployeeType = $_.EmployeeType
                CostCenter = $_.CostCenter
                Manager = $_.Manager
                HomeDirectory = $_.HomeDirectory
                HomeDrive = $_.HomeDrive
                ScriptPath = $_.ScriptPath
                ProfilePath = $_.ProfilePath
                LogonScript = $_.LogonScript
                Created = $_.Created
                Modified = $_.Modified
            }
        }
        
        $exportData | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
        Write-Log "Exported $($exportData.Count) users to $OutputFile" -Level "SUCCESS"
        
        return @{ Success = $exportData.Count; Errors = 0; ErrorDetails = @() }
        
    } catch {
        Write-Log "Error exporting users: $($_.Exception.Message)" -Level "ERROR"
        return @{ Success = 0; Errors = 1; ErrorDetails = @($_.Exception.Message) }
    }
}

# =============================================================================
# MAIN SCRIPT
# =============================================================================

Write-Log "Starting Active Directory Bulk Operations" -Level "INFO"
Write-Log "Operation: $Operation" -Level "INFO"
Write-Log "Search Base: $SearchBase" -Level "INFO"
Write-Log "Filter: $Filter" -Level "INFO"

# Validate parameters
if (-not (Test-RequiredParameters)) {
    Write-Log "Parameter validation failed. Exiting." -Level "ERROR"
    exit 1
}

# Perform operation
$result = switch ($Operation) {
    "Create" { New-ADUserBulk -InputFile $InputFile }
    "Update" { Set-ADUserBulkUpdate -InputFile $InputFile }
    "AddToGroup" { Add-ADUserToGroupBulk -GroupName $GroupName -Filter $Filter }
    "RemoveFromGroup" { Remove-ADUserFromGroupBulk -GroupName $GroupName -Filter $Filter }
    "SetPassword" { Set-ADUserPasswordBulk -Password $Password -Filter $Filter -ForceChange $ForcePasswordChange }
    "Unlock" { Unlock-ADUserBulk -Filter $Filter }
    "Enable" { Enable-ADUserBulk -Filter $Filter }
    "Disable" { Disable-ADUserBulk -Filter $Filter }
    "Export" { Export-ADUserBulk -Filter $Filter -OutputFile $OutputFile }
    default {
        Write-Log "Unsupported operation: $Operation" -Level "ERROR"
        exit 1
    }
}

# Display results
Write-Log "=== OPERATION SUMMARY ===" -Level "INFO"
Write-Log "Operation: $Operation" -Level "INFO"
Write-Log "Successful operations: $($result.Success)" -Level "SUCCESS"
Write-Log "Failed operations: $($result.Errors)" -Level "WARNING"

if ($result.ErrorDetails.Count -gt 0) {
    Write-Log "=== ERROR DETAILS ===" -Level "WARNING"
    foreach ($error in $result.ErrorDetails) {
        Write-Log $error -Level "ERROR"
    }
}

# Save log file
Save-LogFile -LogPath $LogFile

# =============================================================================
# SCRIPT COMPLETION
# =============================================================================

Write-Log "Active Directory Bulk Operations script completed" -Level "SUCCESS"
Write-Log "Total processing time: $((Get-Date) - $scriptStartTime)" -Level "INFO"
Write-Log "Log file: $LogFile" -Level "INFO" 
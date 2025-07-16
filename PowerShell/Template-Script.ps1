# =============================================================================
# Script Name: Template-Script.ps1
# Description: Template for PowerShell scripts with standard structure
# Author: [Your Name]
# Date: $(Get-Date -Format 'yyyy-MM-dd')
# Version: 1.0
# =============================================================================

<#
.SYNOPSIS
    Brief description of what the script does.

.DESCRIPTION
    Detailed description of the script's functionality, parameters, and usage.

.PARAMETER ParameterName
    Description of the parameter.

.EXAMPLE
    .\Template-Script.ps1 -ParameterName "Value"
    
    Description of what this example does.

.NOTES
    Additional notes, requirements, or important information.
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$ParameterName = "DefaultValue",
    
    [Parameter(Mandatory=$false)]
    [switch]$Verbose
)

# =============================================================================
# Configuration
# =============================================================================

# Set error action preference
$ErrorActionPreference = "Stop"

# Colors for output
$Green = "Green"
$Yellow = "Yellow"
$Red = "Red"
$Cyan = "Cyan"

# =============================================================================
# Functions
# =============================================================================

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Test-Prerequisites {
    # Add any prerequisite checks here
    Write-ColorOutput "Checking prerequisites..." $Cyan
    
    # Example: Check if a module is installed
    # if (-not (Get-Module -ListAvailable -Name "ModuleName")) {
    #     Write-ColorOutput "Module 'ModuleName' is not installed. Please install it first." $Red
    #     return $false
    # }
    
    Write-ColorOutput "✓ Prerequisites check passed" $Green
    return $true
}

function Main-Function {
    param([string]$InputParameter)
    
    try {
        Write-ColorOutput "Processing: $InputParameter" $Cyan
        
        # Add your main logic here
        
        Write-ColorOutput "Processing completed successfully!" $Green
    }
    catch {
        Write-ColorOutput "Error in Main-Function: $($_.Exception.Message)" $Red
        throw
    }
}

# =============================================================================
# Main Execution
# =============================================================================

try {
    Write-ColorOutput "Script started at $(Get-Date)" $Cyan
    Write-ColorOutput "================================================" $Cyan
    
    # Check prerequisites
    if (-not (Test-Prerequisites)) {
        exit 1
    }
    
    # Validate parameters
    if ([string]::IsNullOrEmpty($ParameterName)) {
        Write-ColorOutput "ParameterName cannot be empty" $Red
        exit 1
    }
    
    # Execute main function
    Main-Function -InputParameter $ParameterName
    
    Write-ColorOutput "Script completed successfully!" $Green
}
catch {
    Write-ColorOutput "Script failed: $($_.Exception.Message)" $Red
    exit 1
}
finally {
    Write-ColorOutput "Script ended at $(Get-Date)" $Cyan
} 
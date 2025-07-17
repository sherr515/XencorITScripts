# instance-tagging.ps1
# Comprehensive EC2 instance tagging and cost allocation management script
#
# OVERALL PURPOSE:
# This script provides comprehensive tagging capabilities for EC2 instances including:
# - Automated tag creation and management
# - Cost allocation and billing organization
# - Environment and project classification
# - Compliance and security tagging
# - Bulk tagging operations across multiple instances
# - Tag validation and cleanup
#
# KEY FEATURES:
# - Multi-instance tagging with pattern matching
# - Cost allocation tags for billing organization
# - Environment and project classification
# - Compliance and security tagging
# - Tag validation and cleanup
# - Bulk operations with dry-run support
#
# USAGE SCENARIOS:
# - Cost allocation and billing organization
# - Environment management (dev, staging, prod)
# - Project and team organization
# - Compliance and security requirements
# - Resource lifecycle management

param(
    [string]$InstanceId = "",
    [string]$Action = "list", # list, add, remove, update, bulk, validate
    [string]$Region = "",
    [string]$Profile = "default",
    [hashtable]$Tags = @{},
    [string]$TagFile = "",
    [string]$Pattern = "",
    [switch]$DryRun,
    [switch]$Force
)

# FUNCTION: Get-InstanceTags
# PURPOSE: Retrieves all tags for a specific EC2 instance
# PARAMETERS:
#   - InstanceId: The ID of the instance to get tags for
#   - Region: AWS region where the instance is located
# RETURNS: Object containing all tags for the instance
# PROCESS:
#   1. Calls AWS CLI to get instance details
#   2. Extracts tags from the response
#   3. Formats tags into readable structure
#   4. Returns tag information or empty array if none
function Get-InstanceTags {
    param([string]$InstanceId, [string]$Region)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    try {
        $instance = aws ec2 describe-instances --instance-ids $InstanceId $regionParam --profile $Profile --output json | ConvertFrom-Json
        
        if ($instance.Reservations.Item(0).Instances.Item(0).Tags) {
            return $instance.Reservations.Item(0).Instances.Item(0).Tags
        } else {
            return @()
        }
    }
    catch {
        Write-Host "Unable to get tags for instance $InstanceId" -ForegroundColor Red
        return @()
    }
}

# FUNCTION: Add-InstanceTags
# PURPOSE: Adds new tags to an EC2 instance
# PARAMETERS:
#   - InstanceId: The ID of the instance to tag
#   - Region: AWS region where the instance is located
#   - Tags: Hashtable of key-value pairs to add as tags
# RETURNS: Success status (boolean)
# PROCESS:
#   1. Validates tag format and requirements
#   2. Converts hashtable to AWS CLI format
#   3. Calls AWS CLI to create tags
#   4. Validates tag creation success
#   5. Returns success status
function Add-InstanceTags {
    param([string]$InstanceId, [string]$Region, [hashtable]$Tags)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    if ($Tags.Count -eq 0) {
        Write-Host "No tags provided to add" -ForegroundColor Yellow
        return $false
    }
    
    try {
        # Validate tags
        # PURPOSE: Ensures tags meet AWS requirements
        # PROCESS: Checks tag key length and value format
        foreach ($key in $Tags.Keys) {
            if ($key.Length -gt 128) {
                Write-Host "Tag key '$key' is too long (max 128 characters)" -ForegroundColor Red
                return $false
            }
            
            if ($Tags.Item($key).Length -gt 256) {
                Write-Host "Tag value for '$key' is too long (max 256 characters)" -ForegroundColor Red
                return $false
            }
        }
        
        # Create tag resources
        # PURPOSE: Converts hashtable to AWS CLI resource format
        # PROCESS: Builds resource string for AWS CLI command
        $resources = "Resource=$InstanceId"
        $tagSpec = @()
        
        foreach ($key in $Tags.Keys) {
            $tagSpec += "Key=$key,Value=$($Tags.Item($key))"
        }
        
        $tagString = $tagSpec -join " "
        
        if (-not $DryRun) {
            # Add tags
            # PURPOSE: Creates tags on the EC2 instance
            # PROCESS: Calls AWS CLI create-tags command
            aws ec2 create-tags --resources $InstanceId --tags $tagString $regionParam --profile $Profile
            
            Write-Host "Tags added successfully to instance $InstanceId" -ForegroundColor Green
            
            # Verify tags were added
            # PURPOSE: Confirms tag creation was successful
            # PROCESS: Retrieves updated tag list and validates
            $updatedTags = Get-InstanceTags -InstanceId $InstanceId -Region $Region
            foreach ($key in $Tags.Keys) {
                $tag = $updatedTags | Where-Object { $_.Key -eq $key }
                if ($tag -and $tag.Value -eq $Tags.Item($key)) {
                    Write-Host "  ✓ $key = $($Tags.Item($key))" -ForegroundColor Green
                } else {
                    Write-Host "  ✗ Failed to add tag: $key" -ForegroundColor Red
                }
            }
        } else {
            Write-Host "[DRY RUN] Would add tags to instance $InstanceId`:" -ForegroundColor Cyan
            foreach ($key in $Tags.Keys) {
                Write-Host ("  {0} = {1}" -f $key, $Tags.Item($key)) -ForegroundColor Gray
            }
        }
        
        return $true
    }
    catch {
        Write-Host "Failed to add tags: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# FUNCTION: Remove-InstanceTags
# PURPOSE: Removes specific tags from an EC2 instance
# PARAMETERS:
#   - InstanceId: The ID of the instance to remove tags from
#   - Region: AWS region where the instance is located
#   - TagKeys: Array of tag keys to remove
# RETURNS: Success status (boolean)
# PROCESS:
#   1. Validates tag keys exist on instance
#   2. Calls AWS CLI to delete tags
#   3. Verifies tag removal
#   4. Returns success status
function Remove-InstanceTags {
    param([string]$InstanceId, [string]$Region, [string[]]$TagKeys)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    if ($TagKeys.Count -eq 0) {
        Write-Host "No tag keys provided to remove" -ForegroundColor Yellow
        return $false
    }
    
    try {
        # Get current tags
        # PURPOSE: Retrieves existing tags to validate removal
        # PROCESS: Gets current tag list and checks for existence
        $currentTags = Get-InstanceTags -InstanceId $InstanceId -Region $Region
        $existingKeys = $currentTags | ForEach-Object { $_.Key }
        
        $tagsToRemove = @()
        foreach ($key in $TagKeys) {
            if ($existingKeys -contains $key) {
                $tagsToRemove += $key
            } else {
                Write-Host "Tag key '$key' not found on instance" -ForegroundColor Yellow
            }
        }
        
        if ($tagsToRemove.Count -eq 0) {
            Write-Host "No valid tags to remove" -ForegroundColor Yellow
            return $false
        }
        
        if (-not $DryRun) {
            # Remove tags
            # PURPOSE: Deletes specified tags from the instance
            # PROCESS: Calls AWS CLI delete-tags command
            $tagString = $tagsToRemove -join " "
            aws ec2 delete-tags --resources $InstanceId --tags $tagString $regionParam --profile $Profile
            
            Write-Host "Tags removed successfully from instance $InstanceId" -ForegroundColor Green
            
            # Verify tags were removed
            # PURPOSE: Confirms tag deletion was successful
            # PROCESS: Retrieves updated tag list and validates removal
            $updatedTags = Get-InstanceTags -InstanceId $InstanceId -Region $Region
            $remainingKeys = $updatedTags | ForEach-Object { $_.Key }
            
            foreach ($key in $tagsToRemove) {
                if ($remainingKeys -notcontains $key) {
                    Write-Host "  ✓ Removed tag: $key" -ForegroundColor Green
                } else {
                    Write-Host "  ✗ Failed to remove tag: $key" -ForegroundColor Red
                }
            }
        } else {
            Write-Host "[DRY RUN] Would remove tags from instance $InstanceId`:" -ForegroundColor Cyan
            foreach ($key in $tagsToRemove) {
                Write-Host "  $key" -ForegroundColor Gray
            }
        }
        
        return $true
    }
    catch {
        Write-Host "Failed to remove tags: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# FUNCTION: Update-InstanceTags
# PURPOSE: Updates existing tags on an EC2 instance
# PARAMETERS:
#   - InstanceId: The ID of the instance to update tags for
#   - Region: AWS region where the instance is located
#   - Tags: Hashtable of key-value pairs to update
# RETURNS: Success status (boolean)
# PROCESS:
#   1. Gets current tags on instance
#   2. Identifies tags that need updating
#   3. Removes old tags and adds new ones
#   4. Validates update success
#   5. Returns success status
function Update-InstanceTags {
    param([string]$InstanceId, [string]$Region, [hashtable]$Tags)
    
    if ($Tags.Count -eq 0) {
        Write-Host "No tags provided to update" -ForegroundColor Yellow
        return $false
    }
    
    try {
        # Get current tags
        # PURPOSE: Retrieves existing tags to identify changes
        # PROCESS: Gets current tag list and compares with new values
        $currentTags = Get-InstanceTags -InstanceId $InstanceId -Region $Region
        $currentTagHash = @{}
        foreach ($tag in $currentTags) {
            $currentTagHash.Item($tag.Key) = $tag.Value
        }
        
        $tagsToUpdate = @{}
        foreach ($key in $Tags.Keys) {
            if ($currentTagHash.ContainsKey($key) -and $currentTagHash.Item($key) -ne $Tags.Item($key)) {
                $tagsToUpdate.Item($key) = $Tags.Item($key)
            } elseif (-not $currentTagHash.ContainsKey($key)) {
                $tagsToUpdate.Item($key) = $Tags.Item($key)
            }
        }
        
        if ($tagsToUpdate.Count -eq 0) {
            Write-Host "No tags need updating" -ForegroundColor Yellow
            return $true
        }
        
        # Update tags by removing and re-adding
        # PURPOSE: Updates tag values by removing old and adding new
        # PROCESS: Deletes old tags and creates new ones with updated values
        $tagKeys = $tagsToUpdate.Keys
        Remove-InstanceTags -InstanceId $InstanceId -Region $Region -TagKeys $tagKeys
        
        if (-not $DryRun) {
            Start-Sleep -Seconds 2 # Brief pause to ensure tags are removed
        }
        
        Add-InstanceTags -InstanceId $InstanceId -Region $Region -Tags $tagsToUpdate
        
        return $true
    }
    catch {
        Write-Host "Failed to update tags: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# FUNCTION: Bulk-TagInstances
# PURPOSE: Applies tags to multiple instances based on pattern matching
# PARAMETERS:
#   - Pattern: Pattern to match instance names or IDs
#   - Region: AWS region where instances are located
#   - Tags: Hashtable of tags to apply
#   - Action: Action to perform (add, update, remove)
# RETURNS: Summary of bulk operation results
# PROCESS:
#   1. Finds instances matching the pattern
#   2. Applies specified action to each instance
#   3. Tracks success and failure counts
#   4. Returns operation summary
function Bulk-TagInstances {
    param([string]$Pattern, [string]$Region, [hashtable]$Tags, [string]$Action)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    try {
        # Find matching instances
        # PURPOSE: Identifies instances that match the specified pattern
        # PROCESS: Lists all instances and filters by pattern
        $instances = aws ec2 describe-instances --filters "Name=instance-state-name,Values=running,stopped" $regionParam --profile $Profile --output json | ConvertFrom-Json
        
        $matchingInstances = @()
        foreach ($reservation in $instances.Reservations) {
            foreach ($instance in $reservation.Instances) {
                $instanceName = ""
                if ($instance.Tags) {
                    $nameTag = $instance.Tags | Where-Object { $_.Key -eq "Name" }
                    if ($nameTag) {
                        $instanceName = $nameTag.Value
                    }
                }
                
                if ($instance.InstanceId -like "*$Pattern*" -or $instanceName -like "*$Pattern*") {
                    $matchingInstances += @{
                        InstanceId = $instance.InstanceId
                        Name = $instanceName
                        State = $instance.State.Name
                    }
                }
            }
        }
        
        if ($matchingInstances.Count -eq 0) {
            Write-Host "No instances found matching pattern: $Pattern" -ForegroundColor Yellow
            return
        }
        
        Write-Host "Found $($matchingInstances.Count) instances matching pattern: $Pattern" -ForegroundColor Cyan
        
        $successCount = 0
        $failureCount = 0
        
        foreach ($instance in $matchingInstances) {
            Write-Host "Processing instance: $($instance.InstanceId) ($($instance.Name))" -ForegroundColor Gray
            
            $result = $false
            switch ($Action.ToLower()) {
                "add" {
                    $result = Add-InstanceTags -InstanceId $instance.InstanceId -Region $Region -Tags $Tags
                }
                "update" {
                    $result = Update-InstanceTags -InstanceId $instance.InstanceId -Region $Region -Tags $Tags
                }
                "remove" {
                    $tagKeys = $Tags.Keys
                    $result = Remove-InstanceTags -InstanceId $instance.InstanceId -Region $Region -TagKeys $tagKeys
                }
            }
            
            if ($result) {
                $successCount++
            } else {
                $failureCount++
            }
        }
        
        Write-Host "`nBulk operation completed:" -ForegroundColor Yellow
        Write-Host "  Success: $successCount" -ForegroundColor Green
        Write-Host "  Failed: $failureCount" -ForegroundColor Red
    }
    catch {
        Write-Host "Failed to perform bulk tagging: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# FUNCTION: Validate-InstanceTags
# PURPOSE: Validates tags on instances for compliance and best practices
# PARAMETERS:
#   - InstanceId: The ID of the instance to validate (optional)
#   - Region: AWS region where instances are located
# RETURNS: Validation report object
# PROCESS:
#   1. Defines required and recommended tags
#   2. Checks instances for tag compliance
#   3. Identifies missing or invalid tags
#   4. Provides recommendations for improvement
function Validate-InstanceTags {
    param([string]$InstanceId, [string]$Region)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    # Define tag requirements
    # PURPOSE: Establishes standard tag requirements for compliance
    # PROCESS: Defines required and recommended tag categories
    $requiredTags = @("Environment", "Project", "Owner")
    $recommendedTags = @("CostCenter", "Application", "Team", "BackupPolicy")
    
    try {
        if ($InstanceId) {
            # Validate single instance
            # PURPOSE: Validates tags on a specific instance
            # PROCESS: Gets instance tags and checks against requirements
            $tags = Get-InstanceTags -InstanceId $InstanceId -Region $Region
            $tagKeys = $tags | ForEach-Object { $_.Key }
            
            Write-Host "Tag validation for instance: $InstanceId" -ForegroundColor Yellow
            Write-Host ("=" * 60) -ForegroundColor DarkGray
            
            $missingRequired = @()
            $missingRecommended = @()
            
            foreach ($tag in $requiredTags) {
                if ($tagKeys -notcontains $tag) {
                    $missingRequired += $tag
                    Write-Host "✗ Missing required tag: $tag" -ForegroundColor Red
                } else {
                    Write-Host "✓ Required tag present: $tag" -ForegroundColor Green
                }
            }
            
            foreach ($tag in $recommendedTags) {
                if ($tagKeys -notcontains $tag) {
                    $missingRecommended += $tag
                    Write-Host "⚠ Missing recommended tag: $tag" -ForegroundColor Yellow
                } else {
                    Write-Host "✓ Recommended tag present: $tag" -ForegroundColor Green
                }
            }
            
            if ($missingRequired.Count -eq 0 -and $missingRecommended.Count -eq 0) {
                Write-Host "`nAll tags are compliant!" -ForegroundColor Green
            } else {
                Write-Host "`nTag compliance issues found:" -ForegroundColor Red
                if ($missingRequired.Count -gt 0) {
                    Write-Host "  Required tags missing: $($missingRequired -join ', ')" -ForegroundColor Red
                }
                if ($missingRecommended.Count -gt 0) {
                    Write-Host "  Recommended tags missing: $($missingRecommended -join ', ')" -ForegroundColor Yellow
                }
            }
        } else {
            # Validate all instances
            # PURPOSE: Validates tags across all instances in region
            # PROCESS: Gets all instances and validates their tags
            $instances = aws ec2 describe-instances --filters "Name=instance-state-name,Values=running,stopped" $regionParam --profile $Profile --output json | ConvertFrom-Json
            
            $complianceReport = @{
                TotalInstances = 0
                CompliantInstances = 0
                NonCompliantInstances = 0
                MissingRequiredTags = @{}
                MissingRecommendedTags = @{}
            }
            
            foreach ($reservation in $instances.Reservations) {
                foreach ($instance in $reservation.Instances) {
                    $complianceReport.TotalInstances++
                    
                    $tags = $instance.Tags
                    $tagKeys = if ($tags) { $tags | ForEach-Object { $_.Key } } else { @() }
                    
                    $missingRequired = @()
                    $missingRecommended = @()
                    
                    foreach ($tag in $requiredTags) {
                        if ($tagKeys -notcontains $tag) {
                            $missingRequired += $tag
                        }
                    }
                    
                    foreach ($tag in $recommendedTags) {
                        if ($tagKeys -notcontains $tag) {
                            $missingRecommended += $tag
                        }
                    }
                    
                    if ($missingRequired.Count -eq 0) {
                        $complianceReport.CompliantInstances++
                    } else {
                        $complianceReport.NonCompliantInstances++
                        $complianceReport.MissingRequiredTags.Item($instance.InstanceId) = $missingRequired
                    }
                    
                    if ($missingRecommended.Count -gt 0) {
                        $complianceReport.MissingRecommendedTags.Item($instance.InstanceId) = $missingRecommended
                    }
                }
            }
            
            Write-Host "Tag compliance report:" -ForegroundColor Yellow
            Write-Host ("=" * 60) -ForegroundColor DarkGray
            Write-Host "Total instances: $($complianceReport.TotalInstances)" -ForegroundColor Cyan
            Write-Host "Compliant instances: $($complianceReport.CompliantInstances)" -ForegroundColor Green
            Write-Host "Non-compliant instances: $($complianceReport.NonCompliantInstances)" -ForegroundColor Red
            
            if ($complianceReport.NonCompliantInstances -gt 0) {
                Write-Host "`nInstances missing required tags:" -ForegroundColor Red
                foreach ($instanceId in $complianceReport.MissingRequiredTags.Keys) {
                    $missing = $complianceReport.MissingRequiredTags.Item($instanceId)
                    Write-Host "  $instanceId`:$($missing -join ', ')" -ForegroundColor Red
                }
            }
        }
    }
    catch {
        Write-Host "Failed to validate tags: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# MAIN SCRIPT EXECUTION
# PURPOSE: Orchestrates tagging operations based on user parameters
# PROCESS:
#   1. Validates input parameters
#   2. Routes to appropriate tagging function
#   3. Handles errors and provides user feedback
#   4. Manages dry-run functionality

Write-Host "AWS EC2 Instance Tagging" -ForegroundColor Green
Write-Host "=======================" -ForegroundColor Green

switch ($Action.ToLower()) {
    "list" {
        # LIST TAGS WORKFLOW
        # PURPOSE: Displays all tags for a specific instance
        # PROCESS: Retrieves and formats tag information
        if ($InstanceId) {
            $tags = Get-InstanceTags -InstanceId $InstanceId -Region $Region
            
            Write-Host "`nTags for instance: $InstanceId" -ForegroundColor Yellow
            Write-Host ("=" * 60) -ForegroundColor DarkGray
            
            if ($tags.Count -gt 0) {
                foreach ($tag in $tags) {
                    Write-Host "$($tag.Key) = $($tag.Value)" -ForegroundColor White
                }
            } else {
                Write-Host "No tags found for this instance" -ForegroundColor Gray
            }
        } else {
            Write-Host "Please specify an InstanceId to list tags" -ForegroundColor Red
        }
    }
    
    "add" {
        # ADD TAGS WORKFLOW
        # PURPOSE: Adds new tags to an EC2 instance
        # PROCESS: Validates tags and adds them to instance
        if (-not $InstanceId) {
            Write-Host "Please specify an InstanceId to add tags" -ForegroundColor Red
            return
        }
        
        if ($Tags.Count -eq 0) {
            Write-Host "Please specify tags to add using -Tags parameter" -ForegroundColor Red
            return
        }
        
        Add-InstanceTags -InstanceId $InstanceId -Region $Region -Tags $Tags
    }
    
    "remove" {
        # REMOVE TAGS WORKFLOW
        # PURPOSE: Removes specific tags from an EC2 instance
        # PROCESS: Identifies and removes specified tags
        if (-not $InstanceId) {
            Write-Host "Please specify an InstanceId to remove tags" -ForegroundColor Red
            return
        }
        
        if ($Tags.Count -eq 0) {
            Write-Host "Please specify tag keys to remove using -Tags parameter" -ForegroundColor Red
            return
        }
        
        $tagKeys = $Tags.Keys
        Remove-InstanceTags -InstanceId $InstanceId -Region $Region -TagKeys $tagKeys
    }
    
    "update" {
        # UPDATE TAGS WORKFLOW
        # PURPOSE: Updates existing tags on an EC2 instance
        # PROCESS: Modifies tag values while preserving others
        if (-not $InstanceId) {
            Write-Host "Please specify an InstanceId to update tags" -ForegroundColor Red
            return
        }
        
        if ($Tags.Count -eq 0) {
            Write-Host "Please specify tags to update using -Tags parameter" -ForegroundColor Red
            return
        }
        
        Update-InstanceTags -InstanceId $InstanceId -Region $Region -Tags $Tags
    }
    
    "bulk" {
        # BULK TAGGING WORKFLOW
        # PURPOSE: Applies tags to multiple instances
        # PROCESS: Finds matching instances and applies tags
        if (-not $Pattern) {
            Write-Host "Please specify a pattern to match instances" -ForegroundColor Red
            return
        }
        
        if ($Tags.Count -eq 0) {
            Write-Host "Please specify tags to apply using -Tags parameter" -ForegroundColor Red
            return
        }
        
        Bulk-TagInstances -Pattern $Pattern -Region $Region -Tags $Tags -Action "add"
    }
    
    "validate" {
        # VALIDATION WORKFLOW
        # PURPOSE: Validates tags for compliance
        # PROCESS: Checks tags against requirements and standards
        Validate-InstanceTags -InstanceId $InstanceId -Region $Region
    }
    
    default {
        Write-Host "Invalid action. Valid actions: list, add, remove, update, bulk, validate" -ForegroundColor Red
    }
}

# USAGE EXAMPLES AND HELP
# PURPOSE: Provides guidance on script usage
# PROCESS: Displays common usage patterns and examples
Write-Host "`nUsage Examples:" -ForegroundColor Magenta
Write-Host "  .\instance-tagging.ps1 -InstanceId i-1234567890abcdef0 -Action list"
Write-Host "  .\instance-tagging.ps1 -InstanceId i-1234567890abcdef0 -Action add -Tags @{Environment='prod', Project='webapp'}"
Write-Host "  .\instance-tagging.ps1 -InstanceId i-1234567890abcdef0 -Action remove -Tags @{OldTag='value'}"
Write-Host "  .\instance-tagging.ps1 -InstanceId i-1234567890abcdef0 -Action update -Tags @{Environment='staging'}"
Write-Host "  .\instance-tagging.ps1 -Action bulk -Pattern 'web-' -Tags @{Environment='prod', Team='devops'}"
Write-Host "  .\instance-tagging.ps1 -InstanceId i-1234567890abcdef0 -Action validate" 
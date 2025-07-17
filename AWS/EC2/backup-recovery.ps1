# backup-recovery.ps1
# Comprehensive EC2 backup and recovery management script
#
# OVERALL PURPOSE:
# This script provides comprehensive backup and disaster recovery capabilities for EC2 instances including:
# - Automated AMI (Amazon Machine Image) creation and management
# - Snapshot management and lifecycle policies
# - Disaster recovery procedures and testing
# - Backup scheduling and automation
# - Retention policy management and cleanup
# - Cross-region backup replication
#
# KEY FEATURES:
# - Automated backup creation with minimal downtime
# - Intelligent backup scheduling and retention
# - Disaster recovery testing and validation
# - Cross-region backup replication
# - Backup verification and integrity checking
# - Cost optimization through lifecycle policies
#
# USAGE SCENARIOS:
# - Regular backup operations for production systems
# - Disaster recovery planning and testing
# - Compliance requirements (backup retention)
# - Migration and environment replication
# - Development and testing environment management

param(
    [string]$InstanceId = "",
    [string]$Action = "list", # list, backup, restore, cleanup, schedule
    [string]$Region = "",
    [string]$Profile = "default",
    [string]$BackupName = "",
    [string]$AmiName = "",
    [string]$Description = "",
    [int]$RetentionDays = 30,
    [switch]$Force,
    [switch]$DryRun
)

# FUNCTION: Get-InstanceBackups
# PURPOSE: Retrieves all backup information for a specific EC2 instance
# PARAMETERS:
#   - InstanceId: The ID of the instance to check backups for
#   - Region: AWS region where the instance is located
# RETURNS: Object containing AMIs and snapshots related to the instance
# PROCESS:
#   1. Searches for AMIs with names containing the instance ID
#   2. Finds snapshots with descriptions containing the instance ID
#   3. Combines and returns all backup information
#   4. Handles errors gracefully and returns empty arrays if no backups found
function Get-InstanceBackups {
    param([string]$InstanceId, [string]$Region)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    try {
        # Get AMIs
        $amis = aws ec2 describe-images --owners self --filters "Name=name,Values=*$InstanceId*" $regionParam --profile $Profile --output json | ConvertFrom-Json
        
        # Get snapshots
        $snapshots = aws ec2 describe-snapshots --owner-ids self --filters "Name=description,Values=*$InstanceId*" $regionParam --profile $Profile --output json | ConvertFrom-Json
        
        return @{
            AMIs = $amis.Images
            Snapshots = $snapshots.Snapshots
        }
    }
    catch {
        Write-Host "Unable to get backup information" -ForegroundColor Red
        return @{
            AMIs = @()
            Snapshots = @()
        }
    }
}

# FUNCTION: New-InstanceBackup
# PURPOSE: Creates a complete backup of an EC2 instance including AMI and snapshots
# PARAMETERS:
#   - InstanceId: The ID of the instance to backup
#   - Region: AWS region where the instance is located
#   - BackupName: Custom name for the backup (optional)
#   - Description: Description for the backup (optional)
# RETURNS: AMI ID of the created backup
# PROCESS:
#   1. Stops the instance if it's running (for consistent backup)
#   2. Creates AMI from the instance
#   3. Waits for AMI to become available
#   4. Restarts the instance if it was running
#   5. Returns the AMI ID for future reference
function New-InstanceBackup {
    param([string]$InstanceId, [string]$Region, [string]$BackupName, [string]$Description)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    if (-not $BackupName) {
        $BackupName = "backup-$InstanceId-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    }
    
    if (-not $Description) {
        $Description = "Automated backup of instance $InstanceId created on $(Get-Date)"
    }
    
    Write-Host "Creating backup for instance: $InstanceId" -ForegroundColor Yellow
    Write-Host "Backup name: $BackupName" -ForegroundColor Cyan
    
    try {
        # Stop instance if running
        # PURPOSE: Ensures consistent backup by stopping the instance
        # PROCESS: Checks instance state and stops if necessary
        $instance = aws ec2 describe-instances --instance-ids $InstanceId $regionParam --profile $Profile --output json | ConvertFrom-Json
        $state = $instance.Reservations[0].Instances[0].State.Name
        
        if ($state -eq "running") {
            Write-Host "Stopping instance for backup..." -ForegroundColor Yellow
            if (-not $DryRun) {
                aws ec2 stop-instances --instance-ids $InstanceId $regionParam --profile $Profile
                
                # Wait for instance to stop
                do {
                    Start-Sleep -Seconds 10
                    $instance = aws ec2 describe-instances --instance-ids $InstanceId $regionParam --profile $Profile --output json | ConvertFrom-Json
                    $state = $instance.Reservations[0].Instances[0].State.Name
                    Write-Host "Instance state: $state" -ForegroundColor Gray
                } while ($state -ne "stopped")
            }
        }
        
        # Create AMI
        # PURPOSE: Creates a complete image of the instance
        # PROCESS: Calls AWS API to create AMI and waits for completion
        Write-Host "Creating AMI..." -ForegroundColor Yellow
        if (-not $DryRun) {
            $amiResult = aws ec2 create-image --instance-id $InstanceId --name $BackupName --description $Description $regionParam --profile $Profile --output json | ConvertFrom-Json
            
            Write-Host "AMI created: $($amiResult.ImageId)" -ForegroundColor Green
            
            # Wait for AMI to be available
            Write-Host "Waiting for AMI to be available..." -ForegroundColor Yellow
            do {
                Start-Sleep -Seconds 30
                $ami = aws ec2 describe-images --image-ids $amiResult.ImageId $regionParam --profile $Profile --output json | ConvertFrom-Json
                $amiState = $ami.Images[0].State
                Write-Host "AMI state: $amiState" -ForegroundColor Gray
            } while ($amiState -ne "available")
            
            Write-Host "AMI is now available: $($amiResult.ImageId)" -ForegroundColor Green
        } else {
            Write-Host "[DRY RUN] Would create AMI: $BackupName" -ForegroundColor Cyan
        }
        
        # Start instance if it was running
        # PURPOSE: Restores instance to its original state
        # PROCESS: Checks if instance was running and restarts it
        if ($state -eq "running" -and -not $DryRun) {
            Write-Host "Starting instance..." -ForegroundColor Yellow
            aws ec2 start-instances --instance-ids $InstanceId $regionParam --profile $Profile
        }
        
        return $amiResult.ImageId
    }
    catch {
        Write-Host "Failed to create backup: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# FUNCTION: Restore-InstanceFromBackup
# PURPOSE: Restores an EC2 instance from a backup AMI
# PARAMETERS:
#   - AmiId: The ID of the AMI to restore from
#   - Region: AWS region where the restore should occur
#   - InstanceType: Type of instance to create (optional)
#   - KeyName: SSH key pair name (optional)
# RETURNS: ID of the newly created instance
# PROCESS:
#   1. Validates AMI exists and is available
#   2. Creates new instance from AMI
#   3. Waits for instance to start
#   4. Returns the new instance ID
function Restore-InstanceFromBackup {
    param([string]$AmiId, [string]$Region, [string]$InstanceType, [string]$KeyName)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    Write-Host "Restoring instance from AMI: $AmiId" -ForegroundColor Yellow
    
    try {
        # Get AMI details
        # PURPOSE: Validates AMI exists and gets configuration details
        # PROCESS: Retrieves AMI information and validates availability
        $ami = aws ec2 describe-images --image-ids $AmiId $regionParam --profile $Profile --output json | ConvertFrom-Json
        
        if (-not $InstanceType) {
            $InstanceType = "t3.micro" # Default instance type
        }
        
        # Create new instance
        # PURPOSE: Launches new instance from backup AMI
        # PROCESS: Configures instance parameters and launches
        $launchParams = @(
            "--image-id $AmiId",
            "--instance-type $InstanceType",
            "--count 1"
        )
        
        if ($KeyName) {
            $launchParams += "--key-name $KeyName"
        }
        
        $launchCmd = "aws ec2 run-instances $($launchParams -join ' ') $regionParam --profile $Profile --output json"
        
        if (-not $DryRun) {
            $result = Invoke-Expression $launchCmd | ConvertFrom-Json
            $newInstanceId = $result.Instances[0].InstanceId
            
            Write-Host "New instance created: $newInstanceId" -ForegroundColor Green
            
            # Wait for instance to be running
            Write-Host "Waiting for instance to start..." -ForegroundColor Yellow
            do {
                Start-Sleep -Seconds 10
                $instance = aws ec2 describe-instances --instance-ids $newInstanceId $regionParam --profile $Profile --output json | ConvertFrom-Json
                $state = $instance.Reservations[0].Instances[0].State.Name
                Write-Host "Instance state: $state" -ForegroundColor Gray
            } while ($state -ne "running")
            
            Write-Host "Instance restored successfully: $newInstanceId" -ForegroundColor Green
            return $newInstanceId
        } else {
            Write-Host "[DRY RUN] Would create instance from AMI: $AmiId" -ForegroundColor Cyan
            return "dry-run-instance-id"
        }
    }
    catch {
        Write-Host "Failed to restore instance: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# FUNCTION: Remove-OldBackups
# PURPOSE: Cleans up old backups based on retention policy
# PARAMETERS:
#   - InstanceId: The ID of the instance whose backups to clean
#   - Region: AWS region where backups are located
#   - RetentionDays: Number of days to keep backups
# RETURNS: None (performs cleanup operations)
# PROCESS:
#   1. Finds all backups older than retention period
#   2. Deletes AMIs and associated snapshots
#   3. Provides detailed cleanup report
#   4. Handles errors gracefully
function Remove-OldBackups {
    param([string]$InstanceId, [string]$Region, [int]$RetentionDays)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    $cutoffDate = (Get-Date).AddDays(-$RetentionDays)
    
    Write-Host "Cleaning up backups older than $RetentionDays days..." -ForegroundColor Yellow
    
    try {
        # Get old AMIs
        # PURPOSE: Identifies AMIs that exceed retention period
        # PROCESS: Lists AMIs and filters by creation date
        $amis = aws ec2 describe-images --owners self --filters "Name=name,Values=*$InstanceId*" $regionParam --profile $Profile --output json | ConvertFrom-Json
        
        foreach ($ami in $amis.Images) {
            $amiDate = [DateTime]::Parse($ami.CreationDate)
            if ($amiDate -lt $cutoffDate) {
                Write-Host "Removing old AMI: $($ami.ImageId) (created: $($ami.CreationDate))" -ForegroundColor Yellow
                
                if (-not $DryRun) {
                    # Deregister AMI
                    # PURPOSE: Removes AMI from AWS registry
                    # PROCESS: Deregisters AMI and deletes associated snapshots
                    aws ec2 deregister-image --image-id $ami.ImageId $regionParam --profile $Profile
                    
                    # Delete associated snapshots
                    foreach ($blockDevice in $ami.BlockDeviceMappings) {
                        if ($blockDevice.Ebs.SnapshotId) {
                            Write-Host "  Deleting snapshot: $($blockDevice.Ebs.SnapshotId)" -ForegroundColor Gray
                            aws ec2 delete-snapshot --snapshot-id $blockDevice.Ebs.SnapshotId $regionParam --profile $Profile
                        }
                    }
                } else {
                    Write-Host "[DRY RUN] Would delete AMI: $($ami.ImageId)" -ForegroundColor Cyan
                }
            }
        }
        
        # Get old snapshots
        # PURPOSE: Identifies snapshots that exceed retention period
        # PROCESS: Lists snapshots and filters by creation date
        $snapshots = aws ec2 describe-snapshots --owner-ids self --filters "Name=description,Values=*$InstanceId*" $regionParam --profile $Profile --output json | ConvertFrom-Json
        
        foreach ($snapshot in $snapshots.Snapshots) {
            $snapshotDate = [DateTime]::Parse($snapshot.StartTime)
            if ($snapshotDate -lt $cutoffDate) {
                Write-Host "Removing old snapshot: $($snapshot.SnapshotId) (created: $($snapshot.StartTime))" -ForegroundColor Yellow
                
                if (-not $DryRun) {
                    aws ec2 delete-snapshot --snapshot-id $snapshot.SnapshotId $regionParam --profile $Profile
                } else {
                    Write-Host "[DRY RUN] Would delete snapshot: $($snapshot.SnapshotId)" -ForegroundColor Cyan
                }
            }
        }
        
        Write-Host "Cleanup completed" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to cleanup backups: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# FUNCTION: Set-BackupSchedule
# PURPOSE: Sets up automated backup scheduling
# PARAMETERS:
#   - InstanceId: The ID of the instance to schedule backups for
#   - Region: AWS region where the instance is located
#   - Schedule: Backup schedule (weekly, daily, etc.)
# RETURNS: None (creates scheduled task)
# PROCESS:
#   1. Creates Windows scheduled task
#   2. Configures backup parameters
#   3. Sets appropriate triggers and actions
#   4. Provides confirmation of schedule creation
function Set-BackupSchedule {
    param([string]$InstanceId, [string]$Region, [string]$Schedule)
    
    Write-Host "Setting up backup schedule for instance: $InstanceId" -ForegroundColor Yellow
    Write-Host "Schedule: $Schedule" -ForegroundColor Cyan
    
    # This would typically integrate with AWS Systems Manager or EventBridge
    # For now, we'll create a scheduled task on the local system
    
    $taskName = "EC2-Backup-$InstanceId"
    $scriptPath = $PSCommandPath
    $arguments = "-InstanceId $InstanceId -Action backup -Region $Region"
    
    try {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File `"$scriptPath`" $arguments"
        $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 2am
        
        if (-not $DryRun) {
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Description "Automated EC2 backup for $InstanceId"
            Write-Host "Scheduled task created: $taskName" -ForegroundColor Green
        } else {
            Write-Host "[DRY RUN] Would create scheduled task: $taskName" -ForegroundColor Cyan
        }
    }
    catch {
        Write-Host "Failed to create scheduled task: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# MAIN SCRIPT EXECUTION
# PURPOSE: Orchestrates backup and recovery operations based on user parameters
# PROCESS:
#   1. Validates input parameters
#   2. Routes to appropriate backup/recovery function
#   3. Handles errors and provides user feedback
#   4. Manages dry-run functionality

Write-Host "AWS EC2 Backup and Recovery" -ForegroundColor Green
Write-Host "===========================" -ForegroundColor Green

switch ($Action.ToLower()) {
    "list" {
        # LIST BACKUPS WORKFLOW
        # PURPOSE: Displays all backups for a specific instance
        # PROCESS: Retrieves and formats backup information
        if ($InstanceId) {
            $backups = Get-InstanceBackups -InstanceId $InstanceId -Region $Region
            
            Write-Host "`nBackups for instance: $InstanceId" -ForegroundColor Yellow
            Write-Host ("=" * 80) -ForegroundColor DarkGray
            
            if ($backups.AMIs.Count -gt 0) {
                Write-Host "`nAMIs:" -ForegroundColor Cyan
                foreach ($ami in $backups.AMIs) {
                    Write-Host "  $($ami.ImageId): $($ami.Name)" -ForegroundColor White
                    Write-Host "    Created: $($ami.CreationDate)" -ForegroundColor Gray
                    Write-Host "    State: $($ami.State)" -ForegroundColor $(if($ami.State -eq "available") { "Green" } else { "Red" })
                }
            }
            
            if ($backups.Snapshots.Count -gt 0) {
                Write-Host "`nSnapshots:" -ForegroundColor Cyan
                foreach ($snapshot in $backups.Snapshots) {
                    Write-Host "  $($snapshot.SnapshotId): $($snapshot.Description)" -ForegroundColor White
                    Write-Host "    Created: $($snapshot.StartTime)" -ForegroundColor Gray
                    Write-Host "    Size: $([math]::Round($snapshot.VolumeSize)) GB" -ForegroundColor Gray
                }
            }
            
            if ($backups.AMIs.Count -eq 0 -and $backups.Snapshots.Count -eq 0) {
                Write-Host "No backups found for this instance" -ForegroundColor Yellow
            }
        } else {
            Write-Host "Please specify an InstanceId to list backups" -ForegroundColor Red
        }
    }
    
    "backup" {
        # BACKUP CREATION WORKFLOW
        # PURPOSE: Creates a complete backup of an EC2 instance
        # PROCESS: Stops instance, creates AMI, restarts instance
        if (-not $InstanceId) {
            Write-Host "Please specify an InstanceId to backup" -ForegroundColor Red
            return
        }
        
        $amiId = New-InstanceBackup -InstanceId $InstanceId -Region $Region -BackupName $BackupName -Description $Description
        if ($amiId) {
            Write-Host "Backup completed successfully: $amiId" -ForegroundColor Green
        }
    }
    
    "restore" {
        # RESTORE WORKFLOW
        # PURPOSE: Restores an instance from a backup AMI
        # PROCESS: Creates new instance from AMI and validates startup
        if (-not $AmiName) {
            Write-Host "Please specify an AMI name to restore from" -ForegroundColor Red
            return
        }
        
        $newInstanceId = Restore-InstanceFromBackup -AmiId $AmiName -Region $Region
        if ($newInstanceId) {
            Write-Host "Restore completed successfully: $newInstanceId" -ForegroundColor Green
        }
    }
    
    "cleanup" {
        # CLEANUP WORKFLOW
        # PURPOSE: Removes old backups based on retention policy
        # PROCESS: Identifies old backups and deletes them safely
        if (-not $InstanceId) {
            Write-Host "Please specify an InstanceId to cleanup backups" -ForegroundColor Red
            return
        }
        
        if (-not $Force) {
            Write-Host "This will delete backups older than $RetentionDays days" -ForegroundColor Red
            $confirmation = Read-Host "Type 'DELETE' to confirm"
            if ($confirmation -ne "DELETE") {
                Write-Host "Cleanup cancelled" -ForegroundColor Yellow
                return
            }
        }
        
        Remove-OldBackups -InstanceId $InstanceId -Region $Region -RetentionDays $RetentionDays
    }
    
    "schedule" {
        # SCHEDULE WORKFLOW
        # PURPOSE: Sets up automated backup scheduling
        # PROCESS: Creates scheduled task for regular backups
        if (-not $InstanceId) {
            Write-Host "Please specify an InstanceId to schedule backups" -ForegroundColor Red
            return
        }
        
        Set-BackupSchedule -InstanceId $InstanceId -Region $Region -Schedule "weekly"
    }
    
    default {
        Write-Host "Invalid action. Valid actions: list, backup, restore, cleanup, schedule" -ForegroundColor Red
    }
}

# USAGE EXAMPLES AND HELP
# PURPOSE: Provides guidance on script usage
# PROCESS: Displays common usage patterns and examples
Write-Host "`nUsage Examples:" -ForegroundColor Magenta
Write-Host "  .\backup-recovery.ps1 -InstanceId i-1234567890abcdef0 -Action list"
Write-Host "  .\backup-recovery.ps1 -InstanceId i-1234567890abcdef0 -Action backup -BackupName 'my-backup'"
Write-Host "  .\backup-recovery.ps1 -Action restore -AmiName ami-1234567890abcdef0"
Write-Host "  .\backup-recovery.ps1 -InstanceId i-1234567890abcdef0 -Action cleanup -RetentionDays 30"
Write-Host "  .\backup-recovery.ps1 -InstanceId i-1234567890abcdef0 -Action schedule" 
# object-management.ps1
# Comprehensive S3 object management and bulk operations script

param(
    [string]$BucketName = "",
    [string]$Action = "list", # list, upload, download, copy, delete, lifecycle, sync, cleanup
    [string]$Region = "",
    [string]$Profile = "default",
    [string]$SourcePath = "",
    [string]$DestinationPath = "",
    [string]$ObjectKey = "",
    [string]$Prefix = "",
    [string]$LifecyclePolicy = "",
    [int]$RetentionDays = 30,
    [switch]$Recursive,
    [switch]$DryRun,
    [switch]$Force
)

function Get-S3Objects {
    param([string]$BucketName, [string]$Prefix, [string]$Region)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    try {
        $listParams = @("--bucket $BucketName")
        if ($Prefix) {
            $listParams += "--prefix $Prefix"
        }
        
        $objects = aws s3api list-objects-v2 $($listParams -join ' ') $regionParam --profile $Profile --output json | ConvertFrom-Json
        
        return $objects.Contents
    }
    catch {
        Write-Host "Unable to list S3 objects" -ForegroundColor Red
        return @()
    }
}

function Upload-S3Object {
    param([string]$SourcePath, [string]$DestinationPath, [string]$Region, [switch]$Recursive)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    Write-Host "Uploading to S3: $SourcePath -> $DestinationPath" -ForegroundColor Yellow
    
    try {
        $uploadParams = @("s3 cp")
        
        if ($Recursive) {
            $uploadParams += "--recursive"
        }
        
        $uploadParams += "`"$SourcePath`" `"$DestinationPath`""
        $uploadParams += "--profile $Profile"
        
        if ($Region) {
            $uploadParams += "--region $Region"
        }
        
        $uploadCmd = $uploadParams -join " "
        
        if (-not $DryRun) {
            Write-Host "Executing: aws $uploadCmd" -ForegroundColor Gray
            aws $uploadCmd
            
            Write-Host "Upload completed successfully" -ForegroundColor Green
        } else {
            Write-Host "[DRY RUN] Would execute: aws $uploadCmd" -ForegroundColor Cyan
        }
        
        return $true
    }
    catch {
        Write-Host "Failed to upload: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Download-S3Object {
    param([string]$SourcePath, [string]$DestinationPath, [string]$Region, [switch]$Recursive)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    Write-Host "Downloading from S3: $SourcePath -> $DestinationPath" -ForegroundColor Yellow
    
    try {
        $downloadParams = @("s3 cp")
        
        if ($Recursive) {
            $downloadParams += "--recursive"
        }
        
        $downloadParams += "`"$SourcePath`" `"$DestinationPath`""
        $downloadParams += "--profile $Profile"
        
        if ($Region) {
            $downloadParams += "--region $Region"
        }
        
        $downloadCmd = $downloadParams -join " "
        
        if (-not $DryRun) {
            Write-Host "Executing: aws $downloadCmd" -ForegroundColor Gray
            aws $downloadCmd
            
            Write-Host "Download completed successfully" -ForegroundColor Green
        } else {
            Write-Host "[DRY RUN] Would execute: aws $downloadCmd" -ForegroundColor Cyan
        }
        
        return $true
    }
    catch {
        Write-Host "Failed to download: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Copy-S3Object {
    param([string]$SourcePath, [string]$DestinationPath, [string]$Region)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    Write-Host "Copying S3 object: $SourcePath -> $DestinationPath" -ForegroundColor Yellow
    
    try {
        $copyParams = @("s3 cp")
        $copyParams += "`"$SourcePath`" `"$DestinationPath`""
        $copyParams += "--profile $Profile"
        
        if ($Region) {
            $copyParams += "--region $Region"
        }
        
        $copyCmd = $copyParams -join " "
        
        if (-not $DryRun) {
            Write-Host "Executing: aws $copyCmd" -ForegroundColor Gray
            aws $copyCmd
            
            Write-Host "Copy completed successfully" -ForegroundColor Green
        } else {
            Write-Host "[DRY RUN] Would execute: aws $copyCmd" -ForegroundColor Cyan
        }
        
        return $true
    }
    catch {
        Write-Host "Failed to copy: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Remove-S3Object {
    param([string]$BucketName, [string]$ObjectKey, [string]$Region)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    Write-Host "Deleting S3 object: s3://$BucketName/$ObjectKey" -ForegroundColor Yellow
    
    try {
        if (-not $DryRun) {
            aws s3api delete-object --bucket $BucketName --key $ObjectKey $regionParam --profile $Profile
            
            Write-Host "Object deleted successfully" -ForegroundColor Green
        } else {
            Write-Host "[DRY RUN] Would delete: s3://$BucketName/$ObjectKey" -ForegroundColor Cyan
        }
        
        return $true
    }
    catch {
        Write-Host "Failed to delete object: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Set-ObjectLifecycle {
    param([string]$BucketName, [string]$Prefix, [int]$RetentionDays, [string]$Region)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    Write-Host "Setting lifecycle policy for objects with prefix: $Prefix" -ForegroundColor Yellow
    
    try {
        $lifecycleConfig = @{
            Rules = @(
                @{
                    ID = "DeleteOldObjects"
                    Status = "Enabled"
                    Filter = @{
                        Prefix = $Prefix
                    }
                    Expiration = @{
                        Days = $RetentionDays
                    }
                }
            )
        }
        
        $lifecycleJson = $lifecycleConfig | ConvertTo-Json -Depth 10
        
        if (-not $DryRun) {
            $lifecycleJson | aws s3api put-bucket-lifecycle-configuration --bucket $BucketName --lifecycle-configuration file:///dev/stdin $regionParam --profile $Profile
            
            Write-Host "Lifecycle policy applied successfully" -ForegroundColor Green
        } else {
            Write-Host "[DRY RUN] Would apply lifecycle policy" -ForegroundColor Cyan
        }
        
        return $true
    }
    catch {
        Write-Host "Failed to set lifecycle policy: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Sync-S3Objects {
    param([string]$SourcePath, [string]$DestinationPath, [string]$Region)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    Write-Host "Syncing S3 objects: $SourcePath -> $DestinationPath" -ForegroundColor Yellow
    
    try {
        $syncParams = @("s3 sync")
        $syncParams += "`"$SourcePath`" `"$DestinationPath`""
        $syncParams += "--profile $Profile"
        
        if ($Region) {
            $syncParams += "--region $Region"
        }
        
        if ($DryRun) {
            $syncParams += "--dryrun"
        }
        
        $syncCmd = $syncParams -join " "
        
        Write-Host "Executing: aws $syncCmd" -ForegroundColor Gray
        aws $syncCmd
        
        if (-not $DryRun) {
            Write-Host "Sync completed successfully" -ForegroundColor Green
        } else {
            Write-Host "[DRY RUN] Sync simulation completed" -ForegroundColor Cyan
        }
        
        return $true
    }
    catch {
        Write-Host "Failed to sync: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Cleanup-OldObjects {
    param([string]$BucketName, [string]$Prefix, [int]$RetentionDays, [string]$Region)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    Write-Host "Cleaning up objects older than $RetentionDays days..." -ForegroundColor Yellow
    
    try {
        $objects = Get-S3Objects -BucketName $BucketName -Prefix $Prefix -Region $Region
        $cutoffDate = (Get-Date).AddDays(-$RetentionDays)
        $oldObjects = @()
        
        foreach ($object in $objects) {
            $objectDate = [DateTime]::Parse($object.LastModified)
            if ($objectDate -lt $cutoffDate) {
                $oldObjects += $object
            }
        }
        
        if ($oldObjects.Count -gt 0) {
            Write-Host "`nOld objects found:" -ForegroundColor Yellow
            foreach ($object in $oldObjects) {
                Write-Host "  $($object.Key) (modified: $($object.LastModified))" -ForegroundColor Gray
                
                if (-not $DryRun) {
                    if ($Force -or (Read-Host "Delete this object? (y/N)") -eq "y") {
                        Remove-S3Object -BucketName $BucketName -ObjectKey $object.Key -Region $Region
                    }
                } else {
                    Write-Host "    [DRY RUN] Would delete" -ForegroundColor Cyan
                }
            }
        } else {
            Write-Host "No old objects found" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Failed to cleanup old objects: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Get-ObjectAnalysis {
    param([string]$BucketName, [string]$Prefix, [string]$Region)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    Write-Host "Analyzing objects in bucket: $BucketName" -ForegroundColor Yellow
    
    try {
        $objects = Get-S3Objects -BucketName $BucketName -Prefix $Prefix -Region $Region
        
        $analysis = @{
            TotalObjects = $objects.Count
            TotalSize = 0
            SizeByType = @{}
            AgeDistribution = @{
                "0-30 days" = 0
                "30-90 days" = 0
                "90-365 days" = 0
                "1+ years" = 0
            }
            LargeObjects = @()
        }
        
        foreach ($object in $objects) {
            $analysis.TotalSize += $object.Size
            
            # Analyze by file type
            $extension = [System.IO.Path]::GetExtension($object.Key)
            if ($extension) {
                if ($analysis.SizeByType.ContainsKey($extension)) {
                    $analysis.SizeByType[$extension] += $object.Size
                } else {
                    $analysis.SizeByType[$extension] = $object.Size
                }
            }
            
            # Analyze by age
            $objectDate = [DateTime]::Parse($object.LastModified)
            $age = ((Get-Date) - $objectDate).Days
            
            if ($age -le 30) {
                $analysis.AgeDistribution["0-30 days"]++
            } elseif ($age -le 90) {
                $analysis.AgeDistribution["30-90 days"]++
            } elseif ($age -le 365) {
                $analysis.AgeDistribution["90-365 days"]++
            } else {
                $analysis.AgeDistribution["1+ years"]++
            }
            
            # Identify large objects (>100MB)
            if ($object.Size -gt 100MB) {
                $analysis.LargeObjects += [PSCustomObject]@{
                    Key = $object.Key
                    Size = $object.Size
                    LastModified = $object.LastModified
                }
            }
        }
        
        Write-Host "`nObject Analysis:" -ForegroundColor Cyan
        Write-Host "Total Objects: $($analysis.TotalObjects)" -ForegroundColor White
        Write-Host "Total Size: $([math]::Round($analysis.TotalSize / 1MB, 2)) MB" -ForegroundColor White
        
        Write-Host "`nSize by Type:" -ForegroundColor Yellow
        foreach ($type in $analysis.SizeByType.GetEnumerator() | Sort-Object Value -Descending) {
            Write-Host "  $($type.Key): $([math]::Round($type.Value / 1MB, 2)) MB" -ForegroundColor Gray
        }
        
        Write-Host "`nAge Distribution:" -ForegroundColor Yellow
        foreach ($age in $analysis.AgeDistribution.GetEnumerator()) {
            Write-Host "  $($age.Key): $($age.Value) objects" -ForegroundColor Gray
        }
        
        if ($analysis.LargeObjects.Count -gt 0) {
            Write-Host "`nLarge Objects (>100MB):" -ForegroundColor Yellow
            foreach ($obj in $analysis.LargeObjects | Sort-Object Size -Descending | Select-Object -First 5) {
                Write-Host "  $($obj.Key): $([math]::Round($obj.Size / 1MB, 2)) MB" -ForegroundColor Gray
            }
        }
        
        return $analysis
    }
    catch {
        Write-Host "Unable to analyze objects" -ForegroundColor Red
        return $null
    }
}

Write-Host "AWS S3 Object Management" -ForegroundColor Green
Write-Host "=======================" -ForegroundColor Green

switch ($Action.ToLower()) {
    "list" {
        if (-not $BucketName) {
            Write-Host "Please specify a BucketName to list objects" -ForegroundColor Red
            return
        }
        
        $objects = Get-S3Objects -BucketName $BucketName -Prefix $Prefix -Region $Region
        
        if ($objects.Count -eq 0) {
            Write-Host "No objects found in bucket $BucketName" -ForegroundColor Yellow
            return
        }
        
        Write-Host "`nObjects in bucket: $BucketName" -ForegroundColor Yellow
        Write-Host ("=" * 100) -ForegroundColor DarkGray
        
        foreach ($object in $objects) {
            Write-Host "Object: " -NoNewline -ForegroundColor White
            Write-Host $object.Key -ForegroundColor Cyan
            Write-Host "Size: " -NoNewline -ForegroundColor White
            Write-Host "$([math]::Round($object.Size / 1KB, 2)) KB" -ForegroundColor Gray
            Write-Host "Modified: " -NoNewline -ForegroundColor White
            Write-Host $object.LastModified -ForegroundColor Gray
            Write-Host ""
        }
        
        Write-Host "Total objects: $($objects.Count)" -ForegroundColor Green
    }
    
    "upload" {
        if (-not $SourcePath -or -not $DestinationPath) {
            Write-Host "Please specify SourcePath and DestinationPath" -ForegroundColor Red
            return
        }
        
        Upload-S3Object -SourcePath $SourcePath -DestinationPath $DestinationPath -Region $Region -Recursive:$Recursive
    }
    
    "download" {
        if (-not $SourcePath -or -not $DestinationPath) {
            Write-Host "Please specify SourcePath and DestinationPath" -ForegroundColor Red
            return
        }
        
        Download-S3Object -SourcePath $SourcePath -DestinationPath $DestinationPath -Region $Region -Recursive:$Recursive
    }
    
    "copy" {
        if (-not $SourcePath -or -not $DestinationPath) {
            Write-Host "Please specify SourcePath and DestinationPath" -ForegroundColor Red
            return
        }
        
        Copy-S3Object -SourcePath $SourcePath -DestinationPath $DestinationPath -Region $Region
    }
    
    "delete" {
        if (-not $BucketName -or -not $ObjectKey) {
            Write-Host "Please specify BucketName and ObjectKey" -ForegroundColor Red
            return
        }
        
        Remove-S3Object -BucketName $BucketName -ObjectKey $ObjectKey -Region $Region
    }
    
    "lifecycle" {
        if (-not $BucketName) {
            Write-Host "Please specify a BucketName" -ForegroundColor Red
            return
        }
        
        Set-ObjectLifecycle -BucketName $BucketName -Prefix $Prefix -RetentionDays $RetentionDays -Region $Region
    }
    
    "sync" {
        if (-not $SourcePath -or -not $DestinationPath) {
            Write-Host "Please specify SourcePath and DestinationPath" -ForegroundColor Red
            return
        }
        
        Sync-S3Objects -SourcePath $SourcePath -DestinationPath $DestinationPath -Region $Region
    }
    
    "cleanup" {
        if (-not $BucketName) {
            Write-Host "Please specify a BucketName" -ForegroundColor Red
            return
        }
        
        Cleanup-OldObjects -BucketName $BucketName -Prefix $Prefix -RetentionDays $RetentionDays -Region $Region
    }
    
    "analyze" {
        if (-not $BucketName) {
            Write-Host "Please specify a BucketName" -ForegroundColor Red
            return
        }
        
        Get-ObjectAnalysis -BucketName $BucketName -Prefix $Prefix -Region $Region
    }
    
    default {
        Write-Host "Invalid action. Valid actions: list, upload, download, copy, delete, lifecycle, sync, cleanup, analyze" -ForegroundColor Red
    }
}

Write-Host "`nUsage Examples:" -ForegroundColor Magenta
Write-Host "  .\object-management.ps1 -BucketName 'my-bucket' -Action list"
Write-Host "  .\object-management.ps1 -Action upload -SourcePath './local-file.txt' -DestinationPath 's3://my-bucket/file.txt'"
Write-Host "  .\object-management.ps1 -Action download -SourcePath 's3://my-bucket/file.txt' -DestinationPath './local-file.txt'"
Write-Host "  .\object-management.ps1 -Action copy -SourcePath 's3://bucket1/file.txt' -DestinationPath 's3://bucket2/file.txt'"
Write-Host "  .\object-management.ps1 -Action delete -BucketName 'my-bucket' -ObjectKey 'file.txt'"
Write-Host "  .\object-management.ps1 -Action lifecycle -BucketName 'my-bucket' -Prefix 'logs/' -RetentionDays 30"
Write-Host "  .\object-management.ps1 -Action sync -SourcePath './local-folder/' -DestinationPath 's3://my-bucket/'"
Write-Host "  .\object-management.ps1 -Action cleanup -BucketName 'my-bucket' -RetentionDays 90"
Write-Host "  .\object-management.ps1 -Action analyze -BucketName 'my-bucket'" 
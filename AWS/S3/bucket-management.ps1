# bucket-management.ps1
# Comprehensive S3 bucket management and configuration script

param(
    [string]$BucketName = "",
    [string]$Action = "list", # list, create, configure, lifecycle, security, sync, cleanup
    [string]$Region = "",
    [string]$Profile = "default",
    [string]$SourcePath = "",
    [string]$DestinationPath = "",
    [string]$LifecyclePolicy = "",
    [string]$EncryptionType = "AES256", # AES256, aws:kms
    [string]$KmsKeyId = "",
    [string]$Versioning = "Enabled", # Enabled, Suspended
    [string]$PublicAccess = "Private", # Private, PublicRead, PublicReadWrite
    [switch]$DryRun,
    [switch]$Force
)

function New-S3Bucket {
    param([string]$BucketName, [string]$Region)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    Write-Host "Creating S3 bucket: $BucketName" -ForegroundColor Yellow
    
    try {
        if (-not $DryRun) {
            $createParams = @(
                "--bucket $BucketName"
            )
            
            if ($Region -and $Region -ne "us-east-1") {
                $createParams += "--create-bucket-configuration LocationConstraint=$Region"
            }
            
            $createCmd = "aws s3api create-bucket $($createParams -join ' ') $regionParam --profile $Profile"
            Invoke-Expression $createCmd
            
            Write-Host "Bucket created successfully" -ForegroundColor Green
            return $true
        } else {
            Write-Host "[DRY RUN] Would create bucket: $BucketName" -ForegroundColor Cyan
            return $true
        }
    }
    catch {
        Write-Host "Failed to create bucket: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Set-BucketConfiguration {
    param([string]$BucketName, [string]$Versioning, [string]$EncryptionType, [string]$KmsKeyId)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    Write-Host "Configuring bucket: $BucketName" -ForegroundColor Yellow
    
    try {
        # Set versioning
        if (-not $DryRun) {
            aws s3api put-bucket-versioning --bucket $BucketName --versioning-configuration Status=$Versioning $regionParam --profile $Profile
            Write-Host "Versioning set to: $Versioning" -ForegroundColor Green
        } else {
            Write-Host "[DRY RUN] Would set versioning to: $Versioning" -ForegroundColor Cyan
        }
        
        # Set encryption
        if (-not $DryRun) {
            $encryptionConfig = @{
                Rules = @(
                    @{
                        ApplyServerSideEncryptionByDefault = @{
                            SSEAlgorithm = $EncryptionType
                        }
                    }
                )
            }
            
            if ($EncryptionType -eq "aws:kms" -and $KmsKeyId) {
                $encryptionConfig.Rules[0].ApplyServerSideEncryptionByDefault.KMSMasterKeyID = $KmsKeyId
            }
            
            $encryptionJson = $encryptionConfig | ConvertTo-Json -Depth 10
            $encryptionJson | aws s3api put-bucket-encryption --bucket $BucketName --server-side-encryption-configuration file:///dev/stdin $regionParam --profile $Profile
            
            Write-Host "Encryption set to: $EncryptionType" -ForegroundColor Green
        } else {
            Write-Host "[DRY RUN] Would set encryption to: $EncryptionType" -ForegroundColor Cyan
        }
        
        # Set public access block
        if (-not $DryRun) {
            $publicAccessConfig = @{
                BlockPublicAcls = $true
                IgnorePublicAcls = $true
                BlockPublicPolicy = $true
                RestrictPublicBuckets = $true
            }
            
            if ($PublicAccess -eq "PublicRead") {
                $publicAccessConfig.BlockPublicAcls = $false
                $publicAccessConfig.IgnorePublicAcls = $false
            } elseif ($PublicAccess -eq "PublicReadWrite") {
                $publicAccessConfig.BlockPublicAcls = $false
                $publicAccessConfig.IgnorePublicAcls = $false
                $publicAccessConfig.BlockPublicPolicy = $false
                $publicAccessConfig.RestrictPublicBuckets = $false
            }
            
            $publicAccessJson = $publicAccessConfig | ConvertTo-Json
            $publicAccessJson | aws s3api put-public-access-block --bucket $BucketName --public-access-block-configuration file:///dev/stdin $regionParam --profile $Profile
            
            Write-Host "Public access set to: $PublicAccess" -ForegroundColor Green
        } else {
            Write-Host "[DRY RUN] Would set public access to: $PublicAccess" -ForegroundColor Cyan
        }
        
        return $true
    }
    catch {
        Write-Host "Failed to configure bucket: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Set-BucketLifecycle {
    param([string]$BucketName, [string]$LifecyclePolicy)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    Write-Host "Setting lifecycle policy for bucket: $BucketName" -ForegroundColor Yellow
    
    try {
        if (-not $LifecyclePolicy) {
            # Default lifecycle policy
            $lifecycleConfig = @{
                Rules = @(
                    @{
                        ID = "TransitionToIA"
                        Status = "Enabled"
                        Filter = @{
                            Prefix = ""
                        }
                        Transitions = @(
                            @{
                                Days = 30
                                StorageClass = "STANDARD_IA"
                            }
                        )
                    },
                    @{
                        ID = "TransitionToGlacier"
                        Status = "Enabled"
                        Filter = @{
                            Prefix = ""
                        }
                        Transitions = @(
                            @{
                                Days = 90
                                StorageClass = "GLACIER"
                            }
                        )
                    },
                    @{
                        ID = "DeleteOldVersions"
                        Status = "Enabled"
                        Filter = @{
                            Prefix = ""
                        }
                        NoncurrentVersionTransitions = @(
                            @{
                                NoncurrentDays = 30
                                StorageClass = "STANDARD_IA"
                            }
                        )
                        NoncurrentVersionExpiration = @{
                            NoncurrentDays = 365
                        }
                    }
                )
            }
        } else {
            $lifecycleConfig = $LifecyclePolicy | ConvertFrom-Json
        }
        
        if (-not $DryRun) {
            $lifecycleJson = $lifecycleConfig | ConvertTo-Json -Depth 10
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

function Sync-S3Bucket {
    param([string]$SourcePath, [string]$DestinationPath, [string]$Direction = "upload")
    
    Write-Host "Syncing $Direction to/from S3..." -ForegroundColor Yellow
    
    try {
        if ($Direction -eq "upload") {
            $syncCmd = "aws s3 sync `"$SourcePath`" `"$DestinationPath`" --profile $Profile"
        } else {
            $syncCmd = "aws s3 sync `"$DestinationPath`" `"$SourcePath`" --profile $Profile"
        }
        
        if ($DryRun) {
            $syncCmd += " --dryrun"
        }
        
        Write-Host "Executing: $syncCmd" -ForegroundColor Gray
        Invoke-Expression $syncCmd
        
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

function Get-BucketSecurity {
    param([string]$BucketName)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    Write-Host "Analyzing security for bucket: $BucketName" -ForegroundColor Yellow
    
    try {
        # Get bucket encryption
        $encryption = aws s3api get-bucket-encryption --bucket $BucketName $regionParam --profile $Profile --output json 2>$null | ConvertFrom-Json
        
        # Get public access block
        $publicAccess = aws s3api get-public-access-block --bucket $BucketName $regionParam --profile $Profile --output json | ConvertFrom-Json
        
        # Get bucket policy
        $policy = aws s3api get-bucket-policy --bucket $BucketName $regionParam --profile $Profile --output json 2>$null | ConvertFrom-Json
        
        # Get bucket ACL
        $acl = aws s3api get-bucket-acl --bucket $BucketName $regionParam --profile $Profile --output json | ConvertFrom-Json
        
        Write-Host "`nSecurity Analysis:" -ForegroundColor Cyan
        
        # Encryption status
        if ($encryption.ServerSideEncryptionConfiguration) {
            $algorithm = $encryption.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm
            Write-Host "Encryption: $algorithm" -ForegroundColor Green
        } else {
            Write-Host "Encryption: None" -ForegroundColor Red
        }
        
        # Public access status
        $publicAccessBlock = $publicAccess.PublicAccessBlockConfiguration
        $isPublic = -not ($publicAccessBlock.BlockPublicAcls -and $publicAccessBlock.IgnorePublicAcls -and $publicAccessBlock.BlockPublicPolicy -and $publicAccessBlock.RestrictPublicBuckets)
        
        Write-Host "Public Access: $(if($isPublic) { 'Enabled' } else { 'Blocked' })" -ForegroundColor $(if($isPublic) { "Red" } else { "Green" })
        
        # Bucket policy
        if ($policy.Policy) {
            Write-Host "Bucket Policy: Present" -ForegroundColor Green
        } else {
            Write-Host "Bucket Policy: None" -ForegroundColor Yellow
        }
        
        # ACL analysis
        $publicGrants = $acl.Grants | Where-Object { $_.Grantee.URI -eq "http://acs.amazonaws.com/groups/global/AllUsers" }
        if ($publicGrants) {
            Write-Host "Public ACL Grants: Found" -ForegroundColor Red
        } else {
            Write-Host "Public ACL Grants: None" -ForegroundColor Green
        }
        
        # Security recommendations
        Write-Host "`nSecurity Recommendations:" -ForegroundColor Yellow
        if (-not $encryption.ServerSideEncryptionConfiguration) {
            Write-Host "  - Enable server-side encryption" -ForegroundColor Red
        }
        if ($isPublic) {
            Write-Host "  - Block public access" -ForegroundColor Red
        }
        if ($publicGrants) {
            Write-Host "  - Remove public ACL grants" -ForegroundColor Red
        }
        if (-not $policy.Policy) {
            Write-Host "  - Consider adding a bucket policy" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "Unable to analyze bucket security: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Remove-BucketContents {
    param([string]$BucketName, [int]$DaysOld = 0)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    Write-Host "Cleaning up bucket contents..." -ForegroundColor Yellow
    
    try {
        if ($DaysOld -gt 0) {
            $cutoffDate = (Get-Date).AddDays(-$DaysOld)
            Write-Host "Removing objects older than $DaysOld days..." -ForegroundColor Yellow
            
            $objects = aws s3api list-objects-v2 --bucket $BucketName $regionParam --profile $Profile --output json | ConvertFrom-Json
            
            foreach ($object in $objects.Contents) {
                $objectDate = [DateTime]::Parse($object.LastModified)
                if ($objectDate -lt $cutoffDate) {
                    Write-Host "Removing: $($object.Key) (last modified: $($object.LastModified))" -ForegroundColor Yellow
                    
                    if (-not $DryRun) {
                        aws s3api delete-object --bucket $BucketName --key $object.Key $regionParam --profile $Profile
                    } else {
                        Write-Host "  [DRY RUN] Would remove" -ForegroundColor Cyan
                    }
                }
            }
        } else {
            Write-Host "Removing all objects..." -ForegroundColor Yellow
            
            if (-not $DryRun) {
                aws s3 rm "s3://$BucketName" --recursive --profile $Profile
            } else {
                Write-Host "[DRY RUN] Would remove all objects" -ForegroundColor Cyan
            }
        }
        
        Write-Host "Cleanup completed" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to cleanup bucket: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "AWS S3 Bucket Management" -ForegroundColor Green
Write-Host "=======================" -ForegroundColor Green

switch ($Action.ToLower()) {
    "list" {
        $buckets = aws s3api list-buckets --profile $Profile --output json | ConvertFrom-Json
        
        if ($buckets.Buckets) {
            Write-Host "`nS3 Buckets:" -ForegroundColor Yellow
            Write-Host ("=" * 80) -ForegroundColor DarkGray
            
            foreach ($bucket in $buckets.Buckets) {
                Write-Host "Bucket: " -NoNewline -ForegroundColor White
                Write-Host $bucket.Name -ForegroundColor Cyan
                Write-Host "Created: " -NoNewline -ForegroundColor White
                Write-Host $bucket.CreationDate -ForegroundColor Gray
                
                # Get bucket location
                try {
                    $location = aws s3api get-bucket-location --bucket $bucket.Name --profile $Profile --output json | ConvertFrom-Json
                    Write-Host "Region: " -NoNewline -ForegroundColor White
                    Write-Host $location.LocationConstraint -ForegroundColor Gray
                }
                catch {
                    Write-Host "Region: us-east-1" -ForegroundColor Gray
                }
                
                Write-Host ""
            }
            
            Write-Host "Total buckets: $($buckets.Buckets.Count)" -ForegroundColor Green
        } else {
            Write-Host "No S3 buckets found." -ForegroundColor Yellow
        }
    }
    
    "create" {
        if (-not $BucketName) {
            Write-Host "Please specify a BucketName to create" -ForegroundColor Red
            return
        }
        
        $success = New-S3Bucket -BucketName $BucketName -Region $Region
        if ($success) {
            Set-BucketConfiguration -BucketName $BucketName -Versioning $Versioning -EncryptionType $EncryptionType -KmsKeyId $KmsKeyId
        }
    }
    
    "configure" {
        if (-not $BucketName) {
            Write-Host "Please specify a BucketName to configure" -ForegroundColor Red
            return
        }
        
        Set-BucketConfiguration -BucketName $BucketName -Versioning $Versioning -EncryptionType $EncryptionType -KmsKeyId $KmsKeyId
    }
    
    "lifecycle" {
        if (-not $BucketName) {
            Write-Host "Please specify a BucketName to set lifecycle policy" -ForegroundColor Red
            return
        }
        
        Set-BucketLifecycle -BucketName $BucketName -LifecyclePolicy $LifecyclePolicy
    }
    
    "security" {
        if (-not $BucketName) {
            Write-Host "Please specify a BucketName to analyze security" -ForegroundColor Red
            return
        }
        
        Get-BucketSecurity -BucketName $BucketName
    }
    
    "sync" {
        if (-not $SourcePath -or -not $DestinationPath) {
            Write-Host "Please specify both SourcePath and DestinationPath" -ForegroundColor Red
            return
        }
        
        $direction = if ($DestinationPath -like "s3://*") { "upload" } else { "download" }
        Sync-S3Bucket -SourcePath $SourcePath -DestinationPath $DestinationPath -Direction $direction
    }
    
    "cleanup" {
        if (-not $BucketName) {
            Write-Host "Please specify a BucketName to cleanup" -ForegroundColor Red
            return
        }
        
        Remove-BucketContents -BucketName $BucketName -DaysOld 30
    }
    
    default {
        Write-Host "Invalid action. Valid actions: list, create, configure, lifecycle, security, sync, cleanup" -ForegroundColor Red
    }
}

Write-Host "`nUsage Examples:" -ForegroundColor Magenta
Write-Host "  .\bucket-management.ps1 -Action list"
Write-Host "  .\bucket-management.ps1 -Action create -BucketName 'my-bucket' -Region 'us-west-2'"
Write-Host "  .\bucket-management.ps1 -Action configure -BucketName 'my-bucket' -Versioning 'Enabled' -EncryptionType 'AES256'"
Write-Host "  .\bucket-management.ps1 -Action lifecycle -BucketName 'my-bucket'"
Write-Host "  .\bucket-management.ps1 -Action security -BucketName 'my-bucket'"
Write-Host "  .\bucket-management.ps1 -Action sync -SourcePath './local-folder' -DestinationPath 's3://my-bucket/'"
Write-Host "  .\bucket-management.ps1 -Action cleanup -BucketName 'my-bucket'" 
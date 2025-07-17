# security-audit.ps1
# Comprehensive S3 security audit and compliance checking script

param(
    [string]$BucketName = "",
    [string]$Action = "audit", # audit, scan, report, fix, compliance
    [string]$Region = "",
    [string]$Profile = "default",
    [string]$ReportPath = "",
    [switch]$Detailed,
    [switch]$AutoFix,
    [switch]$Export
)

function Get-BucketSecurityStatus {
    param([string]$BucketName)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    try {
        $securityStatus = @{
            BucketName = $BucketName
            Encryption = $null
            PublicAccess = $null
            BucketPolicy = $null
            ACL = $null
            Versioning = $null
            Logging = $null
            Lifecycle = $null
            Issues = @()
            Recommendations = @()
            Score = 100
        }
        
        # Check encryption
        try {
            $encryption = aws s3api get-bucket-encryption --bucket $BucketName $regionParam --profile $Profile --output json 2>$null | ConvertFrom-Json
            if ($encryption.ServerSideEncryptionConfiguration) {
                $securityStatus.Encryption = $encryption.ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm
            } else {
                $securityStatus.Encryption = "None"
                $securityStatus.Issues += "No server-side encryption configured"
                $securityStatus.Score -= 20
            }
        }
        catch {
            $securityStatus.Encryption = "None"
            $securityStatus.Issues += "No server-side encryption configured"
            $securityStatus.Score -= 20
        }
        
        # Check public access block
        try {
            $publicAccess = aws s3api get-public-access-block --bucket $BucketName $regionParam --profile $Profile --output json | ConvertFrom-Json
            $config = $publicAccess.PublicAccessBlockConfiguration
            $securityStatus.PublicAccess = @{
                BlockPublicAcls = $config.BlockPublicAcls
                IgnorePublicAcls = $config.IgnorePublicAcls
                BlockPublicPolicy = $config.BlockPublicPolicy
                RestrictPublicBuckets = $config.RestrictPublicBuckets
            }
            
            if (-not ($config.BlockPublicAcls -and $config.IgnorePublicAcls -and $config.BlockPublicPolicy -and $config.RestrictPublicBuckets)) {
                $securityStatus.Issues += "Public access not fully blocked"
                $securityStatus.Score -= 15
            }
        }
        catch {
            $securityStatus.Issues += "Unable to check public access block"
            $securityStatus.Score -= 10
        }
        
        # Check bucket policy
        try {
            $policy = aws s3api get-bucket-policy --bucket $BucketName $regionParam --profile $Profile --output json 2>$null | ConvertFrom-Json
            $securityStatus.BucketPolicy = "Present"
        }
        catch {
            $securityStatus.BucketPolicy = "None"
            $securityStatus.Issues += "No bucket policy configured"
            $securityStatus.Score -= 5
        }
        
        # Check ACL
        try {
            $acl = aws s3api get-bucket-acl --bucket $BucketName $regionParam --profile $Profile --output json | ConvertFrom-Json
            $publicGrants = $acl.Grants | Where-Object { $_.Grantee.URI -eq "http://acs.amazonaws.com/groups/global/AllUsers" }
            if ($publicGrants) {
                $securityStatus.ACL = "Public"
                $securityStatus.Issues += "Public ACL grants found"
                $securityStatus.Score -= 25
            } else {
                $securityStatus.ACL = "Private"
            }
        }
        catch {
            $securityStatus.ACL = "Unknown"
            $securityStatus.Score -= 5
        }
        
        # Check versioning
        try {
            $versioning = aws s3api get-bucket-versioning --bucket $BucketName $regionParam --profile $Profile --output json | ConvertFrom-Json
            $securityStatus.Versioning = $versioning.Status
            if ($versioning.Status -ne "Enabled") {
                $securityStatus.Issues += "Versioning not enabled"
                $securityStatus.Score -= 10
            }
        }
        catch {
            $securityStatus.Versioning = "Unknown"
            $securityStatus.Score -= 5
        }
        
        # Check logging
        try {
            $logging = aws s3api get-bucket-logging --bucket $BucketName $regionParam --profile $Profile --output json | ConvertFrom-Json
            if ($logging.LoggingEnabled) {
                $securityStatus.Logging = "Enabled"
            } else {
                $securityStatus.Logging = "Disabled"
                $securityStatus.Issues += "Access logging not enabled"
                $securityStatus.Score -= 10
            }
        }
        catch {
            $securityStatus.Logging = "Disabled"
            $securityStatus.Issues += "Access logging not enabled"
            $securityStatus.Score -= 10
        }
        
        # Check lifecycle
        try {
            $lifecycle = aws s3api get-bucket-lifecycle-configuration --bucket $BucketName $regionParam --profile $Profile --output json 2>$null | ConvertFrom-Json
            $securityStatus.Lifecycle = "Configured"
        }
        catch {
            $securityStatus.Lifecycle = "None"
            $securityStatus.Issues += "No lifecycle policy configured"
            $securityStatus.Score -= 5
        }
        
        # Generate recommendations
        if ($securityStatus.Encryption -eq "None") {
            $securityStatus.Recommendations += "Enable server-side encryption"
        }
        if ($securityStatus.PublicAccess -and -not ($securityStatus.PublicAccess.BlockPublicAcls -and $securityStatus.PublicAccess.IgnorePublicAcls -and $securityStatus.PublicAccess.BlockPublicPolicy -and $securityStatus.PublicAccess.RestrictPublicBuckets)) {
            $securityStatus.Recommendations += "Block all public access"
        }
        if ($securityStatus.ACL -eq "Public") {
            $securityStatus.Recommendations += "Remove public ACL grants"
        }
        if ($securityStatus.Versioning -ne "Enabled") {
            $securityStatus.Recommendations += "Enable versioning"
        }
        if ($securityStatus.Logging -eq "Disabled") {
            $securityStatus.Recommendations += "Enable access logging"
        }
        if ($securityStatus.Lifecycle -eq "None") {
            $securityStatus.Recommendations += "Configure lifecycle policy"
        }
        
        return $securityStatus
    }
    catch {
        Write-Host "Unable to get security status for bucket $BucketName" -ForegroundColor Red
        return $null
    }
}

function Scan-BucketForSensitiveData {
    param([string]$BucketName)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    Write-Host "Scanning bucket for sensitive data..." -ForegroundColor Yellow
    
    try {
        $objects = aws s3api list-objects-v2 --bucket $BucketName $regionParam --profile $Profile --output json | ConvertFrom-Json
        
        $sensitivePatterns = @(
            @{ Pattern = "password|secret|key|token|credential"; Type = "Credentials" },
            @{ Pattern = "\.pem$|\.key$|\.crt$|\.p12$"; Type = "Certificates" },
            @{ Pattern = "\.sql$|\.db$|\.sqlite$"; Type = "Database Files" },
            @{ Pattern = "\.log$|\.txt$"; Type = "Log Files" },
            @{ Pattern = "backup|dump|export"; Type = "Backup Files" }
        )
        
        $sensitiveObjects = @()
        
        foreach ($object in $objects.Contents) {
            foreach ($pattern in $sensitivePatterns) {
                if ($object.Key -match $pattern.Pattern -or $object.Key -match $pattern.Pattern.ToUpper()) {
                    $sensitiveObjects += [PSCustomObject]@{
                        Key = $object.Key
                        Size = $object.Size
                        LastModified = $object.LastModified
                        Type = $pattern.Type
                    }
                    break
                }
            }
        }
        
        if ($sensitiveObjects.Count -gt 0) {
            Write-Host "`nSensitive objects found:" -ForegroundColor Red
            foreach ($obj in $sensitiveObjects) {
                Write-Host "  $($obj.Key) ($($obj.Type))" -ForegroundColor Red
                Write-Host "    Size: $($obj.Size) bytes, Modified: $($obj.LastModified)" -ForegroundColor Gray
            }
        } else {
            Write-Host "No sensitive objects detected" -ForegroundColor Green
        }
        
        return $sensitiveObjects
    }
    catch {
        Write-Host "Unable to scan bucket for sensitive data" -ForegroundColor Red
        return @()
    }
}

function Test-BucketCompliance {
    param([string]$BucketName)
    
    $securityStatus = Get-BucketSecurityStatus -BucketName $BucketName
    if (-not $securityStatus) { return }
    
    $compliance = @{
        HIPAA = $true
        SOX = $true
        PCI = $true
        GDPR = $true
        Issues = @()
    }
    
    # HIPAA Compliance
    if ($securityStatus.Encryption -eq "None") {
        $compliance.HIPAA = $false
        $compliance.Issues += "HIPAA: Encryption required"
    }
    if ($securityStatus.ACL -eq "Public") {
        $compliance.HIPAA = $false
        $compliance.Issues += "HIPAA: Public access not allowed"
    }
    
    # SOX Compliance
    if ($securityStatus.Logging -eq "Disabled") {
        $compliance.SOX = $false
        $compliance.Issues += "SOX: Access logging required"
    }
    if ($securityStatus.Versioning -ne "Enabled") {
        $compliance.SOX = $false
        $compliance.Issues += "SOX: Versioning required"
    }
    
    # PCI Compliance
    if ($securityStatus.Encryption -eq "None") {
        $compliance.PCI = $false
        $compliance.Issues += "PCI: Encryption required"
    }
    if ($securityStatus.PublicAccess -and -not ($securityStatus.PublicAccess.BlockPublicAcls -and $securityStatus.PublicAccess.IgnorePublicAcls -and $securityStatus.PublicAccess.BlockPublicPolicy -and $securityStatus.PublicAccess.RestrictPublicBuckets)) {
        $compliance.PCI = $false
        $compliance.Issues += "PCI: Public access must be blocked"
    }
    
    # GDPR Compliance
    if ($securityStatus.Lifecycle -eq "None") {
        $compliance.GDPR = $false
        $compliance.Issues += "GDPR: Data retention policy required"
    }
    
    return $compliance
}

function Fix-SecurityIssues {
    param([string]$BucketName, [object]$SecurityStatus)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    Write-Host "Fixing security issues for bucket: $BucketName" -ForegroundColor Yellow
    
    try {
        # Fix encryption
        if ($SecurityStatus.Encryption -eq "None") {
            Write-Host "Enabling server-side encryption..." -ForegroundColor Yellow
            $encryptionConfig = @{
                Rules = @(
                    @{
                        ApplyServerSideEncryptionByDefault = @{
                            SSEAlgorithm = "AES256"
                        }
                    }
                )
            }
            $encryptionJson = $encryptionConfig | ConvertTo-Json -Depth 10
            $encryptionJson | aws s3api put-bucket-encryption --bucket $BucketName --server-side-encryption-configuration file:///dev/stdin $regionParam --profile $Profile
            Write-Host "Encryption enabled" -ForegroundColor Green
        }
        
        # Fix public access
        if ($SecurityStatus.PublicAccess) {
            $config = $SecurityStatus.PublicAccess
            if (-not ($config.BlockPublicAcls -and $config.IgnorePublicAcls -and $config.BlockPublicPolicy -and $config.RestrictPublicBuckets)) {
                Write-Host "Blocking public access..." -ForegroundColor Yellow
                $publicAccessConfig = @{
                    BlockPublicAcls = $true
                    IgnorePublicAcls = $true
                    BlockPublicPolicy = $true
                    RestrictPublicBuckets = $true
                }
                $publicAccessJson = $publicAccessConfig | ConvertTo-Json
                $publicAccessJson | aws s3api put-public-access-block --bucket $BucketName --public-access-block-configuration file:///dev/stdin $regionParam --profile $Profile
                Write-Host "Public access blocked" -ForegroundColor Green
            }
        }
        
        # Fix versioning
        if ($SecurityStatus.Versioning -ne "Enabled") {
            Write-Host "Enabling versioning..." -ForegroundColor Yellow
            aws s3api put-bucket-versioning --bucket $BucketName --versioning-configuration Status=Enabled $regionParam --profile $Profile
            Write-Host "Versioning enabled" -ForegroundColor Green
        }
        
        # Fix logging
        if ($SecurityStatus.Logging -eq "Disabled") {
            Write-Host "Enabling access logging..." -ForegroundColor Yellow
            $loggingConfig = @{
                LoggingEnabled = @{
                    TargetBucket = "$BucketName-logs"
                    TargetPrefix = "logs/"
                }
            }
            $loggingJson = $loggingConfig | ConvertTo-Json -Depth 10
            $loggingJson | aws s3api put-bucket-logging --bucket $BucketName --bucket-logging-status file:///dev/stdin $regionParam --profile $Profile
            Write-Host "Access logging enabled" -ForegroundColor Green
        }
        
        Write-Host "Security fixes completed" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to fix security issues: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Export-SecurityReport {
    param([string]$BucketName, [object]$SecurityStatus, [object]$Compliance, [array]$SensitiveObjects)
    
    $report = @{
        Timestamp = Get-Date
        BucketName = $BucketName
        SecurityStatus = $SecurityStatus
        Compliance = $Compliance
        SensitiveObjects = $SensitiveObjects
    }
    
    $reportFile = if ($ReportPath) { $ReportPath } else { "s3-security-report-$BucketName-$(Get-Date -Format 'yyyyMMdd-HHmmss').json" }
    
    $report | ConvertTo-Json -Depth 10 | Out-File $reportFile
    Write-Host "Security report exported to: $reportFile" -ForegroundColor Green
    
    return $reportFile
}

Write-Host "AWS S3 Security Audit" -ForegroundColor Green
Write-Host "=====================" -ForegroundColor Green

if (-not $BucketName) {
    Write-Host "Please specify a BucketName to audit" -ForegroundColor Red
    return
}

switch ($Action.ToLower()) {
    "audit" {
        Write-Host "`nAuditing bucket: $BucketName" -ForegroundColor Yellow
        
        $securityStatus = Get-BucketSecurityStatus -BucketName $BucketName
        if (-not $securityStatus) { return }
        
        Write-Host "`nSecurity Status:" -ForegroundColor Cyan
        Write-Host "Encryption: $($securityStatus.Encryption)" -ForegroundColor $(if($securityStatus.Encryption -ne "None") { "Green" } else { "Red" })
        Write-Host "Versioning: $($securityStatus.Versioning)" -ForegroundColor $(if($securityStatus.Versioning -eq "Enabled") { "Green" } else { "Red" })
        Write-Host "Logging: $($securityStatus.Logging)" -ForegroundColor $(if($securityStatus.Logging -eq "Enabled") { "Green" } else { "Red" })
        Write-Host "ACL: $($securityStatus.ACL)" -ForegroundColor $(if($securityStatus.ACL -eq "Private") { "Green" } else { "Red" })
        Write-Host "Lifecycle: $($securityStatus.Lifecycle)" -ForegroundColor $(if($securityStatus.Lifecycle -eq "Configured") { "Green" } else { "Yellow" })
        
        Write-Host "`nSecurity Score: $($securityStatus.Score)/100" -ForegroundColor $(if($securityStatus.Score -ge 80) { "Green" } elseif($securityStatus.Score -ge 60) { "Yellow" } else { "Red" })
        
        if ($securityStatus.Issues.Count -gt 0) {
            Write-Host "`nIssues Found:" -ForegroundColor Red
            foreach ($issue in $securityStatus.Issues) {
                Write-Host "  - $issue" -ForegroundColor Red
            }
        }
        
        if ($securityStatus.Recommendations.Count -gt 0) {
            Write-Host "`nRecommendations:" -ForegroundColor Yellow
            foreach ($rec in $securityStatus.Recommendations) {
                Write-Host "  - $rec" -ForegroundColor Yellow
            }
        }
    }
    
    "scan" {
        $sensitiveObjects = Scan-BucketForSensitiveData -BucketName $BucketName
    }
    
    "compliance" {
        $securityStatus = Get-BucketSecurityStatus -BucketName $BucketName
        $compliance = Test-BucketCompliance -BucketName $BucketName
        
        Write-Host "`nCompliance Status:" -ForegroundColor Cyan
        Write-Host "HIPAA: $($compliance.HIPAA)" -ForegroundColor $(if($compliance.HIPAA) { "Green" } else { "Red" })
        Write-Host "SOX: $($compliance.SOX)" -ForegroundColor $(if($compliance.SOX) { "Green" } else { "Red" })
        Write-Host "PCI: $($compliance.PCI)" -ForegroundColor $(if($compliance.PCI) { "Green" } else { "Red" })
        Write-Host "GDPR: $($compliance.GDPR)" -ForegroundColor $(if($compliance.GDPR) { "Green" } else { "Red" })
        
        if ($compliance.Issues.Count -gt 0) {
            Write-Host "`nCompliance Issues:" -ForegroundColor Red
            foreach ($issue in $compliance.Issues) {
                Write-Host "  - $issue" -ForegroundColor Red
            }
        }
    }
    
    "fix" {
        $securityStatus = Get-BucketSecurityStatus -BucketName $BucketName
        if ($securityStatus) {
            Fix-SecurityIssues -BucketName $BucketName -SecurityStatus $securityStatus
        }
    }
    
    "report" {
        $securityStatus = Get-BucketSecurityStatus -BucketName $BucketName
        $compliance = Test-BucketCompliance -BucketName $BucketName
        $sensitiveObjects = Scan-BucketForSensitiveData -BucketName $BucketName
        
        $reportFile = Export-SecurityReport -BucketName $BucketName -SecurityStatus $securityStatus -Compliance $compliance -SensitiveObjects $sensitiveObjects
        
        if ($Export) {
            Write-Host "`nDetailed report exported to: $reportFile" -ForegroundColor Green
        }
    }
    
    default {
        Write-Host "Invalid action. Valid actions: audit, scan, compliance, fix, report" -ForegroundColor Red
    }
}

Write-Host "`nUsage Examples:" -ForegroundColor Magenta
Write-Host "  .\security-audit.ps1 -BucketName 'my-bucket' -Action audit"
Write-Host "  .\security-audit.ps1 -BucketName 'my-bucket' -Action scan"
Write-Host "  .\security-audit.ps1 -BucketName 'my-bucket' -Action compliance"
Write-Host "  .\security-audit.ps1 -BucketName 'my-bucket' -Action fix -AutoFix"
Write-Host "  .\security-audit.ps1 -BucketName 'my-bucket' -Action report -Export" 
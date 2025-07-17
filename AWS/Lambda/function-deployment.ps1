# function-deployment.ps1
# Comprehensive Lambda function deployment and management script

param(
    [string]$FunctionName = "",
    [string]$Action = "deploy", # deploy, update, rollback, monitor, test, cleanup
    [string]$Runtime = "nodejs18.x",
    [string]$Handler = "index.handler",
    [string]$RoleArn = "",
    [string]$Region = "",
    [string]$Profile = "default",
    [string]$SourcePath = "",
    [string]$ZipFile = "",
    [string]$Environment = "",
    [int]$Timeout = 30,
    [int]$MemorySize = 128,
    [string]$Version = "",
    [switch]$DryRun,
    [switch]$Force
)

function New-LambdaPackage {
    param([string]$SourcePath, [string]$Runtime)
    
    Write-Host "Creating Lambda deployment package..." -ForegroundColor Yellow
    
    $tempDir = "lambda-package-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    $zipFile = "$FunctionName-$(Get-Date -Format 'yyyyMMdd-HHmmss').zip"
    
    try {
        # Create temporary directory
        New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
        
        # Copy source files
        if (Test-Path $SourcePath) {
            Copy-Item -Path "$SourcePath\*" -Destination $tempDir -Recurse -Force
        } else {
            Write-Host "Source path not found: $SourcePath" -ForegroundColor Red
            return $null
        }
        
        # Install dependencies for Node.js
        if ($Runtime -like "nodejs*") {
            if (Test-Path "$SourcePath\package.json") {
                Write-Host "Installing Node.js dependencies..." -ForegroundColor Yellow
                Set-Location $tempDir
                npm install --production
                Set-Location ..
            }
        }
        
        # Install dependencies for Python
        if ($Runtime -like "python*") {
            if (Test-Path "$SourcePath\requirements.txt") {
                Write-Host "Installing Python dependencies..." -ForegroundColor Yellow
                pip install -r "$SourcePath\requirements.txt" -t $tempDir
            }
        }
        
        # Create ZIP file
        Write-Host "Creating ZIP package..." -ForegroundColor Yellow
        Compress-Archive -Path "$tempDir\*" -DestinationPath $zipFile -Force
        
        # Cleanup temp directory
        Remove-Item -Path $tempDir -Recurse -Force
        
        Write-Host "Package created: $zipFile" -ForegroundColor Green
        return $zipFile
    }
    catch {
        Write-Host "Failed to create package: $($_.Exception.Message)" -ForegroundColor Red
        if (Test-Path $tempDir) {
            Remove-Item -Path $tempDir -Recurse -Force
        }
        return $null
    }
}

function Deploy-LambdaFunction {
    param([string]$FunctionName, [string]$ZipFile, [string]$Runtime, [string]$Handler, [string]$RoleArn)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    Write-Host "Deploying Lambda function: $FunctionName" -ForegroundColor Yellow
    
    try {
        # Check if function exists
        $existingFunction = $null
        try {
            $existingFunction = aws lambda get-function --function-name $FunctionName $regionParam --profile $Profile --output json | ConvertFrom-Json
        }
        catch {
            # Function doesn't exist, will create new
        }
        
        if ($existingFunction) {
            Write-Host "Updating existing function..." -ForegroundColor Yellow
            
            if (-not $DryRun) {
                # Update function code
                aws lambda update-function-code --function-name $FunctionName --zip-file "fileb://$ZipFile" $regionParam --profile $Profile
                
                # Update function configuration
                $configParams = @(
                    "--function-name $FunctionName",
                    "--timeout $Timeout",
                    "--memory-size $MemorySize"
                )
                
                if ($Environment) {
                    $configParams += "--environment Variables={$Environment}"
                }
                
                $configCmd = "aws lambda update-function-configuration $($configParams -join ' ') $regionParam --profile $Profile"
                Invoke-Expression $configCmd
                
                Write-Host "Function updated successfully" -ForegroundColor Green
            } else {
                Write-Host "[DRY RUN] Would update function: $FunctionName" -ForegroundColor Cyan
            }
        } else {
            Write-Host "Creating new function..." -ForegroundColor Yellow
            
            if (-not $RoleArn) {
                Write-Host "Please specify a RoleArn for the new function" -ForegroundColor Red
                return $false
            }
            
            if (-not $DryRun) {
                $createParams = @(
                    "--function-name $FunctionName",
                    "--runtime $Runtime",
                    "--handler $Handler",
                    "--role $RoleArn",
                    "--timeout $Timeout",
                    "--memory-size $MemorySize",
                    "--zip-file fileb://$ZipFile"
                )
                
                if ($Environment) {
                    $createParams += "--environment Variables={$Environment}"
                }
                
                $createCmd = "aws lambda create-function $($createParams -join ' ') $regionParam --profile $Profile --output json"
                $result = Invoke-Expression $createCmd | ConvertFrom-Json
                
                Write-Host "Function created successfully: $($result.FunctionArn)" -ForegroundColor Green
            } else {
                Write-Host "[DRY RUN] Would create function: $FunctionName" -ForegroundColor Cyan
            }
        }
        
        return $true
    }
    catch {
        Write-Host "Failed to deploy function: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Get-FunctionVersions {
    param([string]$FunctionName)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    try {
        $versions = aws lambda list-versions-by-function --function-name $FunctionName $regionParam --profile $Profile --output json | ConvertFrom-Json
        return $versions.Versions
    }
    catch {
        Write-Host "Unable to get function versions" -ForegroundColor Red
        return @()
    }
}

function Rollback-FunctionVersion {
    param([string]$FunctionName, [string]$Version)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    Write-Host "Rolling back function $FunctionName to version $Version" -ForegroundColor Yellow
    
    try {
        if (-not $DryRun) {
            aws lambda update-function-code --function-name $FunctionName --s3-bucket dummy --s3-key dummy $regionParam --profile $Profile
            aws lambda update-function-code --function-name $FunctionName --revision-id $Version $regionParam --profile $Profile
            
            Write-Host "Function rolled back successfully" -ForegroundColor Green
        } else {
            Write-Host "[DRY RUN] Would rollback function to version: $Version" -ForegroundColor Cyan
        }
    }
    catch {
        Write-Host "Failed to rollback function: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Test-LambdaFunction {
    param([string]$FunctionName, [string]$Payload)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    if (-not $Payload) {
        $Payload = '{"test": "data"}'
    }
    
    Write-Host "Testing function: $FunctionName" -ForegroundColor Yellow
    Write-Host "Payload: $Payload" -ForegroundColor Gray
    
    try {
        $result = aws lambda invoke --function-name $FunctionName --payload $Payload $regionParam --profile $Profile response.json --output json | ConvertFrom-Json
        
        if (Test-Path "response.json") {
            $response = Get-Content "response.json" -Raw
            Write-Host "`nFunction Response:" -ForegroundColor Cyan
            Write-Host $response -ForegroundColor White
            Remove-Item "response.json" -Force
        }
        
        Write-Host "`nExecution Details:" -ForegroundColor Cyan
        Write-Host "Status Code: $($result.StatusCode)" -ForegroundColor $(if($result.StatusCode -eq 200) { "Green" } else { "Red" })
        
        if ($result.LogResult) {
            $logs = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($result.LogResult))
            Write-Host "Logs: $logs" -ForegroundColor Gray
        }
        
        if ($result.FunctionError) {
            Write-Host "Function Error: $($result.FunctionError)" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "Failed to test function: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Monitor-FunctionMetrics {
    param([string]$FunctionName, [int]$Days = 7)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    $endTime = Get-Date
    $startTime = $endTime.AddDays(-$Days)
    
    Write-Host "Monitoring function metrics for the last $Days days..." -ForegroundColor Yellow
    
    try {
        # Invocations
        $invocations = aws cloudwatch get-metric-statistics --namespace AWS/Lambda --metric-name Invocations --dimensions Name=FunctionName,Value=$FunctionName --start-time $startTime.ToString("yyyy-MM-ddTHH:mm:ss") --end-time $endTime.ToString("yyyy-MM-ddTHH:mm:ss") --period 3600 --statistics Sum $regionParam --profile $Profile --output json | ConvertFrom-Json
        
        # Duration
        $duration = aws cloudwatch get-metric-statistics --namespace AWS/Lambda --metric-name Duration --dimensions Name=FunctionName,Value=$FunctionName --start-time $startTime.ToString("yyyy-MM-ddTHH:mm:ss") --end-time $endTime.ToString("yyyy-MM-ddTHH:mm:ss") --period 3600 --statistics Average $regionParam --profile $Profile --output json | ConvertFrom-Json
        
        # Errors
        $errors = aws cloudwatch get-metric-statistics --namespace AWS/Lambda --metric-name Errors --dimensions Name=FunctionName,Value=$FunctionName --start-time $startTime.ToString("yyyy-MM-ddTHH:mm:ss") --end-time $endTime.ToString("yyyy-MM-ddTHH:mm:ss") --period 3600 --statistics Sum $regionParam --profile $Profile --output json | ConvertFrom-Json
        
        Write-Host "`nFunction Metrics:" -ForegroundColor Cyan
        
        if ($invocations.Datapoints.Count -gt 0) {
            $totalInvocations = ($invocations.Datapoints | Measure-Object -Property Sum -Sum).Sum
            Write-Host "Total Invocations: $totalInvocations" -ForegroundColor Green
        }
        
        if ($duration.Datapoints.Count -gt 0) {
            $avgDuration = ($duration.Datapoints | Measure-Object -Property Average -Average).Average
            Write-Host "Average Duration: $([math]::Round($avgDuration, 2)) ms" -ForegroundColor Green
        }
        
        if ($errors.Datapoints.Count -gt 0) {
            $totalErrors = ($errors.Datapoints | Measure-Object -Property Sum -Sum).Sum
            Write-Host "Total Errors: $totalErrors" -ForegroundColor $(if($totalErrors -eq 0) { "Green" } else { "Red" })
        }
        
        # Calculate error rate
        if ($totalInvocations -gt 0 -and $totalErrors -gt 0) {
            $errorRate = [math]::Round(($totalErrors / $totalInvocations) * 100, 2)
            Write-Host "Error Rate: $errorRate%" -ForegroundColor $(if($errorRate -lt 5) { "Green" } elseif($errorRate -lt 10) { "Yellow" } else { "Red" })
        }
    }
    catch {
        Write-Host "Unable to get function metrics" -ForegroundColor Red
    }
}

function Remove-OldVersions {
    param([string]$FunctionName, [int]$KeepVersions = 5)
    
    $regionParam = if ($Region) { "--region $Region" } else { "" }
    
    Write-Host "Cleaning up old function versions (keeping $KeepVersions)..." -ForegroundColor Yellow
    
    try {
        $versions = Get-FunctionVersions -FunctionName $FunctionName
        $oldVersions = $versions | Where-Object { $_.Version -ne '$LATEST' } | Sort-Object -Property LastModified -Descending | Select-Object -Skip $KeepVersions
        
        foreach ($version in $oldVersions) {
            Write-Host "Removing version: $($version.Version)" -ForegroundColor Yellow
            
            if (-not $DryRun) {
                aws lambda delete-function --function-name $FunctionName --qualifier $version.Version $regionParam --profile $Profile
                Write-Host "  Removed" -ForegroundColor Green
            } else {
                Write-Host "  [DRY RUN] Would remove" -ForegroundColor Cyan
            }
        }
        
        if ($oldVersions.Count -eq 0) {
            Write-Host "No old versions to remove" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Failed to cleanup old versions: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "AWS Lambda Function Deployment" -ForegroundColor Green
Write-Host "=============================" -ForegroundColor Green

switch ($Action.ToLower()) {
    "deploy" {
        if (-not $FunctionName) {
            Write-Host "Please specify a FunctionName to deploy" -ForegroundColor Red
            return
        }
        
        if (-not $SourcePath -and -not $ZipFile) {
            Write-Host "Please specify either SourcePath or ZipFile" -ForegroundColor Red
            return
        }
        
        $packageFile = $ZipFile
        if ($SourcePath) {
            $packageFile = New-LambdaPackage -SourcePath $SourcePath -Runtime $Runtime
        }
        
        if ($packageFile) {
            $success = Deploy-LambdaFunction -FunctionName $FunctionName -ZipFile $packageFile -Runtime $Runtime -Handler $Handler -RoleArn $RoleArn
            
            if ($success -and $SourcePath) {
                # Cleanup package file
                Remove-Item $packageFile -Force
            }
        }
    }
    
    "update" {
        if (-not $FunctionName) {
            Write-Host "Please specify a FunctionName to update" -ForegroundColor Red
            return
        }
        
        $packageFile = $ZipFile
        if ($SourcePath) {
            $packageFile = New-LambdaPackage -SourcePath $SourcePath -Runtime $Runtime
        }
        
        if ($packageFile) {
            Deploy-LambdaFunction -FunctionName $FunctionName -ZipFile $packageFile -Runtime $Runtime -Handler $Handler -RoleArn $RoleArn
            
            if ($SourcePath) {
                Remove-Item $packageFile -Force
            }
        }
    }
    
    "rollback" {
        if (-not $FunctionName -or -not $Version) {
            Write-Host "Please specify FunctionName and Version to rollback" -ForegroundColor Red
            return
        }
        
        Rollback-FunctionVersion -FunctionName $FunctionName -Version $Version
    }
    
    "test" {
        if (-not $FunctionName) {
            Write-Host "Please specify a FunctionName to test" -ForegroundColor Red
            return
        }
        
        Test-LambdaFunction -FunctionName $FunctionName -Payload '{"test": "data"}'
    }
    
    "monitor" {
        if (-not $FunctionName) {
            Write-Host "Please specify a FunctionName to monitor" -ForegroundColor Red
            return
        }
        
        Monitor-FunctionMetrics -FunctionName $FunctionName -Days 7
    }
    
    "cleanup" {
        if (-not $FunctionName) {
            Write-Host "Please specify a FunctionName to cleanup" -ForegroundColor Red
            return
        }
        
        Remove-OldVersions -FunctionName $FunctionName -KeepVersions 5
    }
    
    default {
        Write-Host "Invalid action. Valid actions: deploy, update, rollback, test, monitor, cleanup" -ForegroundColor Red
    }
}

Write-Host "`nUsage Examples:" -ForegroundColor Magenta
Write-Host "  .\function-deployment.ps1 -FunctionName 'my-function' -Action deploy -SourcePath './src' -RoleArn 'arn:aws:iam::123456789012:role/lambda-role'"
Write-Host "  .\function-deployment.ps1 -FunctionName 'my-function' -Action update -SourcePath './src'"
Write-Host "  .\function-deployment.ps1 -FunctionName 'my-function' -Action test"
Write-Host "  .\function-deployment.ps1 -FunctionName 'my-function' -Action monitor"
Write-Host "  .\function-deployment.ps1 -FunctionName 'my-function' -Action rollback -Version '1'"
Write-Host "  .\function-deployment.ps1 -FunctionName 'my-function' -Action cleanup" 
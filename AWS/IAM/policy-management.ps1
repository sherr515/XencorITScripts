# policy-management.ps1
# Comprehensive IAM policy management and analysis script

param(
    [string]$PolicyName = "",
    [string]$Action = "list", # list, create, attach, detach, analyze, audit, cleanup
    [string]$UserName = "",
    [string]$GroupName = "",
    [string]$RoleName = "",
    [string]$PolicyArn = "",
    [string]$PolicyDocument = "",
    [string]$Profile = "default",
    [switch]$ShowDetails,
    [switch]$DryRun,
    [switch]$Force
)

function Get-IAMPolicies {
    param([string]$PolicyName, [string]$PolicyType = "all")
    
    try {
        switch ($PolicyType.ToLower()) {
            "managed" {
                $policies = aws iam list-policies --scope Local --profile $Profile --output json | ConvertFrom-Json
                return $policies.Policies
            }
            "aws" {
                $policies = aws iam list-policies --scope AWS --profile $Profile --output json | ConvertFrom-Json
                return $policies.Policies
            }
            default {
                $allPolicies = @()
                $managed = aws iam list-policies --scope Local --profile $Profile --output json | ConvertFrom-Json
                $aws = aws iam list-policies --scope AWS --profile $Profile --output json | ConvertFrom-Json
                $allPolicies += $managed.Policies
                $allPolicies += $aws.Policies
                return $allPolicies
            }
        }
    }
    catch {
        Write-Host "Unable to get policies" -ForegroundColor Red
        return @()
    }
}

function Get-PolicyDetails {
    param([string]$PolicyArn)
    
    try {
        $policy = aws iam get-policy --policy-arn $PolicyArn --profile $Profile --output json | ConvertFrom-Json
        $version = aws iam get-policy-version --policy-arn $PolicyArn --version-id $policy.Policy.DefaultVersionId --profile $Profile --output json | ConvertFrom-Json
        
        return @{
            Policy = $policy.Policy
            Document = $version.PolicyVersion.Document
        }
    }
    catch {
        Write-Host "Unable to get policy details for $PolicyArn" -ForegroundColor Red
        return $null
    }
}

function New-IAMPolicy {
    param([string]$PolicyName, [string]$PolicyDocument, [string]$Description)
    
    if (-not $PolicyDocument) {
        Write-Host "Please provide a policy document" -ForegroundColor Red
        return $null
    }
    
    try {
        Write-Host "Creating policy: $PolicyName" -ForegroundColor Yellow
        
        if (-not $DryRun) {
            $result = aws iam create-policy --policy-name $PolicyName --policy-document $PolicyDocument --description $Description --profile $Profile --output json | ConvertFrom-Json
            
            Write-Host "Policy created successfully: $($result.Policy.Arn)" -ForegroundColor Green
            return $result.Policy.Arn
        } else {
            Write-Host "[DRY RUN] Would create policy: $PolicyName" -ForegroundColor Cyan
            return "dry-run-policy-arn"
        }
    }
    catch {
        Write-Host "Failed to create policy: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Attach-PolicyToEntity {
    param([string]$PolicyArn, [string]$EntityType, [string]$EntityName)
    
    try {
        Write-Host "Attaching policy $PolicyArn to $EntityType`:$EntityName" -ForegroundColor Yellow
        
        switch ($EntityType.ToLower()) {
            "user" {
                if (-not $DryRun) {
                    aws iam attach-user-policy --user-name $EntityName --policy-arn $PolicyArn --profile $Profile
                } else {
                    Write-Host "[DRY RUN] Would attach policy to user: $EntityName" -ForegroundColor Cyan
                }
            }
            "group" {
                if (-not $DryRun) {
                    aws iam attach-group-policy --group-name $EntityName --policy-arn $PolicyArn --profile $Profile
                } else {
                    Write-Host "[DRY RUN] Would attach policy to group: $EntityName" -ForegroundColor Cyan
                }
            }
            "role" {
                if (-not $DryRun) {
                    aws iam attach-role-policy --role-name $EntityName --policy-arn $PolicyArn --profile $Profile
                } else {
                    Write-Host "[DRY RUN] Would attach policy to role: $EntityName" -ForegroundColor Cyan
                }
            }
            default {
                Write-Host "Invalid entity type. Use: user, group, or role" -ForegroundColor Red
                return
            }
        }
        
        Write-Host "Policy attached successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to attach policy: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Detach-PolicyFromEntity {
    param([string]$PolicyArn, [string]$EntityType, [string]$EntityName)
    
    try {
        Write-Host "Detaching policy $PolicyArn from $EntityType`:$EntityName" -ForegroundColor Yellow
        
        switch ($EntityType.ToLower()) {
            "user" {
                if (-not $DryRun) {
                    aws iam detach-user-policy --user-name $EntityName --policy-arn $PolicyArn --profile $Profile
                } else {
                    Write-Host "[DRY RUN] Would detach policy from user: $EntityName" -ForegroundColor Cyan
                }
            }
            "group" {
                if (-not $DryRun) {
                    aws iam detach-group-policy --group-name $EntityName --policy-arn $PolicyArn --profile $Profile
                } else {
                    Write-Host "[DRY RUN] Would detach policy from group: $EntityName" -ForegroundColor Cyan
                }
            }
            "role" {
                if (-not $DryRun) {
                    aws iam detach-role-policy --role-name $EntityName --policy-arn $PolicyArn --profile $Profile
                } else {
                    Write-Host "[DRY RUN] Would detach policy from role: $EntityName" -ForegroundColor Cyan
                }
            }
            default {
                Write-Host "Invalid entity type. Use: user, group, or role" -ForegroundColor Red
                return
            }
        }
        
        Write-Host "Policy detached successfully" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed to detach policy: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Analyze-PolicySecurity {
    param([string]$PolicyArn)
    
    $policyDetails = Get-PolicyDetails -PolicyArn $PolicyArn
    if (-not $policyDetails) { return }
    
    $document = $policyDetails.Document
    $analysis = @{
        HighRiskActions = @()
        OverlyPermissive = @()
        Recommendations = @()
    }
    
    # Check for high-risk actions
    $highRiskActions = @(
        "*:Delete*", "*:Remove*", "*:Terminate*", "*:Stop*", 
        "iam:Delete*", "iam:Remove*", "ec2:Terminate*", "rds:Delete*",
        "s3:Delete*", "lambda:Delete*", "cloudformation:Delete*"
    )
    
    foreach ($action in $highRiskActions) {
        if ($document -match $action) {
            $analysis.HighRiskActions += $action
        }
    }
    
    # Check for overly permissive statements
    if ($document -match '"Effect":\s*"Allow".*"Action":\s*"\*"') {
        $analysis.OverlyPermissive += "Policy allows all actions (*)"
    }
    
    if ($document -match '"Resource":\s*"\*"') {
        $analysis.OverlyPermissive += "Policy allows all resources (*)"
    }
    
    # Generate recommendations
    if ($analysis.HighRiskActions.Count -gt 0) {
        $analysis.Recommendations += "Review and restrict high-risk actions"
    }
    
    if ($analysis.OverlyPermissive.Count -gt 0) {
        $analysis.Recommendations += "Implement least privilege principle"
    }
    
    if ($document -match '"Condition"') {
        $analysis.Recommendations += "Good: Policy uses conditions for additional security"
    }
    
    return $analysis
}

function Audit-PolicyCompliance {
    param([string]$PolicyArn)
    
    $policyDetails = Get-PolicyDetails -PolicyArn $PolicyArn
    if (-not $policyDetails) { return }
    
    $document = $policyDetails.Document
    $compliance = @{
        Compliant = $true
        Issues = @()
        Score = 100
    }
    
    # Check for required elements
    if (-not ($document -match '"Version"')) {
        $compliance.Issues += "Missing Version statement"
        $compliance.Score -= 10
    }
    
    if (-not ($document -match '"Statement"')) {
        $compliance.Issues += "Missing Statement array"
        $compliance.Score -= 20
    }
    
    # Check for overly permissive policies
    if ($document -match '"Action":\s*"\*"') {
        $compliance.Issues += "Policy allows all actions"
        $compliance.Score -= 30
    }
    
    if ($document -match '"Resource":\s*"\*"') {
        $compliance.Issues += "Policy allows all resources"
        $compliance.Score -= 20
    }
    
    # Check for missing conditions
    if (-not ($document -match '"Condition"')) {
        $compliance.Issues += "No conditions specified"
        $compliance.Score -= 10
    }
    
    if ($compliance.Score -lt 70) {
        $compliance.Compliant = $false
    }
    
    return $compliance
}

function Remove-UnusedPolicies {
    param([int]$DaysUnused = 90)
    
    Write-Host "Finding unused policies (unused for $DaysUnused days)..." -ForegroundColor Yellow
    
    try {
        $policies = Get-IAMPolicies -PolicyType "managed"
        $unusedPolicies = @()
        
        foreach ($policy in $policies) {
            $lastUsed = $policy.UpdateDate
            $daysSinceUpdate = ((Get-Date) - $lastUsed).Days
            
            if ($daysSinceUpdate -gt $DaysUnused) {
                # Check if policy is attached to any entity
                $attachments = aws iam list-entities-for-policy --policy-arn $policy.Arn --profile $Profile --output json | ConvertFrom-Json
                
                if ($attachments.PolicyGroups.Count -eq 0 -and 
                    $attachments.PolicyUsers.Count -eq 0 -and 
                    $attachments.PolicyRoles.Count -eq 0) {
                    $unusedPolicies += $policy
                }
            }
        }
        
        if ($unusedPolicies.Count -gt 0) {
            Write-Host "`nUnused policies found:" -ForegroundColor Yellow
            foreach ($policy in $unusedPolicies) {
                Write-Host "  $($policy.PolicyName) ($($policy.Arn))" -ForegroundColor Gray
                Write-Host "    Last updated: $($policy.UpdateDate)" -ForegroundColor Gray
                
                if (-not $DryRun) {
                    if ($Force -or (Read-Host "Delete this policy? (y/N)") -eq "y") {
                        aws iam delete-policy --policy-arn $policy.Arn --profile $Profile
                        Write-Host "    Deleted" -ForegroundColor Green
                    }
                } else {
                    Write-Host "    [DRY RUN] Would delete" -ForegroundColor Cyan
                }
            }
        } else {
            Write-Host "No unused policies found" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Failed to cleanup unused policies: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "AWS IAM Policy Management" -ForegroundColor Green
Write-Host "========================" -ForegroundColor Green

switch ($Action.ToLower()) {
    "list" {
        $policies = Get-IAMPolicies -PolicyName $PolicyName
        
        if ($policies.Count -eq 0) {
            Write-Host "No IAM policies found." -ForegroundColor Yellow
            return
        }
        
        Write-Host "`nIAM Policies:" -ForegroundColor Yellow
        Write-Host ("=" * 100) -ForegroundColor DarkGray
        
        foreach ($policy in $policies) {
            Write-Host "Policy: " -NoNewline -ForegroundColor White
            Write-Host $policy.PolicyName -ForegroundColor Cyan
            Write-Host "ARN: " -NoNewline -ForegroundColor White
            Write-Host $policy.Arn -ForegroundColor Gray
            Write-Host "Scope: " -NoNewline -ForegroundColor White
            Write-Host $policy.Scope -ForegroundColor Gray
            Write-Host "Updated: " -NoNewline -ForegroundColor White
            Write-Host $policy.UpdateDate -ForegroundColor Gray
            
            if ($ShowDetails) {
                $details = Get-PolicyDetails -PolicyArn $policy.Arn
                if ($details) {
                    Write-Host "Description: " -NoNewline -ForegroundColor White
                    Write-Host $details.Policy.Description -ForegroundColor Gray
                }
            }
            
            Write-Host ""
        }
        
        Write-Host "Total policies: $($policies.Count)" -ForegroundColor Green
    }
    
    "create" {
        if (-not $PolicyName) {
            Write-Host "Please specify a PolicyName to create" -ForegroundColor Red
            return
        }
        
        $policyArn = New-IAMPolicy -PolicyName $PolicyName -PolicyDocument $PolicyDocument -Description "Policy created by script"
        if ($policyArn) {
            Write-Host "Policy created: $policyArn" -ForegroundColor Green
        }
    }
    
    "attach" {
        if (-not $PolicyArn -or -not $UserName -and -not $GroupName -and -not $RoleName) {
            Write-Host "Please specify PolicyArn and one of: UserName, GroupName, or RoleName" -ForegroundColor Red
            return
        }
        
        if ($UserName) {
            Attach-PolicyToEntity -PolicyArn $PolicyArn -EntityType "user" -EntityName $UserName
        } elseif ($GroupName) {
            Attach-PolicyToEntity -PolicyArn $PolicyArn -EntityType "group" -EntityName $GroupName
        } elseif ($RoleName) {
            Attach-PolicyToEntity -PolicyArn $PolicyArn -EntityType "role" -EntityName $RoleName
        }
    }
    
    "detach" {
        if (-not $PolicyArn -or -not $UserName -and -not $GroupName -and -not $RoleName) {
            Write-Host "Please specify PolicyArn and one of: UserName, GroupName, or RoleName" -ForegroundColor Red
            return
        }
        
        if ($UserName) {
            Detach-PolicyFromEntity -PolicyArn $PolicyArn -EntityType "user" -EntityName $UserName
        } elseif ($GroupName) {
            Detach-PolicyFromEntity -PolicyArn $PolicyArn -EntityType "group" -EntityName $GroupName
        } elseif ($RoleName) {
            Detach-PolicyFromEntity -PolicyArn $PolicyArn -EntityType "role" -EntityName $RoleName
        }
    }
    
    "analyze" {
        if (-not $PolicyArn) {
            Write-Host "Please specify a PolicyArn to analyze" -ForegroundColor Red
            return
        }
        
        $analysis = Analyze-PolicySecurity -PolicyArn $PolicyArn
        
        Write-Host "`nSecurity Analysis for $PolicyArn`:" -ForegroundColor Yellow
        
        if ($analysis.HighRiskActions.Count -gt 0) {
            Write-Host "`nHigh-Risk Actions:" -ForegroundColor Red
            foreach ($action in $analysis.HighRiskActions) {
                Write-Host "  $action" -ForegroundColor Red
            }
        }
        
        if ($analysis.OverlyPermissive.Count -gt 0) {
            Write-Host "`nOverly Permissive:" -ForegroundColor Yellow
            foreach ($issue in $analysis.OverlyPermissive) {
                Write-Host "  $issue" -ForegroundColor Yellow
            }
        }
        
        if ($analysis.Recommendations.Count -gt 0) {
            Write-Host "`nRecommendations:" -ForegroundColor Cyan
            foreach ($rec in $analysis.Recommendations) {
                Write-Host "  $rec" -ForegroundColor Cyan
            }
        }
    }
    
    "audit" {
        if (-not $PolicyArn) {
            Write-Host "Please specify a PolicyArn to audit" -ForegroundColor Red
            return
        }
        
        $compliance = Audit-PolicyCompliance -PolicyArn $PolicyArn
        
        Write-Host "`nCompliance Audit for $PolicyArn`:" -ForegroundColor Yellow
        Write-Host "Compliant: $($compliance.Compliant)" -ForegroundColor $(if($compliance.Compliant) { "Green" } else { "Red" })
        Write-Host "Score: $($compliance.Score)/100" -ForegroundColor $(if($compliance.Score -ge 70) { "Green" } else { "Red" })
        
        if ($compliance.Issues.Count -gt 0) {
            Write-Host "`nIssues:" -ForegroundColor Yellow
            foreach ($issue in $compliance.Issues) {
                Write-Host "  $issue" -ForegroundColor Red
            }
        }
    }
    
    "cleanup" {
        Remove-UnusedPolicies -DaysUnused 90
    }
    
    default {
        Write-Host "Invalid action. Valid actions: list, create, attach, detach, analyze, audit, cleanup" -ForegroundColor Red
    }
}

Write-Host "`nUsage Examples:" -ForegroundColor Magenta
Write-Host "  .\policy-management.ps1 -Action list"
Write-Host "  .\policy-management.ps1 -Action create -PolicyName 'MyPolicy' -PolicyDocument '{}'"
Write-Host "  .\policy-management.ps1 -Action attach -PolicyArn 'arn:aws:iam::123456789012:policy/MyPolicy' -UserName 'myuser'"
Write-Host "  .\policy-management.ps1 -Action analyze -PolicyArn 'arn:aws:iam::123456789012:policy/MyPolicy'"
Write-Host "  .\policy-management.ps1 -Action audit -PolicyArn 'arn:aws:iam::123456789012:policy/MyPolicy'"
Write-Host "  .\policy-management.ps1 -Action cleanup -Force" 
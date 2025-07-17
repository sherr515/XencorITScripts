# role-management.ps1
# Comprehensive IAM role management and trust relationship script

param(
    [string]$RoleName = "",
    [string]$Action = "list", # list, create, update, trust, audit, cleanup
    [string]$Profile = "default",
    [string]$TrustPolicy = "",
    [string]$PolicyArn = "",
    [string]$ServicePrincipal = "",
    [string]$AccountId = "",
    [switch]$DryRun,
    [switch]$Force
)

function Get-IAMRoles {
    param([string]$RoleName)
    
    try {
        if ($RoleName) {
            $roles = aws iam list-roles --path-prefix "/" --profile $Profile --output json | ConvertFrom-Json
            return $roles.Roles | Where-Object { $_.RoleName -eq $RoleName }
        } else {
            $roles = aws iam list-roles --profile $Profile --output json | ConvertFrom-Json
            return $roles.Roles
        }
    }
    catch {
        Write-Host "Unable to get IAM roles" -ForegroundColor Red
        return @()
    }
}

function New-IAMRole {
    param([string]$RoleName, [string]$TrustPolicy, [string]$Description)
    
    Write-Host "Creating IAM role: $RoleName" -ForegroundColor Yellow
    
    try {
        if (-not $TrustPolicy) {
            # Default trust policy for EC2
            $TrustPolicy = @{
                Version = "2012-10-17"
                Statement = @(
                    @{
                        Effect = "Allow"
                        Principal = @{
                            Service = "ec2.amazonaws.com"
                        }
                        Action = "sts:AssumeRole"
                    }
                )
            } | ConvertTo-Json -Depth 10
        }
        
        if (-not $DryRun) {
            $result = aws iam create-role --role-name $RoleName --assume-role-policy-document $TrustPolicy --description $Description --profile $Profile --output json | ConvertFrom-Json
            
            Write-Host "Role created successfully: $($result.Role.Arn)" -ForegroundColor Green
            return $result.Role.Arn
        } else {
            Write-Host "[DRY RUN] Would create role: $RoleName" -ForegroundColor Cyan
            return "dry-run-role-arn"
        }
    }
    catch {
        Write-Host "Failed to create role: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Update-RoleTrustPolicy {
    param([string]$RoleName, [string]$TrustPolicy)
    
    Write-Host "Updating trust policy for role: $RoleName" -ForegroundColor Yellow
    
    try {
        if (-not $DryRun) {
            aws iam update-assume-role-policy --role-name $RoleName --policy-document $TrustPolicy --profile $Profile
            
            Write-Host "Trust policy updated successfully" -ForegroundColor Green
        } else {
            Write-Host "[DRY RUN] Would update trust policy for role: $RoleName" -ForegroundColor Cyan
        }
        
        return $true
    }
    catch {
        Write-Host "Failed to update trust policy: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Attach-RolePolicy {
    param([string]$RoleName, [string]$PolicyArn)
    
    Write-Host "Attaching policy $PolicyArn to role $RoleName" -ForegroundColor Yellow
    
    try {
        if (-not $DryRun) {
            aws iam attach-role-policy --role-name $RoleName --policy-arn $PolicyArn --profile $Profile
            Write-Host "Policy attached successfully" -ForegroundColor Green
        } else {
            Write-Host "[DRY RUN] Would attach policy: $PolicyArn" -ForegroundColor Cyan
        }
        
        return $true
    }
    catch {
        Write-Host "Failed to attach policy: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Detach-RolePolicy {
    param([string]$RoleName, [string]$PolicyArn)
    
    Write-Host "Detaching policy $PolicyArn from role $RoleName" -ForegroundColor Yellow
    
    try {
        if (-not $DryRun) {
            aws iam detach-role-policy --role-name $RoleName --policy-arn $PolicyArn --profile $Profile
            Write-Host "Policy detached successfully" -ForegroundColor Green
        } else {
            Write-Host "[DRY RUN] Would detach policy: $PolicyArn" -ForegroundColor Cyan
        }
        
        return $true
    }
    catch {
        Write-Host "Failed to detach policy: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Get-RoleTrustAnalysis {
    param([string]$RoleName)
    
    Write-Host "Analyzing trust relationships for role: $RoleName" -ForegroundColor Yellow
    
    try {
        $role = aws iam get-role --role-name $RoleName --profile $Profile --output json | ConvertFrom-Json
        $trustPolicy = $role.Role.AssumeRolePolicyDocument
        
        $analysis = @{
            RoleName = $RoleName
            TrustedEntities = @()
            RiskLevel = "Low"
            Issues = @()
            Recommendations = @()
        }
        
        foreach ($statement in $trustPolicy.Statement) {
            if ($statement.Principal.Service) {
                foreach ($service in $statement.Principal.Service) {
                    $analysis.TrustedEntities += "Service: $service"
                    
                    # Check for risky service principals
                    if ($service -eq "lambda.amazonaws.com" -or $service -eq "ecs-tasks.amazonaws.com") {
                        $analysis.RiskLevel = "Medium"
                        $analysis.Issues += "Service principal $service has broad permissions"
                    }
                }
            }
            
            if ($statement.Principal.AWS) {
                foreach ($account in $statement.Principal.AWS) {
                    $analysis.TrustedEntities += "Account: $account"
                    
                    if ($account -eq "*") {
                        $analysis.RiskLevel = "High"
                        $analysis.Issues += "Trusts all AWS accounts"
                    }
                }
            }
            
            if ($statement.Principal.Federated) {
                foreach ($federated in $statement.Principal.Federated) {
                    $analysis.TrustedEntities += "Federated: $federated"
                    $analysis.RiskLevel = "Medium"
                }
            }
        }
        
        # Generate recommendations
        if ($analysis.RiskLevel -eq "High") {
            $analysis.Recommendations += "Restrict trust to specific accounts"
        }
        
        if ($analysis.TrustedEntities.Count -gt 3) {
            $analysis.Recommendations += "Consider reducing the number of trusted entities"
        }
        
        return $analysis
    }
    catch {
        Write-Host "Unable to analyze trust relationships" -ForegroundColor Red
        return $null
    }
}

function Audit-RolePermissions {
    param([string]$RoleName)
    
    Write-Host "Auditing permissions for role: $RoleName" -ForegroundColor Yellow
    
    try {
        # Get attached policies
        $attachedPolicies = aws iam list-attached-role-policies --role-name $RoleName --profile $Profile --output json | ConvertFrom-Json
        
        # Get inline policies
        $inlinePolicies = aws iam list-role-policies --role-name $RoleName --profile $Profile --output json | ConvertFrom-Json
        
        $audit = @{
            RoleName = $RoleName
            AttachedPolicies = $attachedPolicies.AttachedPolicies
            InlinePolicies = $inlinePolicies.PolicyNames
            RiskLevel = "Low"
            Issues = @()
            Recommendations = @()
        }
        
        # Check for overly permissive policies
        $riskyPolicies = @("AdministratorAccess", "*", "FullAccess")
        foreach ($policy in $attachedPolicies.AttachedPolicies) {
            if ($riskyPolicies -contains $policy.PolicyName) {
                $audit.RiskLevel = "High"
                $audit.Issues += "High-privilege policy attached: $($policy.PolicyName)"
            }
        }
        
        # Check for inline policies
        if ($inlinePolicies.PolicyNames.Count -gt 0) {
            foreach ($policyName in $inlinePolicies.PolicyNames) {
                $policyDoc = aws iam get-role-policy --role-name $RoleName --policy-name $policyName --profile $Profile --output json | ConvertFrom-Json
                
                # Check for wildcard permissions
                if ($policyDoc.PolicyDocument -match '"Action":\s*"\*"') {
                    $audit.RiskLevel = "High"
                    $audit.Issues += "Inline policy $policyName allows all actions"
                }
                
                if ($policyDoc.PolicyDocument -match '"Resource":\s*"\*"') {
                    $audit.Issues += "Inline policy $policyName allows all resources"
                }
            }
        }
        
        # Generate recommendations
        if ($audit.RiskLevel -eq "High") {
            $audit.Recommendations += "Review and restrict high-privilege policies"
        }
        
        if ($inlinePolicies.PolicyNames.Count -gt 2) {
            $audit.Recommendations += "Consider consolidating inline policies"
        }
        
        return $audit
    }
    catch {
        Write-Host "Unable to audit role permissions" -ForegroundColor Red
        return $null
    }
}

function Cleanup-UnusedRoles {
    param([int]$DaysUnused = 90)
    
    Write-Host "Finding unused roles (unused for $DaysUnused days)..." -ForegroundColor Yellow
    
    try {
        $roles = Get-IAMRoles
        $unusedRoles = @()
        
        foreach ($role in $roles) {
            # Check when role was last used
            $lastUsed = $role.CreateDate
            $daysSinceCreation = ((Get-Date) - $lastUsed).Days
            
            if ($daysSinceCreation -gt $DaysUnused) {
                # Check if role is attached to any instances
                $instances = aws ec2 describe-instances --filters "Name=iam-instance-profile.arn,Values=$($role.Arn)" --profile $Profile --output json | ConvertFrom-Json
                
                if ($instances.Reservations.Count -eq 0) {
                    $unusedRoles += $role
                }
            }
        }
        
        if ($unusedRoles.Count -gt 0) {
            Write-Host "`nUnused roles found:" -ForegroundColor Yellow
            foreach ($role in $unusedRoles) {
                Write-Host "  $($role.RoleName) ($($role.Arn))" -ForegroundColor Gray
                Write-Host "    Created: $($role.CreateDate)" -ForegroundColor Gray
                
                if (-not $DryRun) {
                    if ($Force -or (Read-Host "Delete this role? (y/N)") -eq "y") {
                        # Detach all policies first
                        $attachedPolicies = aws iam list-attached-role-policies --role-name $role.RoleName --profile $Profile --output json | ConvertFrom-Json
                        foreach ($policy in $attachedPolicies.AttachedPolicies) {
                            Detach-RolePolicy -RoleName $role.RoleName -PolicyArn $policy.PolicyArn
                        }
                        
                        # Delete inline policies
                        $inlinePolicies = aws iam list-role-policies --role-name $role.RoleName --profile $Profile --output json | ConvertFrom-Json
                        foreach ($policyName in $inlinePolicies.PolicyNames) {
                            aws iam delete-role-policy --role-name $role.RoleName --policy-name $policyName --profile $Profile
                        }
                        
                        # Delete the role
                        aws iam delete-role --role-name $role.RoleName --profile $Profile
                        Write-Host "    Deleted" -ForegroundColor Green
                    }
                } else {
                    Write-Host "    [DRY RUN] Would delete" -ForegroundColor Cyan
                }
            }
        } else {
            Write-Host "No unused roles found" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Unable to cleanup unused roles" -ForegroundColor Red
    }
}

Write-Host "AWS IAM Role Management" -ForegroundColor Green
Write-Host "======================" -ForegroundColor Green

switch ($Action.ToLower()) {
    "list" {
        $roles = Get-IAMRoles -RoleName $RoleName
        
        if ($roles.Count -eq 0) {
            Write-Host "No IAM roles found." -ForegroundColor Yellow
            return
        }
        
        Write-Host "`nIAM Roles:" -ForegroundColor Yellow
        Write-Host ("=" * 100) -ForegroundColor DarkGray
        
        foreach ($role in $roles) {
            Write-Host "Role: " -NoNewline -ForegroundColor White
            Write-Host $role.RoleName -ForegroundColor Cyan
            Write-Host "ARN: " -NoNewline -ForegroundColor White
            Write-Host $role.Arn -ForegroundColor Gray
            Write-Host "Created: " -NoNewline -ForegroundColor White
            Write-Host $role.CreateDate -ForegroundColor Gray
            
            if ($role.Description) {
                Write-Host "Description: " -NoNewline -ForegroundColor White
                Write-Host $role.Description -ForegroundColor Gray
            }
            
            Write-Host ""
        }
        
        Write-Host "Total roles: $($roles.Count)" -ForegroundColor Green
    }
    
    "create" {
        if (-not $RoleName) {
            Write-Host "Please specify a RoleName to create" -ForegroundColor Red
            return
        }
        
        New-IAMRole -RoleName $RoleName -TrustPolicy $TrustPolicy -Description "Role created by script"
    }
    
    "update" {
        if (-not $RoleName -or -not $TrustPolicy) {
            Write-Host "Please specify RoleName and TrustPolicy" -ForegroundColor Red
            return
        }
        
        Update-RoleTrustPolicy -RoleName $RoleName -TrustPolicy $TrustPolicy
    }
    
    "trust" {
        if (-not $RoleName) {
            Write-Host "Please specify a RoleName to analyze trust" -ForegroundColor Red
            return
        }
        
        $analysis = Get-RoleTrustAnalysis -RoleName $RoleName
        
        if ($analysis) {
            Write-Host "`nTrust Analysis:" -ForegroundColor Cyan
            Write-Host "Risk Level: $($analysis.RiskLevel)" -ForegroundColor $(if($analysis.RiskLevel -eq "Low") { "Green" } else { "Red" })
            
            Write-Host "`nTrusted Entities:" -ForegroundColor Yellow
            foreach ($entity in $analysis.TrustedEntities) {
                Write-Host "  $entity" -ForegroundColor Gray
            }
            
            if ($analysis.Issues.Count -gt 0) {
                Write-Host "`nIssues:" -ForegroundColor Red
                foreach ($issue in $analysis.Issues) {
                    Write-Host "  - $issue" -ForegroundColor Red
                }
            }
            
            if ($analysis.Recommendations.Count -gt 0) {
                Write-Host "`nRecommendations:" -ForegroundColor Yellow
                foreach ($rec in $analysis.Recommendations) {
                    Write-Host "  - $rec" -ForegroundColor Yellow
                }
            }
        }
    }
    
    "audit" {
        if (-not $RoleName) {
            Write-Host "Please specify a RoleName to audit" -ForegroundColor Red
            return
        }
        
        $audit = Audit-RolePermissions -RoleName $RoleName
        
        if ($audit) {
            Write-Host "`nPermission Audit:" -ForegroundColor Cyan
            Write-Host "Risk Level: $($audit.RiskLevel)" -ForegroundColor $(if($audit.RiskLevel -eq "Low") { "Green" } else { "Red" })
            Write-Host "Attached Policies: $($audit.AttachedPolicies.Count)" -ForegroundColor Gray
            Write-Host "Inline Policies: $($audit.InlinePolicies.Count)" -ForegroundColor Gray
            
            if ($audit.Issues.Count -gt 0) {
                Write-Host "`nIssues:" -ForegroundColor Red
                foreach ($issue in $audit.Issues) {
                    Write-Host "  - $issue" -ForegroundColor Red
                }
            }
            
            if ($audit.Recommendations.Count -gt 0) {
                Write-Host "`nRecommendations:" -ForegroundColor Yellow
                foreach ($rec in $audit.Recommendations) {
                    Write-Host "  - $rec" -ForegroundColor Yellow
                }
            }
        }
    }
    
    "cleanup" {
        Cleanup-UnusedRoles -DaysUnused 90
    }
    
    default {
        Write-Host "Invalid action. Valid actions: list, create, update, trust, audit, cleanup" -ForegroundColor Red
    }
}

Write-Host "`nUsage Examples:" -ForegroundColor Magenta
Write-Host "  .\role-management.ps1 -Action list"
Write-Host "  .\role-management.ps1 -Action create -RoleName 'my-role' -TrustPolicy 'trust-policy.json'"
Write-Host "  .\role-management.ps1 -Action update -RoleName 'my-role' -TrustPolicy 'new-trust-policy.json'"
Write-Host "  .\role-management.ps1 -Action trust -RoleName 'my-role'"
Write-Host "  .\role-management.ps1 -Action audit -RoleName 'my-role'"
Write-Host "  .\role-management.ps1 -Action cleanup -Force" 
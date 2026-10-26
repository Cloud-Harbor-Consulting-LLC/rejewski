# SPDX-License-Identifier: MIT
<#
.SYNOPSIS
    Seeds the cloudharbordemo Entra ID tenant for Project Harbor Sonar Sprint 1:
    3 non-admin users on a custom verified domain, 1 admin user on the tenant
    initial domain assigned to the Application Administrator role.

.NOTES
    Prerequisites:
      - PowerShell 7+
      - Microsoft.Graph module: Install-Module Microsoft.Graph -Scope CurrentUser
      - Global Administrator sign-in to the cloudharbordemo tenant
      - Security Defaults disabled on the tenant (Option A baseline)
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$SeedPassword,

    [string]$NonAdminSuffix = "cloudharbor-demo.com",
    [string]$AdminSuffix    = "cloudharbordemo.onmicrosoft.com"
)

Connect-MgGraph -Scopes "User.ReadWrite.All", "Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory"

$passwordProfile = @{
    Password                      = $SeedPassword
    ForceChangePasswordNextSignIn = $false
}

$nonAdminUsers = @(
    @{ MailNickname = "adelev"; DisplayName = "Adele Vance"; Department = "Human Resources" }
    @{ MailNickname = "alexw";  DisplayName = "Alex Wilber"; Department = "Marketing" }
    @{ MailNickname = "meganb"; DisplayName = "Megan Bowen"; Department = "Operations" }
)

$adminUser = @{
    MailNickname = "leeg"
    DisplayName  = "Lee Gu"
    Department   = "IT Administration"
    JobTitle     = "Application Administrator (Sandbox Pivot Target)"
}

foreach ($u in $nonAdminUsers) {
    $upn = "$($u.MailNickname)@$NonAdminSuffix"
    Write-Host "Creating non-admin user: $($u.DisplayName) ($upn)"
    New-MgUser `
        -AccountEnabled `
        -DisplayName $u.DisplayName `
        -MailNickname $u.MailNickname `
        -UserPrincipalName $upn `
        -Department $u.Department `
        -UsageLocation "US" `
        -PasswordProfile $passwordProfile | Out-Null
}

$adminUpn = "$($adminUser.MailNickname)@$AdminSuffix"
Write-Host "Creating admin user: $($adminUser.DisplayName) ($adminUpn)"
$adminNew = New-MgUser `
    -AccountEnabled `
    -DisplayName $adminUser.DisplayName `
    -MailNickname $adminUser.MailNickname `
    -UserPrincipalName $adminUpn `
    -Department $adminUser.Department `
    -JobTitle $adminUser.JobTitle `
    -UsageLocation "US" `
    -PasswordProfile $passwordProfile

$appAdminRoleTemplateId = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
$appAdminRole = Get-MgDirectoryRole -Filter "roleTemplateId eq '$appAdminRoleTemplateId'"
if (-not $appAdminRole) {
    $appAdminRole = New-MgDirectoryRole -RoleTemplateId $appAdminRoleTemplateId
}
$adminRef = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($adminNew.Id)" }
New-MgDirectoryRoleMemberByRef -DirectoryRoleId $appAdminRole.Id -BodyParameter $adminRef
Write-Host "Assigned Lee Gu to Application Administrator role"

Write-Host ""
Write-Host "Seed complete."
Write-Host "Compromised-user candidate: meganb@$NonAdminSuffix"
Write-Host "Admin pivot target:         leeg@$AdminSuffix"
Disconnect-MgGraph
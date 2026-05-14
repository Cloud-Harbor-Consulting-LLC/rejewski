<#
.SYNOPSIS
    Seeds the cloudharbordemo Entra ID tenant with non-admin users, one admin
    pivot user, and four security groups for Project Harbor Sonar Sprint 1.

.NOTES
    Prerequisites:
      - PowerShell 7+
      - Microsoft.Graph module installed: Install-Module Microsoft.Graph -Scope CurrentUser
      - Global Administrator sign-in to cloudharbordemo
      - Security Defaults disabled on the tenant before running (see threat-model.md v0.1)
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$SeedPassword,

    [string]$TenantSuffix = "cloudharbor-demo.com"
)

Connect-MgGraph -Scopes "User.ReadWrite.All", "Group.ReadWrite.All", "Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory"

$passwordProfile = @{
    Password                      = $SeedPassword
    ForceChangePasswordNextSignIn = $false
}

$nonAdminUsers = @(
    @{ MailNickname = "adelev";     DisplayName = "Adele Vance";       Department = "Human Resources" }
    @{ MailNickname = "alexw";      DisplayName = "Alex Wilber";       Department = "Marketing" }
    @{ MailNickname = "diegos";     DisplayName = "Diego Siciliani";   Department = "Sales" }
    @{ MailNickname = "henriettam"; DisplayName = "Henrietta Mueller"; Department = "Engineering" }
    @{ MailNickname = "lynner";     DisplayName = "Lynne Robbins";     Department = "Finance" }
    @{ MailNickname = "meganb";     DisplayName = "Megan Bowen";       Department = "Operations" }
    @{ MailNickname = "pattif";     DisplayName = "Patti Fernandez";   Department = "Legal" }
    @{ MailNickname = "pradeepg";   DisplayName = "Pradeep Gupta";     Department = "IT Support" }
)

$adminUser = @{
    MailNickname = "leeg"
    DisplayName  = "Lee Gu"
    Department   = "IT Administration"
    JobTitle     = "Global Administrator (Sandbox Pivot Target)"
}

$createdUsers = @{}

foreach ($u in $nonAdminUsers) {
    $upn = "$($u.MailNickname)@$TenantSuffix"
    Write-Host "Creating user: $($u.DisplayName) ($upn)"
    $new = New-MgUser `
        -AccountEnabled `
        -DisplayName $u.DisplayName `
        -MailNickname $u.MailNickname `
        -UserPrincipalName $upn `
        -Department $u.Department `
        -UsageLocation "US" `
        -PasswordProfile $passwordProfile
    $createdUsers[$u.MailNickname] = $new.Id
}

$adminUpn = "$($adminUser.MailNickname)@$TenantSuffix"
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
$createdUsers[$adminUser.MailNickname] = $adminNew.Id

$globalAdminRoleTemplateId = "62e90394-69f5-4237-9190-012177145e10"
$globalAdminRole = Get-MgDirectoryRole -Filter "roleTemplateId eq '$globalAdminRoleTemplateId'"
if (-not $globalAdminRole) {
    $globalAdminRole = New-MgDirectoryRole -RoleTemplateId $globalAdminRoleTemplateId
}
$adminRef = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($adminNew.Id)" }
New-MgDirectoryRoleMemberByRef -DirectoryRoleId $globalAdminRole.Id -BodyParameter $adminRef
Write-Host "Assigned Lee Gu to Global Administrator role"

$groups = @(
    @{ Name = "Marketing-Team";  Members = @("alexw", "diegos") }
    @{ Name = "Engineering-Team"; Members = @("henriettam", "pradeepg") }
    @{ Name = "Finance-Team";    Members = @("lynner", "pattif") }
    @{ Name = "All-Employees";   Members = @("adelev", "alexw", "diegos", "henriettam", "lynner", "meganb", "pattif", "pradeepg") }
)

foreach ($g in $groups) {
    Write-Host "Creating security group: $($g.Name)"
    $newGroup = New-MgGroup `
        -DisplayName $g.Name `
        -MailEnabled:$false `
        -SecurityEnabled `
        -MailNickname ($g.Name -replace "-", "").ToLower() `
        -Description "PHS Sprint 1 seed group"
    foreach ($m in $g.Members) {
        $memberRef = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($createdUsers[$m])" }
        New-MgGroupMemberByRef -GroupId $newGroup.Id -BodyParameter $memberRef
    }
}

Write-Host "Seed complete. Compromised-user candidate: meganb@$TenantSuffix"
Disconnect-MgGraph
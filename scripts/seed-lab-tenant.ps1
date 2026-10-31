# SPDX-License-Identifier: MIT
<#
.SYNOPSIS
    Seeds an Entra ID lab tenant with test accounts for Rejewski runs: non-admin
    users on a verified domain, plus one admin user assigned the Application
    Administrator role as a privilege-escalation target.

.DESCRIPTION
    Every value comes from parameters, so the script holds no tenant, domain,
    account, or password of its own. The default roster uses Microsoft's public
    demo personas; pass -Roster to use your own. Use the seeded account you pick
    as COMPROMISED_USER_UPN in .env. Keep the roster you seed: guardrail G-7
    treats it as the record that the lab holds only test accounts.

.PARAMETER UserDomain
    Verified domain for the non-admin users, for example lab.example.com.

.PARAMETER AdminDomain
    Domain for the admin user, for example <your-tenant>.onmicrosoft.com.

.PARAMETER Roster
    Optional path to a JSON file: an array of objects with MailNickname,
    DisplayName, Department, and an optional IsAdmin (true for at most one entry).

.NOTES
    Prerequisites:
      - PowerShell 7+
      - Microsoft.Graph module: Install-Module Microsoft.Graph -Scope CurrentUser
      - Global Administrator sign-in to your lab tenant
    Each account gets its own password, prompted for securely; nothing is echoed
    or written to disk.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$UserDomain,

    [Parameter(Mandatory = $true)]
    [string]$AdminDomain,

    [string]$Roster
)

$defaultRoster = @(
    @{ MailNickname = "adelev"; DisplayName = "Adele Vance"; Department = "Human Resources" }
    @{ MailNickname = "alexw";  DisplayName = "Alex Wilber"; Department = "Marketing" }
    @{ MailNickname = "meganb"; DisplayName = "Megan Bowen"; Department = "Operations" }
    @{ MailNickname = "leeg";   DisplayName = "Lee Gu";      Department = "IT Administration"; IsAdmin = $true }
)

$accounts = if ($Roster) { Get-Content -Raw -Path $Roster | ConvertFrom-Json } else { $defaultRoster }
$admins = @($accounts | Where-Object { $_.IsAdmin })
if ($admins.Count -gt 1) { throw "The roster may mark at most one account IsAdmin." }

Connect-MgGraph -Scopes "User.ReadWrite.All", "Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory"

$appAdminRoleTemplateId = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"

foreach ($u in $accounts) {
    $domain = if ($u.IsAdmin) { $AdminDomain } else { $UserDomain }
    $upn = "$($u.MailNickname)@$domain"
    $secure = Read-Host -AsSecureString "Password for $upn"
    $passwordProfile = @{
        Password                      = (New-Object System.Net.NetworkCredential("", $secure)).Password
        ForceChangePasswordNextSignIn = $false
    }
    Write-Host "Creating user: $($u.DisplayName) ($upn)"
    $created = New-MgUser `
        -AccountEnabled `
        -DisplayName $u.DisplayName `
        -MailNickname $u.MailNickname `
        -UserPrincipalName $upn `
        -Department $u.Department `
        -UsageLocation "US" `
        -PasswordProfile $passwordProfile
    $passwordProfile.Password = $null

    if ($u.IsAdmin) {
        $appAdminRole = Get-MgDirectoryRole -Filter "roleTemplateId eq '$appAdminRoleTemplateId'"
        if (-not $appAdminRole) {
            $appAdminRole = New-MgDirectoryRole -RoleTemplateId $appAdminRoleTemplateId
        }
        $ref = @{ "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($created.Id)" }
        New-MgDirectoryRoleMemberByRef -DirectoryRoleId $appAdminRole.Id -BodyParameter $ref
        Write-Host "Assigned $($u.DisplayName) to Application Administrator"
    }
}

Write-Host ""
Write-Host "Seed complete. Pick a non-admin account as COMPROMISED_USER_UPN in .env."

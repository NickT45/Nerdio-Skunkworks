<#
.SYNOPSIS
  Converts an Azure Files share used for FSLogix from account-key access to
  Microsoft Entra Kerberos (cloud-only users, Entra joined session hosts).

.DESCRIPTION
  Automates the storage-side steps. Idempotent: safe to re-run.
    1. Enable Entra Kerberos on the storage account
    2. Grant admin consent to the storage account app registration
    3. Add the kdc_enable_cloud_group_sids tag to the app manifest
    4. Assign share-level RBAC to the user group
    5. (Optional, -RotateKeys) Rotate both storage account keys

  NOT automated here (do these by hand or elsewhere):
    - Conditional Access: exclude "[Storage Account] <name>.file.core.windows.net" from MFA
    - NTFS permissions: portal > file share > Manage access (no API)
    - Session host registry settings: Nerdio scripted action
        HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters\CloudKerberosTicketRetrievalEnabled = 1
        HKLM\Software\Policies\Microsoft\AzureADAccount\LoadCredKeyFromProfile = 1
    - Removing the stored account key credential from the hosts / NMM

  Run -RotateKeys only AFTER the pilot pool is confirmed working on Kerberos.

.NOTES
  Runtime: PowerShell 7.2 Azure Automation runbook, system-assigned managed identity.
  Modules: Az.Accounts, Az.Storage, Az.Resources, Microsoft.Graph.Authentication,
           Microsoft.Graph.Applications, Microsoft.Graph.Identity.SignIns
  Managed identity needs:
    Azure : Storage Account Contributor + User Access Administrator on the storage account
    Graph : Application.ReadWrite.All, DelegatedPermissionGrant.ReadWrite.All
            (assign via Graph app role assignment; remove after migration)
  Untested draft. Run with -WhatIfMode $true first.
#>

param(
    [Parameter(Mandatory)] [string] $SubscriptionId,
    [Parameter(Mandatory)] [string] $ResourceGroupName,
    [Parameter(Mandatory)] [string] $StorageAccountName,
    [Parameter(Mandatory)] [string] $ShareName,
    [Parameter(Mandatory)] [string] $UserGroupObjectId,   # Entra group containing FSLogix users
    [bool]   $WhatIfMode  = $true,
    [bool]   $RotateKeys  = $false
)

$ErrorActionPreference = 'Stop'

function Log($msg) { Write-Output ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $msg) }
function Act($desc, [scriptblock]$block) {
    if ($WhatIfMode) { Log "WHATIF: $desc" } else { Log $desc; & $block }
}

# --- Connect ---------------------------------------------------------------
Log "Connecting with managed identity"
Connect-AzAccount -Identity | Out-Null
Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
Connect-MgGraph -Identity -NoWelcome

$sa = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
$appDisplayName = "[Storage Account] $StorageAccountName.file.core.windows.net"

# --- Step 1: Enable Entra Kerberos -----------------------------------------
$dirService = $sa.AzureFilesIdentityBasedAuth.DirectoryServiceOptions
Log "Current identity source: '$dirService'"

if ($dirService -in @('AD', 'AADDS')) {
    throw "Storage account already uses '$dirService'. Only one identity source is allowed. Disable it first."
}

if ($dirService -ne 'AADKERB') {
    Act "Enabling Entra Kerberos on $StorageAccountName" {
        Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName `
            -EnableAzureActiveDirectoryKerberosForFile $true | Out-Null
    }
} else {
    Log "Entra Kerberos already enabled"
}

# --- Locate the app registration / service principal -----------------------
$sp = $null
for ($i = 1; $i -le 6 -and -not $sp; $i++) {
    $sp = Get-MgServicePrincipal -Filter "displayName eq '$appDisplayName'" | Select-Object -First 1
    if (-not $sp) {
        if ($WhatIfMode) { Log "WHATIF: app '$appDisplayName' not found yet (expected if step 1 only simulated)"; break }
        Log "Waiting for app registration (attempt $i)"; Start-Sleep -Seconds 20
    }
}

if ($sp) {
    # --- Step 2: Admin consent ---------------------------------------------
    $graphSp = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"
    $wantedScopes = 'openid profile User.Read'
    $existing = Get-MgOauth2PermissionGrant -Filter "clientId eq '$($sp.Id)' and consentType eq 'AllPrincipals'"
    if ($existing -and ($existing.Scope -split ' ' | Where-Object { $_ }) -contains 'User.Read') {
        Log "Admin consent already granted"
    } else {
        Act "Granting admin consent ($wantedScopes) to '$appDisplayName'" {
            New-MgOauth2PermissionGrant -ClientId $sp.Id -ConsentType 'AllPrincipals' `
                -ResourceId $graphSp.Id -Scope $wantedScopes | Out-Null
        }
    }

    # --- Step 3: kdc_enable_cloud_group_sids tag ---------------------------
    $app  = Get-MgApplication -Filter "appId eq '$($sp.AppId)'" | Select-Object -First 1
    $tag  = 'kdc_enable_cloud_group_sids'
    if ($app.Tags -contains $tag) {
        Log "Manifest tag already present"
    } else {
        $newTags = @($app.Tags) + $tag
        Act "Adding '$tag' to app manifest" {
            Update-MgApplication -ApplicationId $app.Id -Tags $newTags
        }
    }
} elseif (-not $WhatIfMode) {
    throw "App registration '$appDisplayName' was not found after waiting."
}

# --- Step 4: Share-level RBAC ----------------------------------------------
$roleName = 'Storage File Data SMB Share Contributor'
$scope = "$($sa.Id)/fileServices/default/fileshares/$ShareName"
$ra = Get-AzRoleAssignment -ObjectId $UserGroupObjectId -RoleDefinitionName $roleName -Scope $scope -ErrorAction SilentlyContinue
if ($ra) {
    Log "Role assignment already exists on share '$ShareName'"
} else {
    Act "Assigning '$roleName' to group $UserGroupObjectId on share '$ShareName'" {
        New-AzRoleAssignment -ObjectId $UserGroupObjectId -RoleDefinitionName $roleName -Scope $scope | Out-Null
    }
}

# --- Step 5 (optional): Rotate account keys --------------------------------
if ($RotateKeys) {
    Act "Rotating key1 and key2 on $StorageAccountName (hosts still using the key will lose access)" {
        New-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -KeyName key1 | Out-Null
        New-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -KeyName key2 | Out-Null
    }
} else {
    Log "Key rotation skipped (-RotateKeys `$false)"
}

Log "Done. Remaining manual steps: Conditional Access exclusion, NTFS via Manage access, Nerdio registry action, remove stored key credential."

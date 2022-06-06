<#
----------------------------------------------------------------------------------
Copyright (c) Microsoft Corporation.
Licensed under the MIT license.
THIS CODE AND INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, 
EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES 
OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
----------------------------------------------------------------------------------

DESCRIPTION:
    Sample script to query the Microsoft Defender for Endpoint APIs to see if the provided 
    machines have been onboarded
 
PREREQUISITES
    You will need an application created in your tenant with the appropriate permissions to use the API.
    Documentation for setup can be found here:
        https://docs.microsoft.com/microsoft-365/security/defender-endpoint/api-hello-world

USAGE:
    ./mde_check_device.ps1 -HostNames <hostname_1>, <hostname_2>, ... <hostname_n>

#>
param( 
    [Parameter(Mandatory, HelpMessage="Enter one or more computer names separated by commas.")]
    [string[]]$HostNames
 )

# Configuration (your tenant, appId, and appSecret)
$global:tenantId   =   "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$global:appId      =   "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$global:appSecret  =   "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

<# 
If you want, you can use a JSON file for your app configuration. Example contents:
{
    "tenantId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "appId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "appSecret": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
#>
$useJsonConfig = $false
if ($useJsonConfig) {
    $config = Get-Content -Path "config.json" | ConvertFrom-Json
    $global:tenantId = $config.tenantId
    $global:appId = $config.appId
    $global:appSecret = $config.appSecret
}


function Get-MDEAuthToken {
    <#
    .SYNOPSIS
        Gets an authentication token for use with the MDE APIs.
    .PARAMETER TenantId
        The tenant where the MDE API is hosted.
    .PARAMETER AppId
        The application ID with access to the MDE APIs.
    .PARAMETER AppSecret
        The application secret for authentication.
    .OUTPUTS
        System.String. The authentication token retrieved on successful auth.
    .LINK
        https://docs.microsoft.com/microsoft-365/security/defender-endpoint/api-hello-world#step-2---get-a-token-using-the-app-and-use-this-token-to-access-the-api
    .EXAMPLE
        Get-MDEAuthToken -TenantId $tenantId -AppId $appId -AppSecret $appSecret
    #>

    param (
        [Parameter(Mandatory)]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [string]$AppId,

        [Parameter(Mandatory)]
        [string]$AppSecret
    )

    # Authenticate to get a token
    $resourceAppIdUri = 'https://api.securitycenter.microsoft.com'
    $oAuthUri = "https://login.microsoftonline.com/$($TenantId)/oauth2/token"
    $body = [Ordered] @{
        resource = "$resourceAppIdUri"
        client_id = $AppId
        client_secret = $AppSecret
        grant_type = 'client_credentials'
    }
    $response = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $body -ErrorAction Stop
    Write-Output $response.access_token
}

function Get-MDEDeviceOnboardingState {
    <#
    .SYNOPSIS
        Gets the onboarded state of a provided device hostname from the MDE API
    .PARAMETER HostNames
        The device hostnames to query.
    .OUTPUTS
        System.String. JSON-formatted string with key:value pairs of hostname:onboardingStatus.
    .LINK
        https://docs.microsoft.com/microsoft-365/security/defender-endpoint/get-machine-by-id
    .EXAMPLE
        Get-MDEDeviceOnboardingState -Hostname $myDeviceHostname
    #>
    param (
        [Parameter(Mandatory)]
        [string[]]$HostNames
    )

    # Use an OData filter expression to only query the provided hostnames
    $url = "https://api.securitycenter.microsoft.com/api/machines/"
    $url += "?`$filter=computerDnsName in ($($HostNames | Join-String -DoubleQuote -Separator ','))"
    $headers = @{ 
        'Content-Type' = 'application/json'
        'Accept' = 'application/json'
        'Authorization' = "Bearer $aadToken" 
    }
    $webResponse = Invoke-WebRequest -Method Get -Uri $url -Headers $headers -ErrorAction Stop
    $responseJson = $webResponse.Content | ConvertFrom-Json

    # Create a dictionary of computerDnsName:onboardingStatus entries
    $onboardingDict = [System.Collections.SortedList]::new()
    foreach ($machineEntry in $responseJson.value) {
        $onboardingDict[$machineEntry.computerDnsName] = $machineEntry.onboardingStatus
    }
    
    # Update our list to include machines we didn't find
    foreach ($hostname in $HostNames) {
        if (!$onboardingDict.ContainsKey($hostname)) {
            $onboardingDict[$hostname] = "Unknown device. No results from API."
        }
    }
    Write-Output $onboardingDict
}

function main {
    # Authenticate
    $aadToken = Get-MDEAuthToken -TenantId $global:tenantId -AppId $global:appId -AppSecret $global:appSecret
    if ([string]::IsNullOrEmpty($aadToken)) {
        Write-Host "Authentication failed: ", $response
        Exit
    }

    # Write the results out as a JSON object.
    $onboardingDict = Get-MDEDeviceOnboardingState -HostNames $HostNames
    Write-Host $($onboardingDict | ConvertTo-Json)
    Exit
}
main


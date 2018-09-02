## V4:
##    1. Add windows feature "Web-Url-Auth"
##    2. Add param "ApplicationPool"
## V5:
##    1. Enable AnonymousAuthentication
##    2. Add authorization rules for control upload and download permission. 
## V6:
##    1. Check whether the username and password is valid
##    2. Grant user $UserName the FullControl permission of the BITSUpload folder (Change "Security" property)
## V7:
##    1. Add FullControl permission to BITS website share folder (Change "Sharing" property)
##    2. Specify user for verifying BITS website and upload physical path access

[CmdletBinding()]
Param
(
[string]$BitsSiteName = "BITS",
[int]$BitsSitePort = 8083,
[string]$BitsSitePhysicalPath = "D:\BITS_NewWebSite",
[string]$BitsSiteUploadFolderName = "BITSUpload",
[string]$Authorization = "WindowsAuthentication",
[string]$ApplicationPool,
[string]$UserName,
[string]$Password,
[bool]$UnrestrictDownload = $true
)

<#
    .SYNOPSIS
        This script used to create and config a BITS website.
    .DESCRIPTION
        Create a BITS website steps:
            1. Create BITS website "BITS"
            2. Add a virtual directory "BITSUpload" to website "BITS"
            3. Enable BITS upload for virtual directory
            4. Enable Windows Authorization for virtual directory "BITSUpload"
            5. Start website "BITS"
    .PARAMETER BitsSiteName
        BITS website Name, default value is "BITS"
    .PARAMETER BitsSitePort
        BITS website port, default value is 8083
    .PARAMETER BitsSitePhysicalPath
        Bits website physical path, default value is "D:\BITS_NewWebSite"
    .PARAMETER BitsSiteUploadFolderName
        Bits website upload folder name, default value is "BITSUpload". BITSUpload virtual directory physical path will be "$BitsSitePhysicalPath\$BitsSiteUploadFolderName"
    .PARAMETER Authorization
        BITS website authorization type, options: AnonymousAuthentication, WindowsAuthentication (default)
    .PARAMETER ApplicationPool
        BITS website application pool, default application pool is "DefaultAppPool", please input the new application pool name if you need
    .PARAMETER UserName
        The username is use to verify the access of BITSUpload physical path
    .PARAMETER Password
        the Password is use to verify the access of BITSUpload physical path
    .PARAMETER UnrestrictDownload
        'True' means that credentials are required to download, 'False' means that credentials are not required to download
    .Outputs 
        NULL
    .EXAMPLE
        .\CreateBITSWebSite.ps1 -BitsSiteName "BITS" -BitsSitePort 8083 -BitsSitePhysicalPath "D:\BITS_NewWebSite" -BitsSiteUploadFolderName "BITSUpload" -Authorization "WindowsAuthentication"
    .NOTES
        Copyright: (C) Motorola Solutions
#>

Function Write-Log
{
[CmdletBinding()]
param(
[string] $Level,
[string] $Message
)
    try
    {
        $logTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $filePath = "$PSScriptRoot\BITSWebsite.log"
    
        if (($Message -ne $null) -and ($Message -ne ''))
        {
            switch($Level)
            {
                "Debug" { write-host $Message -ForegroundColor White}
                "Info" { write-host $Message -ForegroundColor Green}
                "Warning" { write-host $Message -ForegroundColor Yellow}
                "Exception" { write-host $Message -ForegroundColor Red}
            }

            "$logTime [$Level]  $Message" | out-file -FilePath $filePath -NoClobber -Append -Force
        }
    }
    catch [System.Exception]
    {
        Write-host "Failed to write Log" -ForegroundColor Red
        $_ | out-file -FilePath $filePath -NoClobber -Append
    }
}

Function Check-IsNotEmpty
{
[CmdletBinding()]
param(
$Parameter, 
$ParameterName
)
    
    if (-not $Parameter)
    {
        Write-Log -Level "Warning" -Message "The parameter '$ParameterName' cannot be empty."
    }
}

Function Check-Credential
{
[CmdletBinding()]
param(
[string]$UserName,
[string]$Password
)
    Add-Type -assemblyname system.DirectoryServices.accountmanagement 
    $domain = $env:USERDOMAIN
    $ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain
    $pc = New-Object System.DirectoryServices.AccountManagement.PrincipalContext $ct,$domain
    $isValid = $pc.ValidateCredentials($UserName.ToUpper().TrimStart("$domain\".ToUpper()),$Password)
    return $isValid
}

Check-IsNotEmpty -Parameter $BitsSiteName -ParameterName "BitsSiteName"
Check-IsNotEmpty -Parameter $BitsSitePort -ParameterName "BitsSitePort"
Check-IsNotEmpty -Parameter $BitsSitePhysicalPath -ParameterName "BitsSitePhysicalPath"
Check-IsNotEmpty -Parameter $BitsSiteUploadFolderName -ParameterName "BitsSiteUploadFolderName"

$AuthorizationType = "AnonymousAuthentication", "WindowsAuthentication"
if ($AuthorizationType -notcontains $Authorization)
{
    Write-Log -Level "Warning" -Message "The param 'Authorization' is not invalid. The value should be $AuthorizationType" -ForegroundColor Red
}

if ($UserName -and $Password)
{
    $isValid = Check-Credential -UserName $UserName -Password $Password
    if (-not $isValid)
    {
        Write-Log -Level "Warning" -Message "The username or password is incorrect."
        return
    }
}
else
{
    $cred = Get-Credential -Message "Please input physical path credential."
    $UserName = $cred.UserName
    $Password = $cred.GetNetworkCredential().Password
    $isValid = Check-Credential -UserName $UserName -Password $Password
    if (-not $isValid)
    {
        Write-Log -Level "Warning" -Message "The username or password is incorrect."
        return
    }
}

$ErrorActionPreference = "Stop"

# Precondition: Install IIS and BITS windows features
Import-Module ServerManager
$IISAndBITSfeatures = "Web-Default-Doc", "Web-Dir-Browsing", "Web-Http-Errors", "Web-Static-Content", "Web-Http-Redirect", "Web-Http-Logging", 
"Web-Log-Libraries", "Web-ODBC-Logging", "Web-Request-Monitor", "Web-Http-Tracing", "Web-Stat-Compression", "Web-Dyn-Compression", 
"Web-Filtering", "Web-Basic-Auth", "Web-Windows-Auth", "Web-Digest-Auth", "Web-Url-Auth", "Web-App-Dev", "Web-Net-Ext", "Web-Net-Ext45", "Web-ASP", "Web-Asp-Net", "Web-Asp-Net45", 
"Web-ISAPI-Ext", "Web-ISAPI-Filter", "Web-Includes", "Web-Mgmt-Tools", "Web-Mgmt-Console", "Web-Metabase", "Web-Lgcy-Mgmt-Console", 
"Web-Lgcy-Scripting", "Web-WMI", "Web-Scripting-Tools", "Web-Mgmt-Service",
"BITS-IIS-Ext", "RSAT-Bits-Server"

$installedfeatures = Get-WindowsFeature | Where {$_.Installed -eq $true} | ForEach-Object { $_.Name }
$needInstallFeatureNames =@()
$IISAndBITSfeatures | ForEach-Object {
    if ($installedfeatures -notcontains $_) {
        $needInstallFeatureNames += $_
    }
}

if ($needInstallFeatureNames.Length -gt 0)
{
    Write-Log -Level "Info" -Message "Install necessary windows features..."
    $needInstallFeatureNames | ForEach-Object {
        Write-Log -Level "Info" -Message "Installing windows feature $_"
        $result = Add-WindowsFeature -Name $_ -ErrorAction Continue
        if (-not $result.Success)
        {
            Write-Log -Level "Exception" -Message "Failed to install windows feature $_"
        }
    }
}

## Create and configure BITS website.
try
{
    Import-Module WebAdministration
    
    $isCreatedBITSWebsite = $false
    $isExistOldBITSSession = Test-Path "$BitsSitePhysicalPath\$BitsSiteUploadFolderName\BITS-Sessions"
    $isExistOldWebconfig = Test-Path "$BitsSitePhysicalPath\$BitsSiteUploadFolderName\web.config"
    if ($isExistOldWebconfig)
    {
        Write-Log -Level "Warning" -Message "The physical path '$BitsSitePhysicalPath\$BitsSiteUploadFolderName' maybe already configured a website."
    }

    if (-not (Test-Path $BitsSitePhysicalPath))
    {
        New-Item -ItemType Directory -Path $BitsSitePhysicalPath
    }
    
    $bitSiteUploadFolderPhysicalPath = "$BitsSitePhysicalPath\$BitsSiteUploadFolderName"
    if (-not (Test-Path $bitSiteUploadFolderPhysicalPath))
    {
        New-Item -ItemType Directory -Path $bitSiteUploadFolderPhysicalPath
    }
    
    # [Security Property] Grant user '$UserName' the FullControl permission of the BITSUpload folder
    # If the permission is not enough, enable BITSUpload could be failed.
    Write-Log -Level "Info" -Message "Grant user '$UserName' the FullControl permission of the BITSUpload folder."
    $acl = Get-Acl -Path $bitSiteUploadFolderPhysicalPath
    $fullPermission = $UserName, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow'
    $newRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $fullPermission
    $acl.SetAccessRule($newRule)
    $acl | Set-Acl -Path $bitSiteUploadFolderPhysicalPath
    
    # [Sharing Property] Grant FullControl permission for share folder
    if ($BitsSitePhysicalPath.StartsWith("\\"))
    {
        $shareFolderName = ($BitsSitePhysicalPath -split "\\")[-1]
        Grant-SmbShareAccess -Name $shareFolderName -AccountName $UserName -AccessRight Full -Force
    }

    # Step 1. Create BITS website
    if ($ApplicationPool -and (-not (Test-Path -Path IIS:\AppPools\$ApplicationPool)))
    {
        New-WebAppPool -Name $ApplicationPool
    }
    
    if (-not (Test-Path "IIS:\Sites\$BitsSiteName"))
    {
        Write-Log -Level "Info" -Message "Create website '$BitsSiteName'."
        $bitsSiteObj = New-Website -Name $BitsSiteName -Port $BitsSitePort -IPAddress "*" -HostHeader "" -PhysicalPath $BitsSitePhysicalPath -ApplicationPool $ApplicationPool
        
        if ($bitsSiteObj -ne $null)
        {
            $isCreatedBITSWebsite = $true

            # [Verify path access] Specify user for BITS website
            Set-ItemProperty -Path "IIS:\Sites\$BitsSiteName" -name "userName" -value "$UserName"
            Set-ItemProperty -Path "IIS:\Sites\$BitsSiteName" -name "password" -value "$Password"

            # Step 2. Add BITS Upload virtual directory
            Write-Log -Level "Info" -Message "Add virtual directory."
            $uploadVirtualDirectory = New-WebVirtualDirectory -Site $BitsSiteName -Name $BitsSiteUploadFolderName -PhysicalPath $bitSiteUploadFolderPhysicalPath

            # [Verify path access] Specify user for virtual directory
            Set-ItemProperty -Path "IIS:\Sites\$BitsSiteName\$BitsSiteUploadFolderName" -name "userName" -value "$UserName"
            Set-ItemProperty -Path "IIS:\Sites\$BitsSiteName\$BitsSiteUploadFolderName" -name "password" -value "$Password"

            # Step 3. Enable BITS upload for virtual directory
            Write-Log -Level "Info" -Message "Enable BITS upload for virtual directory."
            # [Issue] This method 'EnableBitsUploads' could be failed because of "Single Threaded Apartment", this issue can be fixed by execute command "powershell.exe -sta" 
            #           before execute create BITS command. This command is use to make sure we are using single thread mode.
            $CurrentThreadState = [Threading.Thread]::CurrentThread.GetApartmentState()
            if ($CurrentThreadState -ne "STA")
            {
                Write-Log -Level "Warning" -Message "The current thread is not 'Single Threaded Apartment', it could be affect the enabling of BITSUpload."
            }
            $vdEntry = New-Object System.DirectoryServices.DirectoryEntry("IIS://localhost/W3SVC/$($bitsSiteObj.ID)/root/$BitsSiteUploadFolderName")
            $vdEntry.EnableBitsUploads()

            # Step 4. Set to Windows Authorization
            Write-Log -Level "Info" -Message "Enable $Authorization for virtual directory '$BitsSiteUploadFolderName'."
            if ($Authorization -eq "WindowsAuthentication")
            {
                Set-WebConfigurationProperty `
                    -Filter "/system.webServer/security/authentication/anonymousAuthentication" `
                    -Name "enabled" `
                    -Value $false `
                    -Location "$BitsSiteName/$BitsSiteUploadFolderName" `
                    -PSPath IIS:\
                Set-WebConfigurationProperty `
                    -Filter "/system.webServer/security/authentication/windowsAuthentication" `
                    -Name "enabled" `
                    -Value $true `
                    -Location "$BitsSiteName/$BitsSiteUploadFolderName" `
                    -PSPath IIS:\    # We are using the root (applicationHost.config) file
                
                if ($UnrestrictDownload)
                {
                    Write-Log -Level "Info" -Message "Allow anonymous user to download"
                    Set-WebConfigurationProperty `
                        -Filter "/system.webServer/security/authentication/anonymousAuthentication" `
                        -Name "enabled" `
                        -Value $true `
                        -Location "$BitsSiteName/$BitsSiteUploadFolderName" `
                        -PSPath IIS:\
                    # Add authorization rules, open download permission
                    # users='?' means 'all anonymous users', users='*' means 'all users', users='S-P1-SetUp, Administrator' means specific one or more users.
                    # For download, only need "GET, HEAD"                    
                    $appcmdPath = "$env:windir\system32\inetsrv"
                    if (-not (Test-Path "$appcmdPath\appcmd.exe"))
                    {
                        Write-Log -Level "Exception" -Message "The path '$appcmdPath\appcmd.exe' does not exist."
                    }
                    else
                    {
                        $erroMessageRegex = "ERROR[\s]*\([\s]*message[\s\S]*\)"
                        # Remove the Inherited URL Authorization, forbid anonymous user to upload
                        $configResult1 = . $appcmdPath\appcmd.exe set config "$BitsSiteName/$BitsSiteUploadFolderName" -section:system.webServer/security/authorization /-"[accessType='Allow',users='*']" | Out-String
                        if ($configResult1 -match $erroMessageRegex)
                        {
                            throw $configResult1
                        }
                        else
                        {
                            Write-Log -Level "Debug" -Message $configResult1
                        }
                        
                        # Add a rule, allow anonymous user to download
                        $configResult2 = . $appcmdPath\appcmd.exe set config "$BitsSiteName/$BitsSiteUploadFolderName" -section:system.webServer/security/authorization /+"[accessType='Allow',users='?',verbs='GET, HEAD']" | Out-String
                        if ($configResult2 -match $erroMessageRegex)
                        {
                            throw $configResult2
                        }
                        else
                        {
                            Write-Log -Level "Debug" -Message $configResult2
                        }
                        
                        # Add a rule, limit upload permission, grant administrator/domain user to upload
                        $configResult3 = . $appcmdPath\appcmd.exe set config "$BitsSiteName/$BitsSiteUploadFolderName" -section:system.webServer/security/authorization /+"[accessType='Allow',roles='Administrators, Administrator, Domain Users']" | Out-String
                        if ($configResult3 -match $erroMessageRegex)
                        {
                            throw $configResult3
                        }
                        else
                        {
                            Write-Log -Level "Debug" -Message $configResult3
                        }
                    }
                }
            }
            elseif ($Authorization -eq "AnonymousAuthentication")
            {
                Set-WebConfigurationProperty `
                    -Filter "/system.webServer/security/authentication/anonymousAuthentication" `
                    -Name "enabled" `
                    -Value $true `
                    -Location "$BitsSiteName/$BitsSiteUploadFolderName" `
                    -PSPath IIS:\
            }

            # Step 5. Start BITS website
            Write-Log -Level "Info" -Message "Start website '$BitsSiteName'."
            try
            {
                Start-Website -Name $BitsSiteName
            }
            catch [System.Exception]
            {
                Write-Log -Level "Exception" -Message "The website $BitsSiteName cannot be started. Another website maybe using the same port."
                Write-Log -Level "Exception" -Message $_
            }
        }
        else
        {
            Write-Log -Level "Exception" -Message "The website $BitsSiteName does not exist!"
        }

        Write-Log -Level "Info" -Message "Successfully created website $BitsSiteName."
    }
    else
    {
        Write-Log -Level "Info" -Message "The website '$BitsSiteName' already exist!"
        return
    }
}
catch [System.Exception]
{
    Write-Log -Level "Exception" -Message "Failed to create BITS Website."
    Write-Log -Level "Exception" -Message $_
    Write-Log -Level "Exception" -Message "    $($_.ScriptStackTrace)"
    # Rollback
    if ($isCreatedBITSWebsite)
    {
        Write-Log -Level "Info" -Message "Rolling back."
        Remove-Website -Name $BitsSiteName
        
        if ((-not $isExistOldBITSSession) -and (Test-Path "$BitsSitePhysicalPath\$BitsSiteUploadFolderName\BITS-Sessions"))
        {
            Remove-Item -Path "$BitsSitePhysicalPath\$BitsSiteUploadFolderName\BITS-Sessions"
        }
        
        if ((-not $isExistOldWebconfig) -and (Test-Path "$BitsSitePhysicalPath\$BitsSiteUploadFolderName\web.config"))
        {
            Remove-Item -Path "$BitsSitePhysicalPath\$BitsSiteUploadFolderName\web.config"
        }
    }
}

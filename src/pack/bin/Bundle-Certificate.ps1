<#
.SYNOPSIS
    Great DANE Connector Response Processor

.DESCRIPTION
    Bundles the X509 Certificate and private key optionally produced by the
    Great DANE Connector, creating an X509Certificate2 instance.

    Requires BouncyCastle 1.8.1 (https://www.nuget.org/packages/BouncyCastle/).

.PARAMETER ConnectorResponse
    Response from Great DANE Connector containing generated key and certificate

.PARAMETER FriendlyName
    PKCS12 friendlyName used to alias bundled key and certificate

.EXAMPLE
    # Be sure to load the Bouncy Castle assembly!
    Add-Type -Path BouncyCastle.Crypto.dll
    $fredsPkcs12 = Publish-Smimea fred@example.com | Bundle-Certificate

.OUTPUTS
    New System.Security.Cryptography.X509Certificates.X509Certificate2 instance

.NOTES
    Adapted from https://github.com/rlipscombe/PSBouncyCastle

    Copyright (C) 2017 Grier Forensics. All Rights Reserved.
#>
Param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [PSObject] $connectorResponse,
    [String] $friendlyName = "default"
)

if (([AppDomain]::CurrentDomain.GetAssemblies() | Where {$_ -match "BouncyCastle.Crypto"}) -eq $null) {
    Write-Host "Bouncy Castle assembly not found! Cannot continue."
    Exit
}

$privateKeyPem = $connectorResponse.privateKey
$certificatePem = $connectorResponse.certificate

if (-not ($privateKeyPem) -or -not ($certificatePem)) {
    Write-Host "Connector response does not contain a private key or certificate"
    Exit
}

$reader = New-Object System.IO.StringReader($privateKeyPem)
$pemReader = New-Object Org.BouncyCastle.OpenSsl.PemReader($reader)
$keypair = [Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair] $pemReader.ReadObject()
$privKey = $keypair.Private

$reader = New-Object System.IO.StringReader($certificatePem)
$pemReader = New-Object Org.BouncyCastle.OpenSsl.PemReader($reader)
$cert = [Org.BouncyCastle.X509.X509Certificate] $pemReader.ReadObject()

$store = New-Object Org.BouncyCastle.Pkcs.Pkcs12Store

$certEntry = New-Object Org.BouncyCastle.Pkcs.X509CertificateEntry($cert)
$store.SetCertificateEntry($friendlyName, $certEntry)

$keyEntry = New-Object Org.BouncyCastle.Pkcs.AsymmetricKeyEntry($privKey)
$store.SetKeyEntry($friendlyName, $keyEntry, @($certEntry))

$randomGenerator = New-Object Org.BouncyCastle.Crypto.Prng.CryptoApiRandomGenerator
$random = New-Object Org.BouncyCastle.Security.SecureRandom($randomGenerator)

# The password is re-used immediately, so it doesn't matter what it is.
$password = 'password'
$stream = New-Object System.IO.MemoryStream
$store.Save($stream, $password, $random)

$keyStorageFlags = (
    [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor
    [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

$result = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
        $stream.ToArray(), $password, $keyStorageFlags)

$stream.Dispose()

$result
<#
.SYNOPSIS
    Great DANE Connector PowerShell client

.DESCRIPTION
    Publishes DANE SMIMEA records using the specified Great DANE Connector.

    This script will attempt to use the Great DANE Connector to generate a
    private key and certificate for the user if no S/MIME certificates are
    supplied.

.PARAMETER Connector
    HTTP address of the Great DANE Connector

.PARAMETER Certificates
    User's X.509 S/MIME certificates

.PARAMETER Name
    User's full name

.PARAMETER EmailAddress
    User's email address

.EXAMPLE
    $password = Read-Host "Enter password" -AsSecureString
    New-Mailbox -UserPrincipalName alice@example.com -Name Alice `
        -OrganizationalUnit Users -Password $password
    Publish-Smimea alice@example.com

.EXAMPLE
    $smimeCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate
    $smimeCertificate.Import("C:\Users\Administrator\Documents\bob@example.com.pem")
    Publish-Smimea -connector https://connector.example.com `
        -certificates $smimeCertificate -userName Bob bob@example.com

.EXAMPLE
    $fredsPkcs12 = Publish-Smimea fred@example.com | Bundle-Certificate

.OUTPUTS
    ProvisionResponse PSObject of the form:

    {
        records:     ["Published DANE SMIMEA resource records"],
        privateKey:  "(Optional) Generated private key",
        certificate: "(Optional) Generated S/MIME certificate"
    }

    Note: Use Bundle-Certificate with Bouncy Castle to produce a bundled
    certificate and key (X509Certificate2) from the ProvisionResponse.

.NOTES
    Copyright (C) 2017 Grier Forensics. All Rights Reserved.
#>

Param(
    [String] $connector = "http://10.0.2.2:35353",
    [System.Security.Cryptography.X509Certificates.X509Certificate[]] $certificates = @(),
    [String] $userName,
    [Parameter(Mandatory=$true, Position=0)][String] $emailAddress
)

# API Key used for all Great DANE Connector requests (Adjust as needed)
$apiKey = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# Convert certificates to Base64-encoded form (PEM). No need for certificate header/footer
$certs = New-Object System.Collections.Generic.List[String]
foreach ($cert in $certificates) {
    $certs.Add(
      "-----BEGIN CERTIFICATE-----`n" +
      [System.Convert]::ToBase64String($cert.GetRawCertData()) +
      "`n-----END CERTIFICATE-----"
    )
}

# Make request body
$body = @{}
if ($userName) {
    $body.Add("name", $userName)
}
if ($certs.Count -gt 0) {
    $body.Add("certificates", $certs)
}
$json = $body | ConvertTo-Json

Invoke-RestMethod -Method POST -Uri $connector/api/v1/user/$emailAddress -Headers @{"Authorization" = $apiKey} -ContentType "application/json" -Body $json

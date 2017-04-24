// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane.connector

import org.scalatest.FlatSpec

class CertificateGeneratorSpec extends FlatSpec {

  import TestUtils.Values._

  "The CertificateGenerator" should "generate RSA keys by default" in {
    val keyPair = TestUtils.makeCertGenerator.makeKeyPair
    assert(keyPair.getPublic.getAlgorithm == "RSA")
    assert(keyPair.getPrivate.getAlgorithm == "RSA")

    assert(keyPair.getPublic.getFormat == "X.509")
    assert(keyPair.getPrivate.getFormat == "PKCS#8")

    // TODO: check for 2048 bits
  }

  it should "create certificates suitable for S/MIME" in {
    val email = "foo@example.com"

    val (key, cert) = TestUtils.makeCertGenerator.makeKeyAndCertificate(email)

    // Subject: emailAddress=<email> (backwards-compatibility)
    assert(TestUtils.emailAddress(cert) == email)

    // Subject Alternative Name: email:<email>
    val subjAltNameEmail = TestUtils.subjectAlternativeNameEmail(cert)
    assert(subjAltNameEmail.nonEmpty && subjAltNameEmail.get == email,
      "Email address not found in Subject Alternative Names")

    // Key Usage: Digital Signature (0) and Key Encipherment (2) only
    assert(TestUtils.smimeKeyUsage(cert))

    // Extended Key Usage: Email Protection only
    assert(TestUtils.smimeExtendedKeyUsage(cert))

    // Constraints: Not a CA
    assert(!TestUtils.isCA(cert))
  }

  // TODO: verify that certificate is properly signed
}

// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane.connector

import java.io.{ByteArrayOutputStream, OutputStream}
import java.math.BigInteger
import java.security._
import java.security.cert.X509Certificate
import java.util.Date

import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509._
import org.bouncycastle.cert.X509ExtensionUtils
import org.bouncycastle.cert.jcajce.{JcaX509CertificateConverter, JcaX509v3CertificateBuilder}
import org.bouncycastle.crypto.digests.SHA1Digest
import org.bouncycastle.operator.DigestCalculator
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

class SHA1DigestCalculator extends DigestCalculator {
  private val bOut = new ByteArrayOutputStream()

  override def getAlgorithmIdentifier: AlgorithmIdentifier = new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)

  override def getOutputStream: OutputStream = bOut

  override def getDigest: Array[Byte] = {
    val bytes = bOut.toByteArray

    bOut.reset()

    val sha1 = new SHA1Digest()

    sha1.update(bytes, 0, bytes.length)

    val digest = new Array[Byte](sha1.getDigestSize)

    sha1.doFinal(digest, 0)

    digest
  }
}

/** Make a private key and S/MIME certificate.
  *
  * Based on Bouncy Castle test code, found here:
  * https://github.com/bcgit/bc-java/blob/master/mail/src/test/java/org/bouncycastle/mail/smime/test/NewSMIMEEnvelopedTest.java
  */
object CertificateGenerator {
  private val Srand = new SecureRandom()

  // TODO: make algo configurable (e.g. RSA, ECDSA, AES, etc.)
  // See: https://github.com/bcgit/bc-java/blob/master/mail/src/test/java/org/bouncycastle/mail/smime/test/CMSTestUtil.java
  private val kpg = KeyPairGenerator.getInstance("RSA", Settings.SecurityProvider)
  kpg.initialize(2048, Srand)

  // TODO: load existing key pair from Settings
  private val SigningKeyPair = makeKeyPair

  private val ExtUtils = new X509ExtensionUtils(new SHA1DigestCalculator)

  // TODO: not guaranteed to be unique
  def serialNumber(): BigInteger = BigInteger.probablePrime(20*8, Srand)

  /** Creates a new 2048-bit RSA key pair
    *
    * @return new RSA KeyPair
    */
  def makeKeyPair: KeyPair = kpg.generateKeyPair()

  /** Create new private key and public S/MIME certificate for the given email address
    *
    * @param emailAddress Email address for which to create S/MIME certificate
    * @return new private key and X.509 certificate
    */
  def makeKeyAndCertificate(emailAddress: String): (PrivateKey, X509Certificate) = {
    val reciKP = makeKeyPair
    val reciCert = makeCertificate(reciKP, emailAddress, SigningKeyPair, Settings.DistinguishedName)
    (reciKP.getPrivate, reciCert)
  }

  /** Creates a new S/MIME certificate using the given KeyPairs and email address
    *
    * @param subjectKP key pair for certificate owner
    * @param subjectEmail email address of certificate owner
    * @param issuingKP key pair for signing authority (e.g. Great DANE Connector's keys)
    * @param issuingDN Distinguished Name of signing authority
    * @param ca whether to create a Certificate Authority certificate
    * @return new X.509 S/MIME certificate
    */
  private def makeCertificate(subjectKP: KeyPair, subjectEmail: String,
                              issuingKP: KeyPair, issuingDN: String,
                      ca: Boolean = false): X509Certificate = {
    val subPub = subjectKP.getPublic
    val issPriv = issuingKP.getPrivate
    val issPub = issuingKP.getPublic

    // Note: we set Subject: emailAddress=<email> for backwards compatibility
    // The correct place to set the email address is in the Subject Alternative Name extension
    val v3CertGen = new JcaX509v3CertificateBuilder(
      new X500Name(issuingDN),
      serialNumber(),
      new Date(System.currentTimeMillis()),
      new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * Settings.CertificateExpiryDays)),
      new X500Name(s"emailAddress=$subjectEmail"),
      subPub)

    val contentSignerBuilder: JcaContentSignerBuilder = makeContentSignerBuilder(issPub)

    v3CertGen.addExtension(
      Extension.authorityKeyIdentifier,
      false,
      createAuthorityKeyId(issPub))

    v3CertGen.addExtension(
      Extension.subjectKeyIdentifier,
      false,
      createSubjectKeyId(subPub))

    v3CertGen.addExtension(
      Extension.keyUsage,
      true,
      new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment)
    )

    v3CertGen.addExtension(
      Extension.basicConstraints,
      true,
      new BasicConstraints(ca))

    v3CertGen.addExtension(
      Extension.extendedKeyUsage,
      false,
      new ExtendedKeyUsage(KeyPurposeId.id_kp_emailProtection)
    )

    /*
    v3CertGen.addExtension(
      Extension.certificatePolicies,
      false,
      new CertificatePolicies(new PolicyInformation())
    )
    */

    /*
    v3CertGen.addExtension(
      Extension.cRLDistributionPoints,
      false,
      new CRLDistPoint()
    )
    */

    v3CertGen.addExtension(
      Extension.subjectAlternativeName,
      false,
      new GeneralNames(new GeneralName(GeneralName.rfc822Name, subjectEmail))
    )

    val cert: X509Certificate = new JcaX509CertificateConverter().setProvider(Settings.SecurityProvider)
      .getCertificate(v3CertGen.build(contentSignerBuilder.build(issPriv)))

    // If these throw exceptions we have a problem
    cert.checkValidity(new Date())
    cert.verify(issPub)

    cert
  }

  private def makeContentSignerBuilder(issPub: PublicKey): JcaContentSignerBuilder =
    new JcaContentSignerBuilder("SHA256WithRSA").setProvider(Settings.SecurityProvider)

  private def createSubjectKeyId(pubKey: SubjectPublicKeyInfo): SubjectKeyIdentifier =
    ExtUtils.createSubjectKeyIdentifier(pubKey)

  private def createSubjectKeyId(pubKey: PublicKey): SubjectKeyIdentifier =
    ExtUtils.createSubjectKeyIdentifier(SubjectPublicKeyInfo.getInstance(pubKey.getEncoded))

  private def createAuthorityKeyId(pubKey: PublicKey): AuthorityKeyIdentifier =
    ExtUtils.createAuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(pubKey.getEncoded))


  def main(args: Array[String]): Unit = {
    if (args.length < 1) {
      println("usage: make-cert <email address>")
      sys.exit(1)
    }

    val email = args(0)
    val (key, cert) = makeKeyAndCertificate(email)
    println(Converters.toPem(cert))
    println(Converters.toPem(key))
  }
}

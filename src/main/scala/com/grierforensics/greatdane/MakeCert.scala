// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane

import java.io.{ByteArrayOutputStream, OutputStream}
import java.math.BigInteger
import java.security.cert.X509Certificate
import java.security._
import java.util.Date

import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509._
import org.bouncycastle.cert.{X509CertificateHolder, X509ExtensionUtils}
import org.bouncycastle.cert.jcajce.{JcaX509CertificateConverter, JcaX509v3CertificateBuilder}
import org.bouncycastle.crypto.digests.SHA1Digest
import org.bouncycastle.jce.provider.BouncyCastleProvider
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
object MakeCert {

  val Provider = new BouncyCastleProvider
  Security.addProvider(Provider)

  val rand = new SecureRandom()

  private val CertificateConverter = new JcaX509CertificateConverter().setProvider(Provider)

  // TODO: make algo configurable (e.g. RSA, ECDSA, AES, etc.)
  // See: https://github.com/bcgit/bc-java/blob/master/mail/src/test/java/org/bouncycastle/mail/smime/test/CMSTestUtil.java
  val kpg = KeyPairGenerator.getInstance("RSA", Provider)
  kpg.initialize(2048, rand)

  val extUtils = new X509ExtensionUtils(new SHA1DigestCalculator)

  def makeKeyPair: KeyPair = kpg.generateKeyPair()

  def makeCertificate(subKP: KeyPair, subDN: String, issKP: KeyPair, issDN: String): X509Certificate =
    makeCertificate(subKP, subDN, issKP, issDN, ca = false)

  def makeCACertificate(subKP: KeyPair, subDN: String, issKP: KeyPair, issDN: String): X509Certificate =
    makeCertificate(subKP, subDN, issKP, issDN, ca = true)

  private def makeCertificate(subKP: KeyPair, subDN: String, issKP: KeyPair, issDN: String, ca: Boolean): X509Certificate = {
    val subPub = subKP.getPublic
    val issPriv = issKP.getPrivate
    val issPub = issKP.getPublic

    val v3CertGen = new JcaX509v3CertificateBuilder(
      new X500Name(issDN),
      serialNumber(),
      new Date(System.currentTimeMillis()),
      new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365)),
      new X500Name(subDN),
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
      new GeneralNames(new GeneralName(GeneralName.rfc822Name, subDN))
    )

    val _cert: X509Certificate = new JcaX509CertificateConverter().setProvider(Provider)
      .getCertificate(v3CertGen.build(contentSignerBuilder.build(issPriv)))

    _cert.checkValidity(new Date())
    _cert.verify(issPub)
    _cert
  }

  def makeContentSignerBuilder(issPub: PublicKey): JcaContentSignerBuilder =
    new JcaContentSignerBuilder("SHA256WithRSA").setProvider(Provider)
  def createSubjectKeyId(pubKey: SubjectPublicKeyInfo): SubjectKeyIdentifier =
    extUtils.createSubjectKeyIdentifier(pubKey)
  def createSubjectKeyId(pubKey: PublicKey): SubjectKeyIdentifier =
    extUtils.createSubjectKeyIdentifier(SubjectPublicKeyInfo.getInstance(pubKey.getEncoded))
  def createAuthorityKeyId(pubKey: PublicKey): AuthorityKeyIdentifier =
    extUtils.createAuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(pubKey.getEncoded))

  // TODO: not guaranteed to be unique
  def serialNumber(): BigInteger = BigInteger.probablePrime(20*8, rand)

  /** Converts an X509CertificateHolder to an X509Certificate */
  def convert(ch: X509CertificateHolder): X509Certificate = CertificateConverter.getCertificate(ch)

  /** Encodes X.509 Certificate data to PEM */
  def toPem(ch: X509CertificateHolder): String = toPem(convert(ch))
  /*
  def toPem(cert: X509Certificate): String = {
    import java.io.StringWriter

    import org.bouncycastle.openssl.jcajce.JcaPEMWriter

    val sw = new StringWriter()
    val pemWriter = new JcaPEMWriter(sw)
    try {
      pemWriter.writeObject(cert)
    } finally {
      pemWriter.close()
    }
    sw.toString
  }

  def toPem(key: PrivateKey): String = {
    import java.io.StringWriter

    import org.bouncycastle.openssl.jcajce.JcaPEMWriter

    val sw = new StringWriter()
    val pemWriter = new JcaPEMWriter(sw)
    try {
      pemWriter.writeObject(key)
    } finally {
      pemWriter.close()
    }
    sw.toString
  }
  */

  def toPem[T](obj: T): String = {
    import java.io.StringWriter

    import org.bouncycastle.openssl.jcajce.JcaPEMWriter

    val sw = new StringWriter()
    val pemWriter = new JcaPEMWriter(sw)
    try {
      pemWriter.writeObject(obj)
    } finally {
      pemWriter.close()
    }
    sw.toString
  }

  def main(args: Array[String]): Unit = {
    if (args.length < 1) {
      println("usage: make-cert <email address>")
      sys.exit(1)
    }

    val email = args(0)

    val signDN = "C=US, ST=Maryland, L=Baltimore, O=Grier Forensics, CN=Great DANE Connector"
    val signKP = makeKeyPair

    val reciDN = s"emailAddress=$email"
    val reciKP = makeKeyPair

    val reciCert = makeCertificate(reciKP, reciDN, signKP, signDN)

    val pem = toPem(reciCert)
    println(pem)

    println(toPem(reciKP.getPrivate))
  }
}

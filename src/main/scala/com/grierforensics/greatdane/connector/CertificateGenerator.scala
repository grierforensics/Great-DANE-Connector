// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane.connector

import java.io.{ByteArrayOutputStream, OutputStream}
import java.math.BigInteger
import java.nio.file.{Files, Paths}
import java.security._
import java.security.cert.X509Certificate
import java.util.Date

import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509._
import org.bouncycastle.cert.X509ExtensionUtils
import org.bouncycastle.cert.jcajce.{JcaX509CertificateConverter, JcaX509v3CertificateBuilder}
import org.bouncycastle.crypto.digests.SHA1Digest
import org.bouncycastle.openssl.jcajce.JcaPKIXIdentityBuilder
import org.bouncycastle.operator.DigestCalculator
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.pkix.jcajce.JcaPKIXIdentity

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

object FilesystemIdentityLoader {
  def loadIdentity(keyPath: String, certPath: String): JcaPKIXIdentity = {
    // Example loading from resource:
    //val keyIs = getClass.getClassLoader.getResourceAsStream("key.pem")
    //val certIs = getClass.getClassLoader.getResourceAsStream("cert.pem")
    val keyIs = Files.newInputStream(Paths.get(keyPath))
    try {
      val certIs = Files.newInputStream(Paths.get(certPath))
      try {
        new JcaPKIXIdentityBuilder().setProvider(Settings.SecurityProvider).build(keyIs, certIs)
      } finally {
        certIs.close()
      }
    } finally {
      keyIs.close()
    }
  }
}

/** Make a private key and S/MIME certificate.
  *
  * Based on Bouncy Castle test code, found here:
  * https://github.com/bcgit/bc-java/blob/master/mail/src/test/java/org/bouncycastle/mail/smime/test/NewSMIMEEnvelopedTest.java
  */
class CertificateGenerator(keyAlgorithm: String, keyBits: Int,
                           signatureAlgorithm: String, expiryDays: Int,
                          identity: Option[JcaPKIXIdentity]) {
  import CertificateGenerator._

  // See: https://github.com/bcgit/bc-java/blob/master/mail/src/test/java/org/bouncycastle/mail/smime/test/CMSTestUtil.java
  private val kpg = KeyPairGenerator.getInstance(keyAlgorithm, Settings.SecurityProvider)
  kpg.initialize(keyBits, Srand)

  private def makeContentSignerBuilder(issPub: PublicKey): JcaContentSignerBuilder =
    new JcaContentSignerBuilder(signatureAlgorithm).setProvider(Settings.SecurityProvider)

  /** Create new private key and public S/MIME certificate for the given email address
    *
    * If this CertificateGenerator instance was instantiated without a signing identity
    * this will generate a self-signed certificate.
    *
    * @param emailAddress Email address for which to create S/MIME certificate
    * @return new private key and X.509 certificate
    */
  def makeKeyAndCertificate(emailAddress: String): (PrivateKey, X509Certificate) = {
    val reciKP = makeKeyPair

    // If identity is None, create a self-signed certificate
    val (signingKeyPair, issuingDN) = identity.fold((reciKP, s"CN=$emailAddress")) { id =>
      (new KeyPair(id.getX509Certificate.getPublicKey, id.getPrivateKey),
      id.getX509Certificate.getIssuerDN.getName)
    }

    val reciCert = makeCertificate(reciKP, emailAddress, signingKeyPair, issuingDN)
    (reciKP.getPrivate, reciCert)
  }

  /** Creates a new 2048-bit RSA key pair
    *
    * @return new RSA KeyPair
    */
  def makeKeyPair: KeyPair = kpg.generateKeyPair()

  /** Creates a new S/MIME certificate using the given KeyPairs and email address
    *
    * @param subjectKP key pair for certificate owner
    * @param subjectEmail email address of certificate owner
    * @param issuingKP key pair for signing authority (e.g. Great DANE Connector's keys)
    * @param issuingDN Distinguished Name of signing authority
    * @param ca whether to create a Certificate Authority certificate
    * @return new X.509 S/MIME certificate
    */
  def makeCertificate(subjectKP: KeyPair, subjectEmail: String,
                      issuingKP: KeyPair, issuingDN: String,
                      ca: Boolean = false): X509Certificate = {
    val subPub = subjectKP.getPublic
    val issPriv = issuingKP.getPrivate
    val issPub = issuingKP.getPublic

    // Note: we set Subject: emailAddress=<email> for backwards compatibility
    // The correct place to set the email address is in the Subject Alternative Name extension
    val v3CertGen = new JcaX509v3CertificateBuilder(
      new X500Name(issuingDN),
      SerialNumber(),
      new Date(System.currentTimeMillis()),
      new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * expiryDays)),
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

}

object CertificateGenerator {
  private val Srand = new SecureRandom()

  private val ExtUtils = new X509ExtensionUtils(new SHA1DigestCalculator)

  // TODO: not guaranteed to be unique
  def SerialNumber(): BigInteger = BigInteger.probablePrime(20*8, Srand)

  private def createSubjectKeyId(pubKey: SubjectPublicKeyInfo): SubjectKeyIdentifier =
    ExtUtils.createSubjectKeyIdentifier(pubKey)

  private def createSubjectKeyId(pubKey: PublicKey): SubjectKeyIdentifier =
    ExtUtils.createSubjectKeyIdentifier(SubjectPublicKeyInfo.getInstance(pubKey.getEncoded))

  private def createAuthorityKeyId(pubKey: PublicKey): AuthorityKeyIdentifier =
    ExtUtils.createAuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(pubKey.getEncoded))

  def Default: Option[CertificateGenerator] = {
    Settings.Generator.map { gen =>
      val identity = FilesystemIdentityLoader.loadIdentity(gen.signingKey, gen.signingCert)
      new CertificateGenerator(gen.keyAlgo, gen.keyBits, gen.signingAlgo, gen.expiryDays, Some(identity))
    }
  }

  def main(args: Array[String]): Unit = {
    if (args.length < 1) {
      println("usage: make-cert <email address>")
      sys.exit(1)
    }

    val email = args(0)
    Default.fold(println("Certificate generation not enabled!")) { generator =>
      val (key, cert) = generator.makeKeyAndCertificate(email)
      println(Converters.toPem(cert))
      println(Converters.toPem(key))
    }
  }
}

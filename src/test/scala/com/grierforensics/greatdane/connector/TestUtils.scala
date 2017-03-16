// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane.connector

import java.security.cert.X509Certificate

import com.grierforensics.greatdane.connector.dns.InMemoryZone
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.{BCStyle, IETFUtils}
import org.bouncycastle.asn1.x509.{GeneralName, KeyPurposeId}

object TestUtils {

  object Values {
    val testOrigin = "example.com"
    val testAddress = "foo@example.com"
    // TODO: create a static certificate instead of dynamically creating one every time tests are run
    val (testKey, testCert) = CertificateGenerator.makeKeyAndCertificate(testAddress)
    val (testKeyPem, testCertPem) = (Converters.toPem(testKey), Converters.toPem(testCert))
  }

  def makeTestConnector: Connector = new Connector(Seq(new InMemoryZone(Values.testOrigin)))

  def issuerDN(cert: X509Certificate): String = cert.getIssuerDN.toString

  def subjectDN(cert: X509Certificate): String = cert.getSubjectDN.getName

  def emailAddress(cert: X509Certificate): String = {
    val e = new X500Name(subjectDN(cert)).getRDNs(BCStyle.EmailAddress)(0)
    IETFUtils.valueToString(e.getFirst.getValue)
  }

  def subjectAlternativeNameEmail(cert: X509Certificate): Option[String] = {
    // See java.security.cert.X509Certificate.getSubjectAlternativeNames documentation for
    // notes on decoding the Subject Alternative Names
    import scala.collection.JavaConverters._
    val altnames: Iterable[List[Any]] = cert.getSubjectAlternativeNames.asScala map { l => l.asScala.toList }
    var emailFound = false
    val found = altnames.flatMap { alt =>
      alt.head.asInstanceOf[Int] match {
        case GeneralName.rfc822Name =>
          Some(alt(1).asInstanceOf[String])
        case _ => None
      }
    }

    found.headOption
  }

  def smimeKeyUsage(cert: X509Certificate): Boolean = {
    // Key Usage: Digital Signature (0) and Key Encipherment (2) only
    val keyUsage = cert.getKeyUsage
    keyUsage.take(9).deep == Array(true, false, true, false, false, false, false, false, false).deep
  }

  def smimeExtendedKeyUsage(cert: X509Certificate): Boolean = {
    // Extended Key Usage: Email Protection only
    import scala.collection.JavaConverters._
    val extendedUsage = cert.getExtendedKeyUsage.asScala.toList
    extendedUsage.length == 1 &&
    extendedUsage.head == KeyPurposeId.id_kp_emailProtection.toString
  }

  def isCA(cert: X509Certificate): Boolean = cert.getBasicConstraints >= 0

  def isValidSmime(email: String, cert: X509Certificate): Boolean = {
    emailAddress(cert) == email &&
      subjectAlternativeNameEmail(cert).getOrElse("") == email &&
      smimeKeyUsage(cert) &&
      smimeExtendedKeyUsage(cert) &&
      !isCA(cert)
  }


}

// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane.connector

import java.security.PrivateKey
import java.security.cert.X509Certificate

import com.grierforensics.greatdane.connector.dns.{DnsZone, DnsZoneFileWriter, InMemoryZone}
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.dane.{DANEEntry, DANEEntryFactory, DANEEntrySelectorFactory, TruncatingDigestCalculator}
import org.bouncycastle.operator.DigestCalculator
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.xbill.DNS._

case class DnsParams(name: String, certificateUsage: Int, selector: Int, matchingType: Int, certificateData: String)

case class GeneratedData(rrecords: Seq[Record], privKey: Option[PrivateKey], cert: Option[X509Certificate]) {
  def pemKey: String = privKey.map(Converters.toPem(_)).getOrElse("")
  def pemCert: String = cert.map(Converters.toPem(_)).getOrElse("")
  def records: Seq[String] = rrecords.map(_.toString)
}

case class EmailAddressNotFoundException(emailAddress: String) extends Exception(s"Email address not found: $emailAddress")
case class DomainNotFoundException(address: String) extends Exception(s"Invalid domain: $address")
case object CertificateGenerationDisabledException extends Exception("Certificate generation not enabled")

/** Connector adds and removes SMIMEA records from its configured Zone
  *
  * @param zone Zone maintained by this Connector
  * @param certificateGenerator Optionally used to generate S/MIME certificates for new users
  */
class Connector(zone: DnsZone, certificateGenerator: Option[CertificateGenerator]) {

  /** Generates an SMIMEA record for `emailAddress` for each certificate.
    *
    * If no certificates are specified, a private key and certificate is generated for `emailAddress`
    *
    * @param emailAddress User's email address
    * @param certificates Existing S/MIME certificates for the user
    * @return Generated records, and optionally generated private key and certificate
    */
  def generateRecords(emailAddress: String, certificates: Seq[String]): GeneratedData = {
    if (!validEmailAddress(emailAddress)) {
      throw DomainNotFoundException(emailAddress)
    }

    def genRecords(certs: Seq[X509Certificate]): Seq[Record] = certs.map(c => genSmimeaRecord(emailAddress, Some(c)))

    if (certificates.isEmpty) {
      val (privKey, cert) = certificateGenerator
        .getOrElse(throw CertificateGenerationDisabledException)
        .makeKeyAndCertificate(emailAddress)
      val records = genRecords(Seq(cert))
      GeneratedData(records, Some(privKey), Some(cert))
    } else {
      val records = genRecords(certificates.map(Converters.fromPem))
      GeneratedData(records, None, None)
    }
  }

  /** Generates SMIMEA record for `emailAddress` for each certificate and adds record to the Zone
    *
    * @param emailAddress User's email address
    * @param certificates Existing S/MIME certificates for the user
    * @return Generated records, and optionally generated private key and certificate
    */
  def provisionUser(emailAddress: String, certificates: Seq[String]): GeneratedData = {
    val generated = generateRecords(emailAddress, certificates)
    zone.addRecords(generated.rrecords)
    generated
  }

  /** Removes all SMIMEA records for `emailAddress` from the Zone
    *
    * @param emailAddress User's email address
    */
  def deprovisionUser(emailAddress: String): Unit = {
    if (!validEmailAddress(emailAddress)) {
      throw DomainNotFoundException(emailAddress)
    }
    val rr = genSmimeaRecord(emailAddress, None)
    zone.removeRecords(rr.getName.toString).orElse(throw EmailAddressNotFoundException(emailAddress))
  }

  private val truncatingDigestCalculator: DigestCalculator = {
    // Sample usage: https://github.com/bcgit/bc-java/blob/master/pkix/src/test/java/org/bouncycastle/cert/test/DANETest.java
    val digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider(Settings.SecurityProvider).build()
    val sha256DigestCalculator = digestCalculatorProvider.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256))
    new TruncatingDigestCalculator(sha256DigestCalculator)
  }

  private val selectorFactory = new DANEEntrySelectorFactory(truncatingDigestCalculator)
  private val entryFactory = new DANEEntryFactory(truncatingDigestCalculator)

  private def createEntry(emailAddress: String, encodedCertificate: Array[Byte]): DANEEntry = {
    // TODO: support different certificate usages
    entryFactory.createEntry(emailAddress, new X509CertificateHolder(encodedCertificate))
  }

  private def createEntry(emailAddress: String, certificate: X509Certificate): DANEEntry = {
    createEntry(emailAddress, certificate.getEncoded)
  }

  private def emailDomain(emailAddress: String): String = {
    val start = emailAddress.lastIndexOf('@') + 1
    if (start == 0) {
      throw new IllegalArgumentException("invalid email address")
    }
    emailAddress.substring(start)
  }

  private def validEmailAddress(emailAddress: String): Boolean = zone.origin == s"_smimecert.${emailDomain(emailAddress)}"

  private def genSmimeaRecord(emailAddress: String, certificate: Option[X509Certificate]): Record = {
    val (domain, rdata) = certificate match {
      case Some(cert) =>
        val entry = createEntry(emailAddress, cert)
        (entry.getDomainName, entry.getRDATA)
      case None =>
        val selector = selectorFactory.createSelector(emailAddress)
        (selector.getDomainName, Array[Byte](3, 0, 0))
    }

    new SMIMEARecord(
      // TODO: better way to create absolute name?
      new Name(domain + '.'),
      DClass.IN, Settings.Zone.ttl, rdata(0), rdata(1), rdata(2), rdata.drop(3)
    )
  }
}

object Connector {
  //def fromHex(s: String): Array[Byte] = Hex.decode(s)

  val zone: DnsZone = {
    val z = Settings.Zone
    val zone = new InMemoryZone(z.origin)
    new Thread() {
      val writer = new DnsZoneFileWriter(zone, z.baseFile, z.outFile)
      override def run(): Unit = {
        while (true) {
          writer.writeZoneFile()
          Thread.sleep(z.writePeriod)
        }
      }
    }.start()
    zone
  }

  def Default: Connector = new Connector(zone, CertificateGenerator.Default)
}

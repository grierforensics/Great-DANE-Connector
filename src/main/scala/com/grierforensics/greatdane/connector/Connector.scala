// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane.connector

import java.security.PrivateKey
import java.security.cert.X509Certificate

import com.grierforensics.greatdane.connector.dns.{DnsZone, InMemoryZone}
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.dane.{DANEEntry, DANEEntryFactory, DANEEntrySelectorFactory, TruncatingDigestCalculator}
import org.bouncycastle.operator.DigestCalculator
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.xbill.DNS._

case class DnsParams(name: String, certificateUsage: Int, selector: Int, matchingType: Int, certificateData: String)

case class ProvisionedUser(rrecords: Seq[Record], privKey: Option[PrivateKey], cert: Option[X509Certificate]) {
  def pemKey: String = privKey.map(Converters.toPem(_)).getOrElse("")
  def pemCert: String = cert.map(Converters.toPem(_)).getOrElse("")
  def records: Seq[String] = rrecords.map(_.toString)
}

case class EmailAddressNotFoundException(emailAddress: String) extends Exception(s"Email address not found: $emailAddress")
case class DomainNotFoundException(domain: String) extends Exception(s"Invalid domain: $domain")

class Connector(dns: Seq[DnsZone]) {
  def this(dns: DnsZone) = this(Seq(dns))

  import scala.collection.immutable.HashMap
  val zones = HashMap(dns.map(z => (z.origin, z)):_*)

  def provisionUser(emailAddress: String, certificates: Seq[String]): ProvisionedUser = {
    val domain = emailDomain(emailAddress)
    val zone = zones.getOrElse(domain, throw DomainNotFoundException(domain))

    def addRecords(certs: Seq[X509Certificate]): Seq[Record] = {
      val rrecords: Seq[Record] = certs map { cert =>
        smimeaRecord(emailAddress, Some(cert))
      }

      zone.addRecords(rrecords)
      rrecords
    }

    if (certificates.isEmpty) {
      val (privKey, cert) = CertificateGenerator.makeKeyAndCertificate(emailAddress)
      val records = addRecords(Seq(cert))
      ProvisionedUser(records, Some(privKey), Some(cert))
    } else {
      val records = addRecords(certificates.map(Converters.fromPem))
      ProvisionedUser(records, None, None)
    }
  }

  def deprovisionUser(emailAddress: String): Unit = {
    val domain = emailDomain(emailAddress)
    val zone = zones.getOrElse(domain, throw DomainNotFoundException(domain))
    val rr = smimeaRecord(emailAddress, None)
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

  def smimeaRecord(emailAddress: String, certificate: Option[X509Certificate]): SMIMEARecord = {
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
      DClass.IN, TTL.MAX_VALUE, rdata(0), rdata(1), rdata(2), rdata.drop(3)
    )
  }
}

object Connector {
  //def fromHex(s: String): Array[Byte] = Hex.decode(s)

  def Default: Connector = new Connector(Settings.Zones.map(z => new InMemoryZone(z.origin)))
}

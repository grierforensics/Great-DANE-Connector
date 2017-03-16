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
import org.bouncycastle.util.encoders.Hex
import org.xbill.DNS._

case class DnsParams(name: String, certificateUsage: Int, selector: Int, matchingType: Int, certificateData: String)

case class KeyAndCert(privKey: PrivateKey, cert: X509Certificate) {
  def pemKey: String = Converters.toPem(privKey)
  def pemCert: String = Converters.toPem(cert)
}

case class EmailAddressNotFoundException(emailAddress: String) extends Exception(s"Email address not found: $emailAddress")
case class DomainNotFoundException(domain: String) extends Exception(s"Invalid domain: $domain")

class Connector(dns: Seq[DnsZone]) {
  def this(dns: DnsZone) = this(Seq(dns))

  import scala.collection.immutable.HashMap
  val zones = HashMap(dns.map(z => (z.origin, z)):_*)

  def provisionUser(emailAddress: String, certificates: Seq[String]): Option[KeyAndCert] = {
    provisionUserX509(emailAddress, certificates.map(Converters.fromPem))
  }

  def provisionUserX509(emailAddress: String, certificates: Seq[X509Certificate]): Option[KeyAndCert] = {
    val domain = emailDomain(emailAddress)
    val zone = zones.getOrElse(domain, throw DomainNotFoundException(domain))

    def addRecords(certs: Seq[X509Certificate]): Unit = {
      val rrecords: Seq[Record] = certs map { cert =>
        val entry = createEntry(emailAddress, cert)

        val rdata = entry.getRDATA

        new SMIMEARecord(
          // TODO: better way to create absolute name?
          new Name(entry.getDomainName + '.'),
          DClass.IN, TTL.MAX_VALUE, rdata(0), rdata(1), rdata(2), rdata.drop(3)
        )
      }

      zone.addRecords(rrecords)
    }

    if (certificates.isEmpty) {
      val (privKey, cert) = CertificateGenerator.makeKeyAndCertificate(emailAddress)
      addRecords(Seq(cert))
      Some(KeyAndCert(privKey, cert))
    } else {
      addRecords(certificates)
      None
    }
  }

  def deprovisionUser(emailAddress: String): Unit = {
    val selector = selectorFactory.createSelector(emailAddress)
    val domain = emailDomain(emailAddress)
    val zone = zones.getOrElse(domain, throw DomainNotFoundException(domain))
    val rr = new SMIMEARecord(new Name(selector.getDomainName + '.'), DClass.IN, TTL.MAX_VALUE, 3, 0, 0, Array())

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
}

object Connector {
  //def fromHex(s: String): Array[Byte] = Hex.decode(s)

  def Default: Connector = new Connector(Settings.Zones.map(new InMemoryZone(_)))

}

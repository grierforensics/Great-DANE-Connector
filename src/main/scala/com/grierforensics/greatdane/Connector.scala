// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane

import java.net.{URI, URL}
import java.security.cert.X509Certificate

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.scala.DefaultScalaModule
import org.apache.http.HttpHeaders
import org.apache.http.client.methods.{HttpGet, HttpPost}
import org.apache.http.entity.StringEntity
import org.apache.http.impl.client.HttpClients
import org.apache.http.util.EntityUtils
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.dane.{DANEEntry, DANEEntryFactory, TruncatingDigestCalculator}
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.bouncycastle.util.encoders.Hex
import org.xbill.DNS._

case class DnsParams(name: String, certificateUsage: Int, selector: Int, matchingType: Int, certificateData: String)

// TODO: change engineHost/Port to an engine URL
class Connector(engineHost: String, enginePort: Int) {

  val mapper = new ObjectMapper().registerModule(DefaultScalaModule)

  val engineUri = new URI("http", null, engineHost, enginePort, null, null, null)

  val dnsModifier: DnsModifier = new InMemoryDns

  def provisionUser(emailAddress: String, certificates: Seq[String]): (Option[String], Option[String]) = {
    val domain = emailDomain(emailAddress)

    def addRecord(certs: Seq[X509Certificate]): Unit = {
      val rrecords: Seq[Record] = certs map { cert =>
        val entry = createEntry(emailAddress, cert)

        val rdata = entry.getRDATA

        new SMIMEARecord(
          // TODO: better way to create absolute name?
          new Name(entry.getDomainName + '.'),
          DClass.IN, TTL.MAX_VALUE, rdata(0), rdata(1), rdata(2), rdata.drop(3)
        )
      }

      dnsModifier.addRecords(domain, rrecords)
    }

    if (certificates.isEmpty) {
      val (privKey, cert) = CertificateGenerator.makeKeyAndCertificate(emailAddress)
      addRecord(Seq(cert))
      (Some(CertificateGenerator.toPem(privKey)), Some(CertificateGenerator.toPem(cert)))
    } else {
      addRecord(certificates.map(CertificateGenerator.fromPem))
      (None, None)
    }
  }

  val TruncatingDigestCalculator = {
    // Sample usage: https://github.com/bcgit/bc-java/blob/master/pkix/src/test/java/org/bouncycastle/cert/test/DANETest.java
    val digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder().setProvider(CertificateGenerator.Provider).build()
    val sha256DigestCalculator = digestCalculatorProvider.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256))
    new TruncatingDigestCalculator(sha256DigestCalculator)
  }

  val EntryFactory = new DANEEntryFactory(TruncatingDigestCalculator)

  private def createEntry(emailAddress: String, encodedCertificate: Array[Byte]): DANEEntry = {
    EntryFactory.createEntry(emailAddress, new X509CertificateHolder(encodedCertificate))
  }

  private def createEntry(emailAddress: String, certificate: X509Certificate): DANEEntry = {
    createEntry(emailAddress, certificate.getEncoded)
  }

  def deprovisionUser(emailAddress: String): Option[Seq[String]] = {
    Some(Seq())
  }


  def emailDomain(emailAddress: String): String = {
    val start = emailAddress.lastIndexOf('@') + 1
    if (start == 0) {
      throw new IllegalArgumentException("invalid email address")
    }
    emailAddress.substring(start)
  }
}

object Connector {
  def fromHex(s: String): Array[Byte] = Hex.decode(s)
}

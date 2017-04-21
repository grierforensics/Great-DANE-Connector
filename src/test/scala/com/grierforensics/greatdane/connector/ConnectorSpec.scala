// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane.connector

import com.grierforensics.greatdane.connector.dns.DnsZone
import org.scalatest.FlatSpec
import org.xbill.DNS.{Record, SMIMEARecord}

class ConnectorSpec extends FlatSpec {
  import TestUtils.Values._

  "A Connector" should "return None for key and cert if certificate(s) are specified" in {
    val connector = TestUtils.makeTestConnector
    val user = connector.provisionUser(testAddress, Seq(testCertPem))

    assert(user.privKey.isEmpty)
    assert(user.cert.isEmpty)
  }

  it should "return a key and cert if certificate(s) are not specified" in {
    val connector = TestUtils.makeTestConnector
    val provisionedUser = connector.provisionUser(testAddress, Seq())

    assert(TestUtils.isValidSmime(testAddress, provisionedUser.cert.get))
  }

  it should "add to DNS valid SMIMEA record(s) for the given email address in provisionUser" in {
    val dns = new DnsZone {
      var lastRecord: Record = _
      override def origin = testOrigin
      override def addRecord(record: Record): Unit = lastRecord = record
      override def removeRecords(name: String): Option[Set[Record]] = {
        val s = Set(lastRecord)
        lastRecord = null
        Some(s)
      }
      override def records = Seq(lastRecord)
    }

    val connector = new Connector(TestUtils.makeCertGenerator, dns)
    connector.provisionUser(testAddress, Seq(testCertPem))

    val record = dns.lastRecord
    assert(record != null)
    assert(record.getType == org.xbill.DNS.Type.SMIMEA)
    val smimea = record.asInstanceOf[SMIMEARecord]
    assert(smimea.getCertificateAssociationData.deep == testCert.getEncoded.deep)
  }

  it should "remove from DNS all SMIMEA record(s) for the given email address in deprovisionUser" in {
    // TODO: test removal of more than one record!
    val dns = new DnsZone {
      import scala.collection.mutable
      val rrecords = new mutable.HashMap[String, mutable.Set[Record]] with mutable.MultiMap[String, Record]
      override def origin: String = testOrigin
      override def addRecord(record: Record): Unit = {
        rrecords.addBinding(record.getName.toString, record)
      }
      override def removeRecords(name: String): Option[Set[Record]] = {
        rrecords.remove(name).map(_.toSet)
      }
      override def records: Seq[Record] = rrecords.values.flatten.toSeq
    }

    val connector = new Connector(TestUtils.makeCertGenerator, dns)
    connector.provisionUser(testAddress, Seq(testCertPem))

    val name = dns.rrecords.keys.head
    val preRecords = dns.rrecords.get(name)
    assert(preRecords.isDefined && preRecords.get.size > 0)

    connector.deprovisionUser(testAddress)

    val postRecords = dns.rrecords.get(name)
    assert(postRecords.isEmpty)
  }

  it should "throw DomainNotFoundException if the email domain is not a valid zone" in {
    val connector = TestUtils.makeTestConnector
    val email = testAddress.replace("com", "net")

    intercept[DomainNotFoundException] {
      connector.provisionUser(email, Seq())
    }

    intercept[DomainNotFoundException] {
      connector.deprovisionUser(email)
    }
  }

  it should "return EmailNotFoundException in deprovisionUser if the email address is not found in DNS" in {
    val connector = new Connector(TestUtils.makeCertGenerator, new DnsZone {
      override def addRecord(record: Record) = ???
      override def removeRecords(name: String) = None
      override def origin: String = testOrigin
      override def records = Seq()
    })

    intercept[EmailAddressNotFoundException] {
      connector.deprovisionUser(testAddress)
    }
  }
}

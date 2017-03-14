// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane

import java.net.{URI, URL}

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.scala.DefaultScalaModule
import org.apache.http.HttpHeaders
import org.apache.http.client.methods.{HttpGet, HttpPost}
import org.apache.http.entity.StringEntity
import org.apache.http.impl.client.HttpClients
import org.apache.http.util.EntityUtils
import org.bouncycastle.util.encoders.Hex
import org.xbill.DNS.{DClass, Name, SMIMEARecord, TTL}

case class DnsParams(name: String, certificateUsage: Int, selector: Int, matchingType: Int, certificateData: String)

// TODO: change engineHost/Port to an engine URL
class Connector(engineHost: String, enginePort: Int) {

  val mapper = new ObjectMapper().registerModule(DefaultScalaModule)

  val engineUri = new URI("http", null, engineHost, enginePort, null, null, null)

  val dnsModifier: DnsModifier = new InMemoryDns

  def provisionUser(emailAddress: String, certificates: Seq[String]): Unit = {
    val domain = {
      val start = emailAddress.lastIndexOf('@') + 1
      if (start == 0) {
        throw new IllegalArgumentException("invalid email address")
      }
      emailAddress.substring(start)
    }

    val client = HttpClients.createDefault()
    val uri = engineUri.resolve(s"/$emailAddress/dnsParams")

    val records = certificates.map { cert =>
      val req = new HttpPost(uri)
      req.addHeader(HttpHeaders.CONTENT_TYPE, "text/plain")
      req.addHeader(HttpHeaders.ACCEPT, "application/json")
      req.setEntity(new StringEntity(cert))

      val resp = client.execute(req)
      val params = try {
        if (resp.getStatusLine.getStatusCode != 200) {
          throw new RuntimeException("Engine unavailable!")
        }
        val entity = resp.getEntity

        val params = mapper.readValue(entity.getContent, classOf[DnsParams])

        EntityUtils.consumeQuietly(entity)

        params

      } finally {
        resp.close()
      }

      new SMIMEARecord(
        new Name(params.name), DClass.IN, TTL.MAX_VALUE, params.certificateUsage, params.selector, params.matchingType, Hex.decode(params.certificateData)
      )
    }

    //dnsModifier.addRecords(records)
  }

  def deprovisionUser(emailAddress: String): Option[Seq[String]] = {
    Some(Seq())
  }

}

object Connector {
  def fromHex(s: String): Array[Byte] = Hex.decode(s)
}

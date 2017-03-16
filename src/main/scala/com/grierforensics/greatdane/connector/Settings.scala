// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane.connector

import java.security.Security

import com.typesafe.config.ConfigFactory
import org.bouncycastle.jce.provider.BouncyCastleProvider

object Settings {
  import scala.collection.JavaConverters._

  private val config = {
    val cfg = ConfigFactory.load()
    cfg.getConfig("com.grierforensics.greatdane.connector")
  }

  // This must occur once, so this is a logical place to do it
  val SecurityProvider = new BouncyCastleProvider
  Security.addProvider(SecurityProvider)


  val Port: Int = config.getInt("port")
  val ApiKey: String = config.getString("apiKey")

  case class ZoneFileDetails(origin: String, baseFile: String, outFile: String, writePeriod: Int)

  val Zones: Seq[ZoneFileDetails] = config.getConfigList("zoneFiles").asScala.map { obj =>
    ZoneFileDetails(
      obj.getString("origin"),
      obj.getString("baseFile"),
      obj.getString("outFile"),
      obj.getInt("writePeriod")
    )
  }

  val DnsServers: Seq[String] = config.getStringList("dns").asScala


  val DistinguishedName: String = "C=US,ST=Maryland,L=Baltimore,O=Grier Forensics,CN=Great DANE Connector"
  val CertificateExpiryDays: Int = 365
}

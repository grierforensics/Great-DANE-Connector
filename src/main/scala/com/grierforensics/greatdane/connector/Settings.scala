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

  val Host: String = config.getString("host")
  val Port: Int = config.getInt("port")
  val ApiKey: String = config.getString("apiKey")

  case class ZoneFileDetails(origin: String, baseFile: String, outFile: String,
                             ttl: Long, writePeriod: Int)

  val Zone = ZoneFileDetails(
    config.getString("zone.origin"),
    config.getString("zone.basefile"),
    config.getString("zone.outfile"),
    config.getLong("zone.ttl"),
    config.getInt("zone.write.period")
  )

  case class GeneratorDetails(keyAlgo: String, keyBits: Int, signingKey: String,
                              signingCert: String, signingAlgo: String, expiryDays: Int)

  private val certs = config.getConfig("certificates")
  val Generator: Option[GeneratorDetails] = if (certs.getBoolean("generate")) {
    Some(
      GeneratorDetails(
        certs.getString("key.algorithm"),
        certs.getInt("key.bits"),

        certs.getString("signing.key"),
        certs.getString("signing.certificate"),
        certs.getString("signing.algorithm"),

        certs.getInt("expiry.days")
      )
    )
  } else {
    None
  }
}

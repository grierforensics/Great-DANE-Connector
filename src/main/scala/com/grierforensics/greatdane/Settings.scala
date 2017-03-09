// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane

import com.typesafe.config.ConfigFactory

object Settings {
  import scala.collection.JavaConverters._

  val config = {
    val cfg = ConfigFactory.load()
    cfg.getConfig("com.grierforensics.greatdane.connector")
  }

  object Default {
    val Port = config.getInt("port")
    val EngineHost = config.getString("engine.host")
    val EnginePort = config.getInt("engine.port")
    val ApiKey = config.getString("apiKey")
    val DnsServers = config.getStringList("dns").asScala
  }
}

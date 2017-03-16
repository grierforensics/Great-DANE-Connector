// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane.connector.dns

import org.xbill.DNS.Record

class InMemoryZone extends DnsZone {
  //type Zone = mutable.ArrayBuffer[Record]
  //val zones = new mutable.HashMap[String, Zone]()

  import scala.collection.mutable.{HashMap, MultiMap, Set}
  val zones = new HashMap[String, Set[Record]] with MultiMap[String, Record]

  override def addRecord(zone: String, record: Record): Unit = {
    println(s"Added DNS record: ${record.toString}")
    zones.addBinding(zone, record)
  }

  override def removeRecords(zone: String, name: String): Unit = {
    zones.get(zone).map { rs =>
      val cleaned = rs.filter(_.getName.toString == name)
      zones.put(zone, cleaned)
    }
  }
}

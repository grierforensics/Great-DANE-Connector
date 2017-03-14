// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane

import scala.collection.mutable

class InMemoryDns extends DnsModifier {
  type Zone = mutable.ArrayBuffer[DnsRecord]
  val zones = new mutable.HashMap[String, Zone]()

  override def createZone(zone: String): Unit = zones.put(zone, new Zone)

  override def removeZone(zone: String): Unit = zones.remove(zone)

  override def addRecord(zone: String, record: DnsRecord): Unit = zones.get(zone).foreach(_.append(record))

  override def removeRecords(zone: String, name: String): Unit = {}//zones.get(zone).
}

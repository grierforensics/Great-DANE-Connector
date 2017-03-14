// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane

class ZoneFileWriter extends DnsModifier {
  override def createZone(zone: String): Unit = ???

  override def removeZone(zone: String): Unit = ???

  override def addRecord(zone: String, record: DnsRecord): Unit = ???

  override def removeRecords(zone: String, name: String): Unit = ???
}

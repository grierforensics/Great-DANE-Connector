// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane

import org.xbill.DNS.Record

class ZoneFileWriter extends DnsModifier {
  override def createZone(zone: String): Unit = ???

  override def removeZone(zone: String): Unit = ???

  override def addRecord(zone: String, record: Record): Unit = ???

  override def removeRecords(zone: String, name: String): Unit = ???
}

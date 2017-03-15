// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane

import org.xbill.DNS.Record

trait DnsModifier {
  def createZone(zone: String): Unit
  def removeZone(zone: String): Unit
  def addRecord(zone: String, record: Record): Unit
  def addRecords(zone: String, records: Seq[Record]): Unit = records.foreach(addRecord(zone, _))
  def removeRecords(zone: String, name: String): Unit
}

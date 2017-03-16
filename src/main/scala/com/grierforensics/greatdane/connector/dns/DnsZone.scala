// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane.connector.dns

import org.xbill.DNS.Record

trait DnsZone {
  def origin: String
  def addRecord(record: Record): Unit
  def addRecords(records: Seq[Record]): Unit = records.foreach(addRecord)
  def removeRecords(name: String): Option[Set[Record]]
  def records: Seq[Record]
}

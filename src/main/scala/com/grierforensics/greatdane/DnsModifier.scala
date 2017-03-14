// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane

trait DnsRecord {

  def name: String
  def rrtype: String
  def ttl: Int = -1
  def content: String
  // def content: Array[Byte]
}

trait DnsModifier {
  def createZone(zone: String)
  def removeZone(zone: String)
  def addRecord(zone: String, record: DnsRecord)
  def removeRecords(zone: String, name: String)
}

// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane.connector.dns

import org.xbill.DNS.Record

class ZoneFileWriter extends DnsZone {

  override def addRecord(zone: String, record: Record): Unit = ???

  override def removeRecords(zone: String, name: String): Unit = ???
}

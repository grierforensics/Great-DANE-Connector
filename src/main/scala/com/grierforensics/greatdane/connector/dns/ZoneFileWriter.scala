// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane.connector.dns

import org.xbill.DNS.Record

class ZoneFileWriter(override val origin: String) extends DnsZone {

  override def addRecord(record: Record): Unit = ???

  override def removeRecords(name: String): Option[Set[Record]] = ???
}

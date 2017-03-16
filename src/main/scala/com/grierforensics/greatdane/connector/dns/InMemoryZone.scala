// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane.connector.dns

import org.xbill.DNS.Record

class InMemoryZone(override val origin: String) extends DnsZone {
  import scala.collection.mutable
  val records = new mutable.HashMap[String, mutable.Set[Record]] with mutable.MultiMap[String, Record]

  override def addRecord(record: Record): Unit = {
    //println(s"Added DNS record: ${record.toString}")
    records.addBinding(record.getName.toString, record)
  }

  override def removeRecords(name: String): Option[Set[Record]] = {
    records.remove(name).map(_.toSet)
  }
}

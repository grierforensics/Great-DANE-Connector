// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane.connector.dns

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths}

import org.xbill.DNS.{Name, Record, Zone}

class InMemoryZone(override val origin: String) extends DnsZone {
  import scala.collection.mutable
  val rrecords = new mutable.HashMap[String, mutable.Set[Record]] with mutable.MultiMap[String, Record]

  override def addRecord(record: Record): Unit = {
    //println(s"Added DNS record: ${record.toString}")
    rrecords.addBinding(record.getName.toString, record)
  }

  override def removeRecords(name: String): Option[Set[Record]] = {
    rrecords.remove(name).map(_.toSet)
  }

  override def records: Seq[Record] = rrecords.values.flatten.toSeq
}

class DnsZoneFileWriter(zone: InMemoryZone, baseZoneFilePath: String, outZoneFilePath: String) {
  def writeZoneFile(): Unit = {
    // TODO: load once and re-use
    val origin = Name.fromString(zone.origin + ".")
    val zoneFile = new Zone(origin, baseZoneFilePath)
    // TODO: track whether changes have occurred to minimize work!
    zone.records.foreach { r =>
      zoneFile.addRecord(r)
    }
    Files.write(Paths.get(outZoneFilePath), zoneFile.toMasterFile.getBytes(StandardCharsets.UTF_8))
  }
}

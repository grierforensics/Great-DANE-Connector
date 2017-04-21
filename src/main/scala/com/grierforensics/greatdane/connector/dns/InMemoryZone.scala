// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane.connector.dns

import java.nio.file.{Files, Paths}

import org.xbill.DNS._

class InMemoryZone(override val origin: String) extends DnsZone {
  import scala.collection.mutable
  val rrecords = new mutable.HashMap[String, mutable.Set[Record]] with mutable.MultiMap[String, Record]

  override def addRecord(record: Record): Unit = {
    //println(s"Added DNS record: ${record.toString}")
    rrecords.addBinding(record.getName.toString, record)
  }

  override def removeRecords(name: String): Option[Set[Record]] = {
    //rrecords.remove(name).map(_.toSet)
    rrecords.remove(name).map { s =>
      val set = s.toSet
      //      set foreach { record =>
      //        println(s"Removing DNS record: ${record.toString}")
      //      }
      set
    }
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

    // `zoneFile.toMasterFile` writes "proper" SMIMEA records, but we need UNKNOWN-type records
    // for compatibility with older DNS servers (e.g. Bind and PowerDNS on CentOS 7) (at least for now)
    //Files.write(Paths.get(outZoneFilePath), zoneFile.toMasterFile.getBytes(StandardCharsets.UTF_8))


    // Borrowed from dnsjava Record
    def unknownToString(data: Array[Byte]): String = {
      val sb = new StringBuffer()
      sb.append("\\# ")
      sb.append(data.length)
      sb.append(" ")
      sb.append(org.xbill.DNS.utils.base16.toString(data))
      sb.toString
    }

    // Borrowed from dnsjava Record `toString`
    def smimeaToString(record: SMIMEARecord): String = {
      val sb = new StringBuffer
      sb.append(record.getName)
      if (sb.length() < 8)
        sb.append("\t")
      if (sb.length() < 16)
        sb.append("\t")
      sb.append("\t")
      if (Options.check("BINDTTL"))
        sb.append(TTL.format(record.getTTL))
      else
        sb.append(record.getTTL)
      sb.append("\t")
      if (record.getDClass != DClass.IN || !Options.check("noPrintIN")) {
        sb.append(DClass.string(record.getDClass))
        sb.append("\t");
      }
      sb.append(s"TYPE${record.getType}")
      val rdata = unknownToString(record.rdataToWireCanonical())
      if (!rdata.equals("")) {
        sb.append("\t")
        sb.append(rdata)
      }
      sb.toString
    }

    val out = Files.newBufferedWriter(Paths.get(outZoneFilePath))
    try {
      import scala.collection.JavaConverters._
      for (entry <- zoneFile.iterator.asScala) {
        val rrset = entry.asInstanceOf[RRset]
        for (rr <- rrset.rrs().asScala) {
          val line: String = rr.asInstanceOf[Record] match {
            case record: SMIMEARecord => smimeaToString(record)
            case record: Record => record.toString
          }
          out.write(line + "\n")
        }
      }
    } finally {
      out.close()
    }
  }
}

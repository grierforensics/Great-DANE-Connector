// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane

import org.xbill.DNS._

object ZoneTest {

  def main(args: Array[String]): Unit = {

    val Dclass = DClass.IN
    val ZoneName = Name.fromString("example.com.")
    val NameServer1 = Name.fromString("ns1.example.com.")
    val NameServer2 = Name.fromString("ns2.example.com.")
    val AdminServer = Name.fromString("admin.example.com.")
    val MailServer = Name.fromString("mail.example.com.")
    val SmimeaDomain = Name.fromString("2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e88._smimecert.example.com.")
    val Serial = 1234567890
    val Refresh = 30
    val Retry = 30
    val Expire = 1209600
    val DefaultTtl = 3600
    val MinimumTtl = 30

    val soa = new SOARecord(ZoneName, Dclass, DefaultTtl, NameServer1, AdminServer, Serial, Refresh, Retry, Expire, MinimumTtl)

    val ns1 = new NSRecord(ZoneName, Dclass, 0, NameServer1)
    val ns2 = new NSRecord(ZoneName, Dclass, DefaultTtl, NameServer2)

    val mx = new MXRecord(ZoneName, Dclass, DefaultTtl, 10, MailServer)

    val smimea = new SMIMEARecord(SmimeaDomain, Dclass, DefaultTtl, 3, 0, 0, (1 to 15).map(_.toByte).toArray)
    println(smimea)

    //val zone = new Zone(ZoneName, Array[Record](soa, ns1, ns2, mx, smimea))
    val zone = new Zone(ZoneName, Array[Record](soa, ns1, smimea))
    println(zone.getOrigin)

    val rr = new RRset()

    println(zone.toMasterFile)
  }

}

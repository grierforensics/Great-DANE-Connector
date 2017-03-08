// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane

import java.util
import javax.ws.rs._
import javax.ws.rs.core.MediaType

@Path("/api/v1/")
@Consumes(Array(MediaType.APPLICATION_JSON))
@Produces(Array(MediaType.APPLICATION_JSON))
class Resource(connector: Connector) {
  @POST
  @Path("/user/{email}")
  def provisionUser(@PathParam("email") emailAddress: String): util.ArrayList[String] = {
    connector.provisionUser(emailAddress, Seq())

    // Test JSON serialization
    val al = new util.ArrayList[String]()
    al.add("hello")
    al.add("world")
    al
  }

  @DELETE
  @Path("/user/{email}")
  def deprovisionUser(@PathParam("email") emailAddress: String): Unit = {
    connector.deprovisionUser(emailAddress)
  }

  @PUT
  @Path("/user/{email}")
  def modifyUser(@PathParam("email") emailAddress: String): Unit = {

  }

  @DELETE
  @Path("/user/{email}/cert")
  def deleteCertificate(@PathParam("email") emailAddress: String): Unit = {

  }
}


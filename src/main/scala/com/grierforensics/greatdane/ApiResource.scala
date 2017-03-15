// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane

import javax.ws.rs._
import javax.ws.rs.core.MediaType

case class ProvisionRequest(name: Option[String], certificates: Option[Seq[String]])
case class ProvisionResponse(privateKey: String, certificate: String)

@Secured
@Path("/v1/")
@Consumes(Array(MediaType.APPLICATION_JSON))
@Produces(Array(MediaType.APPLICATION_JSON))
class ApiResource(connector: Connector) {

  @POST
  @Path("/user/{email}")
  def provisionUser(@PathParam("email") emailAddress: String, body: ProvisionRequest): Option[ProvisionResponse] = {
    val certificates = if (body == null || (body != null && body.certificates.getOrElse(Seq()).isEmpty)) {
      Seq()
    } else {
      body.certificates.get
    }

    val keyAndCert = connector.provisionUser(emailAddress, certificates)

    keyAndCert flatMap { kc =>
      Some(ProvisionResponse(kc.pemKey, kc.pemCert))
    }
  }

  @DELETE
  @Path("/user/{email}")
  def deprovisionUser(@PathParam("email") emailAddress: String): Unit = {
    connector.deprovisionUser(emailAddress)

    // TODO: How to ensure 404 - Not Found is returned if user isn't in DNS?
      /*.orElse(
      throw new NotFoundException(s"Email address $emailAddress not found")
    )
    */
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


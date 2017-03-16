// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane.connector

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

    val keyAndCert = try {
      connector.provisionUser(emailAddress, certificates)
    } catch {
      case DomainNotFoundException(msg) => throw new BadRequestException(msg)
    }

    keyAndCert flatMap { kc =>
      Some(ProvisionResponse(kc.pemKey, kc.pemCert))
    }
  }

  @DELETE
  @Path("/user/{email}")
  def deprovisionUser(@PathParam("email") emailAddress: String): Unit = {
    try {
      connector.deprovisionUser(emailAddress)
    } catch {
      case DomainNotFoundException(msg) => throw new BadRequestException(msg)
      case EmailAddressNotFoundException(msg) => throw new NotFoundException(msg)
    }
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


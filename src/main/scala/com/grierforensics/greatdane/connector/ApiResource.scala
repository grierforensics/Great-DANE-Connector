// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane.connector

import javax.ws.rs._
import javax.ws.rs.core.MediaType

import io.swagger.annotations._

case class ProvisionRequest(name: Option[String], certificates: Option[Seq[String]])
case class ProvisionResponse(records: Seq[String], privateKey: String, certificate: String)

@Path("/")
@Api(value = "API", authorizations = Array(new Authorization(value="apiKey")))
@ApiResponses(value = Array(
  new ApiResponse(code = 401, message = "Unauthenticated")
))
@Consumes(Array(MediaType.APPLICATION_JSON))
@Produces(Array(MediaType.APPLICATION_JSON))
class ApiResource(connector: Connector) {

  @POST
  @Path("/record/{email}")
  @ApiOperation(value = "Create SMIMEA record(s)",
    notes = "Create SMIMEA record(s) for the given email address and certificates S/MIME. " +
      "If no certificate is provided, an S/MIME certificate and private key will be generated " +
      "and returned in addition to the created SMIMEA records.",
    response = classOf[ProvisionResponse]
  )
  @ApiResponses(value = Array(
    new ApiResponse(code = 400, message = "Certificate generation disabled"),
    new ApiResponse(code = 403, message = "Invalid domain in email address"),
    new ApiResponse(code = 200, message = "Record(s) successfully generated")
  ))
  def generateRecord(
                    @ApiParam(value = "User's email address", example = "foo@example.com") @PathParam("email") emailAddress: String,
                    @ApiParam(value = "User name and certificate(s)", required = false,
                      examples = new Example(Array(new ExampleProperty(value="")))) body: ProvisionRequest
                    ): ProvisionResponse = {
    generateUsingConnector(emailAddress, body, connector.generateRecords)
  }

  @Secured
  @POST
  @Path("/user/{email}")
  @ApiOperation(value = "Provisions a user",
    notes = "Provision the user with the given email address. " +
      "Provided certificates will be published as SMIMEA records. If no certificate is provided, an S/MIME " +
      "certificate and private key will be generated for the user, the certificate will be published as an SMIMEA " +
      "record, and the certificate and key will be returned.",
    response = classOf[ProvisionResponse]
  )
  @ApiResponses(value = Array(
    new ApiResponse(code = 400, message = "Certificate generation disabled"),
    new ApiResponse(code = 403, message = "Invalid domain in email address"),
    // TODO: Change to return 201 - Created, rather than just 200 - Ok
    new ApiResponse(code = 200, message = "User successfully provisioned")
  ))
  def provisionUser(
                     @ApiParam(value = "User's email address", example = "foo@example.com") @PathParam("email") emailAddress: String,
                     @ApiParam(value = "User name and certificate(s)", required = false,
                     examples = new Example(Array(new ExampleProperty(value="")))) body: ProvisionRequest
                   ): ProvisionResponse = {
    generateUsingConnector(emailAddress, body, connector.provisionUser)
  }

  /** Extracts certificates from ProvisionRequest and calls `connectorOp` to produce a ProvisionResponse
    *
    * @param emailAddress User's email address
    * @param body provisioning request body (certificates)
    * @param connectorOp Connector's generateRecords or provisionUser method
    * @return response containing SMIMEA records, and optionally generated private key and S/MIME certificate
    */
  private def generateUsingConnector(emailAddress: String, body: ProvisionRequest,
                          connectorOp: (String, Seq[String]) => GeneratedData): ProvisionResponse = {
    val certificates = if (body == null || (body != null && body.certificates.getOrElse(Seq()).isEmpty)) {
      Seq()
    } else {
      body.certificates.get
    }

    val generatedData = try {
      connectorOp(emailAddress, certificates)
    } catch {
      case DomainNotFoundException(msg) => throw new ForbiddenException(msg)
      case e@CertificateGenerationDisabledException => throw new BadRequestException(e.getMessage)
    }

    ProvisionResponse(generatedData.records, generatedData.pemKey, generatedData.pemCert)
  }

  @Secured
  @DELETE
  @Path("/user/{email}")
  @ApiOperation(value = "Deprovisions a user",
    notes = "Deprovision the user with the given email address by removing all corresponding SMIMEA records."
  )
  @ApiResponses(value = Array(
    new ApiResponse(code = 403, message = "Invalid domain in email address"),
    new ApiResponse(code = 404, message = "User email address not found"),
    new ApiResponse(code = 204, message = "User successfully deprovisioned")
  ))
  def deprovisionUser(@ApiParam(value = "User's email address", example = "foo@example.com") @PathParam("email") emailAddress: String): Unit = {
    try {
      connector.deprovisionUser(emailAddress)
    } catch {
      case DomainNotFoundException(msg) => throw new ForbiddenException(msg)
      case EmailAddressNotFoundException(msg) => throw new NotFoundException(msg)
    }
  }

  @Secured
  @PUT
  @Path("/user/{email}")
  @ApiOperation(value = "Modifies a provisioned user",
    notes = "TODO"
  )
  def modifyUser(@ApiParam(value = "User's email address", example = "foo@example.com") @PathParam("email") emailAddress: String): Unit = {

  }

  @Secured
  @DELETE
  @Path("/user/{email}/cert")
  @ApiOperation(value = "Deletes a user's certificate",
    notes = "TODO"
  )
  @ApiResponses(value = Array(
    new ApiResponse(code = 204, message = "Certificate successfully deleted")
  ))
  def deleteCertificate(@ApiParam(value = "User's email address", example = "foo@example.com") @PathParam("email") emailAddress: String): Unit = {

  }
}


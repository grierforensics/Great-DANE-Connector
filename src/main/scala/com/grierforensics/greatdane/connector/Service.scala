// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane.connector

import java.util.logging.Logger
import javax.ws.rs.container.{ContainerRequestContext, ContainerRequestFilter}
import javax.ws.rs.core.{HttpHeaders, Response}
import javax.ws.rs.ext.{ExceptionMapper, Provider}
import javax.ws.rs.{NotAuthorizedException, Priorities, WebApplicationException}

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.jaxrs.json.JacksonJaxbJsonProvider
import com.fasterxml.jackson.module.scala.DefaultScalaModule
import com.grierforensics.greatdane.connector.dns.{DnsZoneFileWriter, InMemoryZone}
import com.typesafe.scalalogging.LazyLogging
import org.eclipse.jetty.server.Server
import org.eclipse.jetty.servlet.{DefaultServlet, ServletContextHandler, ServletHolder}
import org.glassfish.jersey.logging.LoggingFeature
import org.glassfish.jersey.model.ContractProvider
import org.glassfish.jersey.server.ResourceConfig
import org.glassfish.jersey.servlet.ServletContainer
import org.slf4j.bridge.SLF4JBridgeHandler

/** Provides exception handling for Jersey */
@Provider
class CatchAllExceptionMapper extends ExceptionMapper[Exception] with LazyLogging {
  def toResponse(ex: Exception): Response = {
    ex match {
      case e: WebApplicationException => e.getResponse
      case e: Exception => {
        logger.warn("request failed", ex)
        Response.status(500).entity(s"Server Error: ${ex.getMessage()}").build()
      }
    }
  }
}

class ScalaJacksonProvider extends JacksonJaxbJsonProvider(
  new ObjectMapper().registerModule(DefaultScalaModule), JacksonJaxbJsonProvider.DEFAULT_ANNOTATIONS
)

/** Ensures the HTTP request is authenticated via API Key */
@Secured
@Provider
//@Priority(Priorities.AUTHENTICATION)
class AuthenticationFilter extends ContainerRequestFilter {
  override def filter(requestContext: ContainerRequestContext): Unit = {
    val authorizationHeader = requestContext.getHeaderString(HttpHeaders.AUTHORIZATION)

    if (authorizationHeader == null || authorizationHeader == "") {
      throw new NotAuthorizedException("Authorization header missing or invalid")
    }

    if (!keyValid(authorizationHeader)) {
      requestContext.abortWith(
        Response.status(Response.Status.UNAUTHORIZED).build()
      )
    }
  }

  private def keyValid(key: String): Boolean = {
    key == Settings.ApiKey
  }
}

/**
  *
  * References used for constructing embedded server with static content:
  * - http://stackoverflow.com/a/20223103/1689220
  *
  * @param connector
  * @param port
  */
class Service(connector: Connector, port: Int) extends LazyLogging {
  private val server = new Server(port)
  private val context = new ServletContextHandler(server, "/")

  private val apiConfig = new ResourceConfig
  apiConfig.register(new CatchAllExceptionMapper, ContractProvider.NO_PRIORITY)
  apiConfig.register(new ScalaJacksonProvider(), ContractProvider.NO_PRIORITY)
  apiConfig.register(new ApiResource(connector), ContractProvider.NO_PRIORITY)
  apiConfig.register(new AuthenticationFilter, Priorities.AUTHENTICATION)
  apiConfig.register(new LoggingFeature(Logger.getLogger(getClass.getName),
    LoggingFeature.Verbosity.HEADERS_ONLY), ContractProvider.NO_PRIORITY)

  // The API servlet provides the entire REST API
  private val apiServlet = new ServletHolder("api", new ServletContainer(apiConfig))
  context.addServlet(apiServlet, "/api/*")

  // The default servlet serves static HTML content, such as the API docs
  private val defaultServlet = new ServletHolder("default", classOf[DefaultServlet])
  defaultServlet.setInitParameter("resourceBase", "src/main/webapp")
  defaultServlet.setInitParameter("dirAllowed", "true")
  context.addServlet(defaultServlet, "/")


  /** Runs the service indefinitely */
  def run(): Unit = {
    server.start()
    logger.info(s"Listening on port $port")
    server.join()
  }

  def isStarted: Boolean = server.isStarted

  def stop(): Unit = server.stop()

}

object Service extends LazyLogging {

  /** Installs the SLF4J bridge so we can use Logback for logging */
  def installLogging(): Unit = {
    SLF4JBridgeHandler.removeHandlersForRootLogger()
    SLF4JBridgeHandler.install()
    logger.info(s"Logging initialized (DEBUG enabled: ${logger.underlying.isDebugEnabled})")
  }

  def main(args: Array[String]): Unit = {
    installLogging()

    val zones = Settings.Zones.map { z =>
      val zone = new InMemoryZone(z.origin)
      new Thread() {
        val writer = new DnsZoneFileWriter(zone, z.baseFile, z.outFile)
        override def run(): Unit = {
          while (true) {
            writer.writeZoneFile()
            Thread.sleep(z.writePeriod)
          }
        }
      }.start()
      zone
    }
    val connector = new Connector(zones)
    //val connector = Connector.Default

    val port = Settings.Port
    val service = new Service(connector, port)
    service.run()
  }
}

// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane

import java.util.logging.Logger
import javax.ws.rs.WebApplicationException
import javax.ws.rs.core.Response
import javax.ws.rs.ext.{ExceptionMapper, Provider}

import com.fasterxml.jackson.jaxrs.json.JacksonJaxbJsonProvider
import com.typesafe.scalalogging.LazyLogging
import org.eclipse.jetty.server.Server
import org.eclipse.jetty.servlet.{ServletContextHandler, ServletHolder}
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

class Service(connector: Connector, port: Int) extends LazyLogging {
  private val config = new ResourceConfig
  config.register(new JacksonJaxbJsonProvider(), ContractProvider.NO_PRIORITY)
  config.register(new CatchAllExceptionMapper, ContractProvider.NO_PRIORITY)
  config.register(new Resource(connector), ContractProvider.NO_PRIORITY)
  config.register(new LoggingFeature(Logger.getLogger(getClass.getName),
    LoggingFeature.Verbosity.HEADERS_ONLY), ContractProvider.NO_PRIORITY)

  private val servlet = new ServletHolder(new ServletContainer(config))
  private val server = new Server(port)

  private val context = new ServletContextHandler(server, "/")
  context.addServlet(servlet, "/*")

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

  SLF4JBridgeHandler.removeHandlersForRootLogger()
  SLF4JBridgeHandler.install()

  def main(args: Array[String]): Unit = {
    val connector = new Connector(Settings.Default.EngineHost, Settings.Default.EnginePort)
    logger.info(s"Using DNS addresses: ${Settings.Default.DnsServers.mkString(", ")}")

    val port = Settings.Default.Port
    val service = new Service(connector, port)
    service.run()
  }
}

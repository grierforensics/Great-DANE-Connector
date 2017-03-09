// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane

import java.util.logging.Logger
import javax.ws.rs.WebApplicationException
import javax.ws.rs.core.Response
import javax.ws.rs.ext.{ExceptionMapper, Provider}

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.jaxrs.json.JacksonJaxbJsonProvider
import com.fasterxml.jackson.module.scala.DefaultScalaModule
import com.typesafe.scalalogging.LazyLogging
import org.eclipse.jetty.server.{Server, ServerConnector}
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
  apiConfig.register(new ScalaJacksonProvider(), ContractProvider.NO_PRIORITY)
  apiConfig.register(new CatchAllExceptionMapper, ContractProvider.NO_PRIORITY)
  apiConfig.register(new ApiResource(connector), ContractProvider.NO_PRIORITY)
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

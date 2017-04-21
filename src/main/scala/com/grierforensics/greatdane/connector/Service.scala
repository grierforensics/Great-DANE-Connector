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
import com.typesafe.scalalogging.LazyLogging
import io.swagger.jaxrs.config.{BeanConfig, SwaggerContextService}
import io.swagger.models.auth.{ApiKeyAuthDefinition, In}
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
class Service(connector: Connector, host: String, port: Int) extends LazyLogging {
  // The following is the same as creating a JAX-RS Application
  private val apiConfig = new ResourceConfig
  apiConfig.register(new CatchAllExceptionMapper, ContractProvider.NO_PRIORITY)
  apiConfig.register(new ScalaJacksonProvider(), ContractProvider.NO_PRIORITY)
  apiConfig.register(new ApiResource(connector), ContractProvider.NO_PRIORITY)
  apiConfig.register(new AuthenticationFilter, Priorities.AUTHENTICATION)
  apiConfig.register(new LoggingFeature(Logger.getLogger(getClass.getName),
    LoggingFeature.Verbosity.HEADERS_ONLY), ContractProvider.NO_PRIORITY)

  // Set up Swagger for automatic API documentation
  apiConfig.register(classOf[io.swagger.jaxrs.listing.ApiListingResource])
  apiConfig.register(classOf[io.swagger.jaxrs.listing.SwaggerSerializers])

  {
    val beanConfig = new BeanConfig
    beanConfig.setTitle("Great DANE Connector")
    beanConfig.setContact("grierforensics.com")
    beanConfig.setDescription("Great DANE Connector REST API")
    beanConfig.setVersion("1.0.0")
    beanConfig.setSchemes(Array[String]("http"))
    beanConfig.setHost(s"$host:$port")
    beanConfig.setBasePath("/api/v1")

    // Note: the package appears to be necessary!
    beanConfig.setResourcePackage("com.grierforensics.greatdane")
    beanConfig.setScan(true)

    val swagger = beanConfig.getSwagger
    swagger.securityDefinition("apiKey", new ApiKeyAuthDefinition("Authorization", In.HEADER))
    new SwaggerContextService().updateSwagger(swagger)
  }

  private val server = new Server(port)
  private val context = new ServletContextHandler(server, "/")

  // The API servlet provides the entire REST API
  {
    val holder = new ServletHolder("api", new ServletContainer(apiConfig))
    context.addServlet(holder, "/api/v1/*")
  }

  // The default servlet serves static HTML content, such as the API docs
  {
    val holder = new ServletHolder("default", classOf[DefaultServlet])
    holder.setInitParameter("resourceBase", getClass.getClassLoader.getResource("webapp").toExternalForm)
    holder.setInitParameter("dirAllowed", "true")
    context.addServlet(holder, "/")
  }

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

    val connector = Connector.Default

    val service = new Service(connector, Settings.Host, Settings.Port)
    service.run()
  }
}

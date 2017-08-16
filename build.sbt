name := "great-dane-connector"

version := "1.0"

scalaVersion := "2.12.1"

val configJvmOpt = Seq(
  "-Dconfig.file=${PROG_HOME}/conf/connector.conf",
  "-Dlogback.configurationFile=${PROG_HOME}/conf/logback.xml"
)

packAutoSettings ++ Seq(
  // Ensure each command-line script loads the custom config file
  packJvmOpts := Map(
    "service" -> configJvmOpt,
    "daemon" -> configJvmOpt,
    "certificate-generator" -> configJvmOpt,
    "provision-user" -> configJvmOpt
  )
)

libraryDependencies ++= Seq(
  "com.typesafe" % "config" % "1.3.1",

  "ch.qos.logback" %  "logback-classic" % "1.1.7",
  "com.typesafe.scala-logging" %% "scala-logging" % "3.5.0",
  "org.slf4j" % "jul-to-slf4j" % "1.7.21",

  "org.eclipse.jetty" % "jetty-server" % "9.4.2.v20170220",
  "org.eclipse.jetty" % "jetty-servlet" % "9.4.2.v20170220",

  "org.glassfish.jersey.core" % "jersey-server" % "2.25.1",
  "org.glassfish.jersey.containers" % "jersey-container-servlet" % "2.25.1",
  "org.glassfish.jersey.containers" % "jersey-container-jetty-http" % "2.25.1",

  "com.fasterxml.jackson.jaxrs" % "jackson-jaxrs-json-provider" % "2.8.7",
  "com.fasterxml.jackson.module" % "jackson-module-scala_2.12" % "2.8.7",

  "io.swagger" % "swagger-jersey2-jaxrs" % "1.5.13",
  "io.swagger" %% "swagger-scala-module" % "1.0.3",

  "dnsjava" % "dnsjava" % "2.1.8",

  "org.bouncycastle" % "bcprov-jdk15on" % "1.56",
  "org.bouncycastle" % "bcmail-jdk15on" % "1.56",

  "org.apache.httpcomponents" % "httpclient" % "4.5.3",

  "commons-io" % "commons-io" % "2.5",

  "org.scalatest" %% "scalatest" % "3.0.0" % "test",

  "commons-daemon" % "commons-daemon" % "1.0.15"
)

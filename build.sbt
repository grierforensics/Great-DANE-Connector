name := "connector"

version := "1.0"

scalaVersion := "2.12.1"

packAutoSettings

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

  "org.scalatest" %% "scalatest" % "3.0.0" % "test",

  "commons-daemon" % "commons-daemon" % "1.0.15"
)
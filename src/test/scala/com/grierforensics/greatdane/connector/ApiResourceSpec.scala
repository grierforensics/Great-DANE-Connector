// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane.connector

import java.net.{HttpURLConnection, URL}

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.scala.DefaultScalaModule
import org.apache.commons.io.IOUtils
import org.scalatest.FlatSpec

class ApiResourceSpec extends FlatSpec {

  import TestUtils.Values._

  val Mapper = new ObjectMapper().registerModule(DefaultScalaModule)

  val port = 35354
  val enginePort = 25354

  val service = new Service(TestUtils.makeTestConnector, "localhost", port)
  new Thread() {
    override def run(): Unit = {
      service.run()
    }
  }.start()

  // Wait to ensure service is up and running
  while (!service.isStarted) {
    Thread.sleep(200)
  }

  val baseUrl = s"http://localhost:$port/api/v1"

  var apiKey = Settings.ApiKey

  def apiConn(url: String, method: String, auth: Boolean): HttpURLConnection = {
    val conn = new URL(baseUrl + url).openConnection().asInstanceOf[HttpURLConnection]
    conn.setRequestMethod(method)
    conn.setRequestProperty("Content-Type", "application/json")
    conn.setRequestProperty("Accept", "application/json")
    if (auth) {
      conn.setRequestProperty("Authorization", apiKey)
    }
    conn
  }

  /** Performs an HTTP GET on the given URL
    *
    * @param url URL to GET
    * @return (HTTP response code, JSON response body)
    */
  def get(url: String, auth: Boolean = true): (Int, String) = {
    val conn = apiConn(url, "GET", auth)

    val code = conn.getResponseCode
    val json = if (code == 200) IOUtils.toString(conn.getInputStream, "utf-8") else ""
    (code, json)
  }

  def makeUrl(path: String): String = baseUrl + path

  /** Retrieves a JSON sequence given an email and type of resource requested */
  def makeUrl(email: String, kind: String): String = {
    baseUrl + s"/$email/$kind"
  }

  /** Retrieves a JSON resource given an email and type of resource requested */
  def makeUrl(email: String, kind: String, index: Int): String = {
    makeUrl(email, kind) + s"/$index"
  }

  def post(url: String, auth: Boolean = true): (Int, String) = post(url, "", auth)

  def post(url: String, input: String, auth: Boolean): (Int, String) = {
    val conn = apiConn(url, "POST", auth)
    conn.setDoOutput(true)

    IOUtils.write(input, conn.getOutputStream, "utf-8")

    val code = conn.getResponseCode
    val json = if (code == 200) IOUtils.toString(conn.getInputStream, "utf-8") else ""
    (code, json)
  }

  def put(url: String, auth: Boolean = true): (Int, String) = {
    val conn = apiConn(url, "PUT", auth)
    conn.setDoOutput(true)

    //IOUtils.write(input, conn.getOutputStream, "utf-8")

    val code = conn.getResponseCode
    val json = if (code == 200) IOUtils.toString(conn.getInputStream, "utf-8") else ""
    (code, json)
  }

  def delete(url: String, auth: Boolean = true): (Int, String) = {
    val conn = apiConn(url, "DELETE", auth)
    val code = conn.getResponseCode
    (code, "")
  }

  "An ApiResource" should "return 405 for disallowed methods" in {
    val responses = Seq(
      get("/user/test@example.com"),
      get("/user/test@example.com/cert"),
      post("/user/test@example.com/cert"),
      put("/user/test@example.com/cert")
    )

    for (resp <- responses) {
      assert(resp._1 == 405)
    }
  }

  it should "return empty key and cert when certificates are specified to provisionUser" in {
    val (code, resp) = post(s"/user/$testAddress",
      s"""{"name": "foo", "certificates": ["${testCertPem.replaceAll("[\\n\\r]+", "\\\\n")}"]}""",
      auth = true
    )
    assert(code == 200)

    val presp = Mapper.readValue(resp, classOf[ProvisionResponse])
    assert(presp.privateKey.isEmpty)
    assert(presp.certificate.isEmpty)
  }

  it should "return a private key and cert when no body is provided to provisionUser" in {
    val (code, resp) = post(s"/user/$testAddress")
    assert(code == 200)
    val presp = Mapper.readValue(resp, classOf[ProvisionResponse])
    assert(presp.privateKey.nonEmpty, presp.certificate.nonEmpty)
  }

  it should "return a private key and cert when no certificates are provided to provisionUser" in {
    for ((code, resp) <- Seq(
      post(s"/user/$testAddress", """{"name": "foo"}""", auth = true),
      post(s"/user/$testAddress", """{"name": "foo", "certificates": []}""", auth = true)
    )) {
      assert(code == 200)
      val presp = Mapper.readValue(resp, classOf[ProvisionResponse])
      assert(presp.privateKey.nonEmpty, presp.certificate.nonEmpty)
    }
  }

  it should "return HTTP 204 on successful deprovisionUser" in {
    post(s"/user/$testAddress",
      s"""{"name": "foo", "certificates": ["${testCertPem.replaceAll("[\\n\\r]+", "\\\\n")}"]}""",
      auth = true
    )
    val (code, resp) = delete(s"/user/$testAddress")
    assert(code == 204)
  }

  it should "return HTTP 404 if emailAddress doesn't exist in deprovisionUser" in {
    val (code, resp) = delete(s"/user/dne@$testDomain")
    assert(code == 404)
  }

  it should "return HTTP 403 if the domain is invalid" in {
    val badOrigin = testDomain.replace("com", "net")

    for ((code, resp) <- Seq(
      post(s"/user/foo@$badOrigin"),
      delete(s"/user/foo@$badOrigin")
    )) {
      assert(code == 403)
    }
  }

  it should "return HTTP 401 if not authenticated" in {
    for ((code, resp) <- Seq(
      post(s"/user/$testAddress", auth = false),
      delete(s"/user/$testAddress", auth = false)
    )) {
      assert(code == 401)
    }
  }

  it should "return HTTP 401 is API key is invalid" in {
    val origApiKey = apiKey
    apiKey = "abcde"
    try {
      for ((code, resp) <- Seq(
        post(s"/user/$testAddress"),
        delete(s"/user/$testAddress")
      )) {
        assert(code == 401)
      }
    } finally {
      apiKey = origApiKey
    }
  }

  it should "allow unauthenticated requests for generating records" in {
    val (code, resp) = post(s"/record/$testAddress", auth = false)
    assert(code == 200)
  }
}

// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane

import java.net.{HttpURLConnection, URL}

import org.apache.commons.io.IOUtils
import org.scalatest.FlatSpec

class ApiResourceSpec extends FlatSpec {

  val port = 35354
  val enginePort = 25354

  class TestConnector extends Connector("localhost", enginePort)

  val service = new Service(new TestConnector, port)
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

  /** Performs an HTTP GET on the given URL
    *
    * @param url URL to GET
    * @return (HTTP response code, JSON response body)
    */
  def get(url: String): (Int, String) = {
    val conn = new URL(url).openConnection().asInstanceOf[HttpURLConnection]
    conn.setRequestMethod("GET")
    conn.setRequestProperty("Accept", "application/json")

    val code = conn.getResponseCode
    val json = if (code == 200) IOUtils.toString(conn.getInputStream, "utf-8") else ""
    (code, json)
  }

  def makeUrl(path: String): String = baseUrl + path

  /** Retrieves a JSON sequence given an email and type of resource requested */
  def makeUrl(email: String, kind: String): String = {
    baseUrl + s"/${email}/$kind"
  }

  /** Retrieves a JSON resource given an email and type of resource requested */
  def makeUrl(email: String, kind: String, index: Int): String = {
    makeUrl(email, kind) + s"/$index"
  }

  def post(url: String): (Int, String) = post(url, "")

  def post(url: String, input: String): (Int, String) = {
    val conn = new URL(url).openConnection().asInstanceOf[HttpURLConnection]
    conn.setRequestMethod("POST")
    conn.setRequestProperty("Accept", "application/json")
    conn.setDoOutput(true)

    IOUtils.write(input, conn.getOutputStream, "utf-8")

    val code = conn.getResponseCode
    val json = if (code == 200) IOUtils.toString(conn.getInputStream, "utf-8") else ""
    (code, json)
  }

  def put(url: String): (Int, String) = {
    val conn = new URL(url).openConnection().asInstanceOf[HttpURLConnection]
    conn.setRequestMethod("PUT")
    conn.setRequestProperty("Accept", "application/json")
    conn.setDoOutput(true)

    //IOUtils.write(input, conn.getOutputStream, "utf-8")

    val code = conn.getResponseCode
    val json = if (code == 200) IOUtils.toString(conn.getInputStream, "utf-8") else ""
    (code, json)
  }

  "An ApiResource" should "return 405 for disallowed methods" in {
    val responses = Seq(
      get(makeUrl("/user/test@example.com")),
      get(makeUrl("/user/test@example.com/cert")),
      post(makeUrl("/user/test@example.com/cert")),
      put(makeUrl("/user/test@example.com/cert"))
    )

    for (resp <- responses) {
      assert(resp._1 == 405)
    }
  }

}

// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane.connector

import java.net.URI
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths}

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.scala.DefaultScalaModule
import org.apache.commons.io.IOUtils
import org.apache.http.HttpHeaders
import org.apache.http.client.methods.HttpPost
import org.apache.http.entity.StringEntity
import org.apache.http.impl.client.HttpClients

object DemoClient {
  def main(args: Array[String]): Unit = {
    //val host = args(0)
    //val port = args(1)

    val emailAddress = args(0)
    val certPem = if (args.length > 1) {
      new String(Files.readAllBytes(Paths.get(args(1))), StandardCharsets.UTF_8)
    } else ""

    val client = HttpClients.createDefault()
    val uri = new URI(s"http://localhost:35353/api/v1/user/$emailAddress")
    val post = new HttpPost(uri)
    post.addHeader(HttpHeaders.CONTENT_TYPE, "application/json")
    post.addHeader(HttpHeaders.AUTHORIZATION, Settings.ApiKey)
    println(post.toString)

    val req = ProvisionRequest(Some("Foo"), if (certPem.length > 0) Some(Seq(certPem)) else None)
    val mapper = new ObjectMapper().registerModule(DefaultScalaModule)
    val json = mapper.writeValueAsString(req)
    println(json)

    post.setEntity(new StringEntity(json))

    val resp = client.execute(post)
    try {
      val entity = resp.getEntity
      println(resp.getStatusLine.getStatusCode, resp.getStatusLine.getReasonPhrase)
      println(IOUtils.toString(entity.getContent, StandardCharsets.UTF_8))
    } finally {
      resp.close()
    }

  }
}

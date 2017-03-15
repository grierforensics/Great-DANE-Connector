// Copyright (c) 2017 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane

import java.security.cert.X509Certificate

import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.openssl.PEMParser

object Converters {
  private val CertificateConverter = new JcaX509CertificateConverter().setProvider(Settings.SecurityProvider)

  /** Converts an X509CertificateHolder to an X509Certificate */
  def convert(ch: X509CertificateHolder): X509Certificate = CertificateConverter.getCertificate(ch)

  /** Encodes X.509 Certificate data to PEM */
  def toPem(ch: X509CertificateHolder): String = toPem(convert(ch))

  def toPem[T](obj: T): String = {
    import java.io.StringWriter

    import org.bouncycastle.openssl.jcajce.JcaPEMWriter

    val sw = new StringWriter()
    val pemWriter = new JcaPEMWriter(sw)
    try {
      pemWriter.writeObject(obj)
    } finally {
      pemWriter.close()
    }
    sw.toString
  }

  /** Decode a PEM-encoded certificate into an X.509 Certificate object */
  def fromPem(encoded: String): X509Certificate = {
    import java.io.StringReader

    val parser = new PEMParser(new StringReader(encoded))
    val obj = parser.readObject()

    obj match {
      case holder: X509CertificateHolder => CertificateConverter.getCertificate(holder)
      // TODO: support public keys, warn/error for private keys
      // See https://gist.github.com/akorobov/6910564 for examples
      case _ => throw new RuntimeException("Invalid PEM-encoded certificate.")
    }
  }

}

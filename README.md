# Great DANE

<img src="https://tools.greatdanenow.com/GreatDaneLogo3.0_wTagline_WEB.png" align="right" width="300" />

Great DANE is a suite of tools designed to enable users to send secure, private
emails without having to explicitly exchange public keys. By default, email is
sent in the clear (without encryption) and unsigned (unauthenticated). S/MIME
solves both of these problems by encrypting and signing emails, however it
requires you to have the certificate belonging to your correspondent,
presenting a chicken-and-egg problem. By using the DNS as a secure distributed
database for S/MIME certificates, we can eliminate this barrier and finally
make email completely confidential and authenticated.

For more information on DANE SMIMEA, please see the
[IETF RFC](https://tools.ietf.org/html/rfc8162).

# Great DANE Connector

The Great DANE Connector gives organizations the ability to automatically
publish DANE SMIMEA records for user email addresses. It also serves as a
standalone tool for SMIMEA record generation.

The Connector is implemented as an HTTP REST service and provides an API for

1. Optionally generating an S/MIME certificate and private key for a user
2. Publishing DANE SMIMEA records in the DNS

The Connector dynamically generates Bind-style DNS zone files. Generated zone
files can be used to update your DNS server in real time.

## Deploy

The Great DANE Connector binary distribution includes everything needed to deploy
the Connector itself. In addition, you'll need a DNS server compatible with
Bind-style zone files, such as Bind or PowerDNS.

Unpack the binary distribution to the location of your choice, which we'll call
`$CONNECTOR_HOME`. Configure the Connector in `$CONNECTOR_HOME/conf/connector.conf`.
Start the Connector by executing `$CONNECTOR_HOME/bin/service` on Linux/OS X or
`$CONNECTOR_HOME/bin/service.bat` on Windows.

### Configure

The Great DANE Connector can be configured in `$CONNECTOR_HOME/conf/connector.conf`.
This file is well-documented, making it easy to customize your deployment.

### Integrate

The Great DANE Connector binary distribution includes additional tools for
integration with existing platforms and workflows. These can be found in
`$CONNECTOR_HOME/bin`.

#### Microsoft Exchange and Active Directory

The `Publish-Smimea.ps1` tool is a Windows PowerShell script that can be easily
integrated into existing workflows for provisioning Exchange mailboxes and/or
Active Directory users.

The `Bundle-Certificate.ps1` tool processes the output of the `Publish-Smimea.ps1`
script to create a bundled PKCS12 certificate (X509Certificate2 in .NET). This
script depends on the Bouncy Castle assembly, which can be obtained
[here](https://www.nuget.org/packages/Portable.BouncyCastle/).

Both of these scripts contain detailed documentation and examples.
Use PowerShell's `Get-Help -Detailed <script>` for full details.

#### DNS

To make use of the dynamically generated zone files you'll need a DNS server
capable of dynamically updating zone configurations, such as PowerDNS or Bind
with its `rdnc` tool. See [Example](#example) below for an example using PowerDNS.

#### Command-Line

The `provision-user` tool is a basic command-line Connector client that accepts
a user's email address and, optionally, certificates and publishes DANE SMIMEA
records for that user. This tool is useful for testing that you've properly
configured the Connector.

### Example

The `_smimecert.example.com.template` file is a sample DNS zone file containing
only `SOA` and `NS` records. This zone's origin is `_smimecert.example.com`,
meaning it contains records for the `_smimecert.example.com` subdomain. It
generally makes sense to use the `_smimecert` zone cut as defined by the [DANE
SMIMEA RFC](https://tools.ietf.org/html/rfc8162), so as to
avoid interfering with top-level domain records.

By default, the Connector is configured to use this template to generate the
zone file `_smimecert.example.com.zone`. This file can then be synchronized to
your DNS server, after which the DNS server should reload the updated zone file.

One possible way to implement this workflow is using PowerDNS with its Bind
backend. In this scenario, you could configure the Bind zone in `/etc/named.conf`
as follows:

```
zone "_smimecert.example.com" {
        type master;
        file "/etc/named/zones/_smimecert.example.com.zone";
};
```

You'll then need to synchronize the zone file generated by the Connector to
`/etc/named/zones/_smimecert.example.com.zone` on the DNS server, for example
using `rsync` or `scp`. To ensure the zone file is dynamically reloaded,
configure PowerDNS in `/etc/pdns/pdns.conf` as follows:

```
launch=bind
bind-config=/etc/named.conf
bind-check-interval=30
```

With this DNS configuration in place, start the Great DANE Connector:

```
$CONNECTOR_HOME/bin/service
```

then publish an SMIMEA record for a user using the included `provision-user` tool:

- If you have an S/MIME certificate for the user:

    ```
    $CONNECTOR_HOME/bin/provision-user alice@example.com alice.smime-cert.pem
    ```

- Otherwise, ensure you've configured a signing key and certificate in
    `$CONNECTOR_HOME/connector.conf` (e.g. that of your organization) and allow
    the Connector to generate a certificate for the user:

    ```
    $CONNECTOR_HOME/bin/provision-user bob@example.com
    ```

## API

The Great DANE Connector hosts its own API documentation under the `/doc` URL
path. For example, if a Connector instance is running at `http://localhost:35353`,
the API documentation is available at `http://localhost:35353/doc`. The API
documentation also includes a handy feature for interactively exploring the API.

Note: Prefix all endpoints with `/api/v1`.

Note: Authentication is performed by providing the configured API key in the
`Authorization` header.

1. `POST /record/{email}`

    Generate a DANE SMIMEA record for each provided S/MIME certificate.

    Parameters:
    - `email`: email address of user
    - `body`: JSON request body of the form:

        ```
        {
          "name": "<user's name>",
          "certificates": ["PEM-encoded S/MIME certificates"]
        }
        ```

    Response: JSON of the form:

        ```
        {
            "records": ["Generated SMIMEA records"],
            "privateKey": "Optionally generated private key"
            "certificate": "Optionally generated S/MIME certificate"
        }
        ```

1. `POST /user/{email}`

    Provision a user by publishing one or more DANE SMIMEA records.

    Requires authentication using the API key.

    Parameters:
    - `email`: email address of user
    - `body`: JSON request body of the form:

        ```
        {
          "name": "<user's name>",
          "certificates": ["PEM-encoded S/MIME certificates"]
        }
        ```

    Response: JSON of the form:

        ```
        {
            "records": ["Generated SMIMEA records"],
            "privateKey": "Optionally generated private key"
            "certificate": "Optionally generated S/MIME certificate"
        }
        ```

1. `DELETE /user/{email}`

    De-provision a user by deleting all DANE SMIMEA records for the user.

    Requires authentication using the API key.

    Parameters:
    - `email`: email address of user

## Development

The Great DANE Connector is implemented in Scala, using Jersey and an embedded
Jetty HTTP server to provide the HTTP REST functionality.

To compile the service you'll need [SBT](http://www.scala-sbt.org/), the
standard tool for building Scala projects.

Compile and test:

```
$ sbt compile
$ sbt test
```

Build the command-line tools/scripts (`bin/`, `lib/`):

```
$ sbt pack
$ ls ./target/pack/bin/
```

Create distributable archives (`.zip`, `.tar.gz`):

```
$ sbt pack-archive
```

## License

Dual-licensed under Apache License 2.0 and 3-Clause BSD License. See LICENSE.

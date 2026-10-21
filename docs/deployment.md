# Deploy the SMTP service and connect a relay

[Administration guide](../README.md)

Use this guide to bring up a listener, connect it to the server that performs
onward delivery, and maintain its TLS configuration. Incoming client login is
configured separately in [client submission](client-submission.md).

## Build and install

Build against the NaviServer installation that will load the module:

```sh
make NAVISERVER=/usr/local/ns
make install NAVISERVER=/usr/local/ns
```

Set `server` and `home` to the values used by your existing NaviServer
configuration. The examples below belong in that configuration, not in a Tcl
request script. Restart after installing the module or changing its startup
configuration. The default build does not require an external spam scanner or
libspf2; optional SPF backends are covered in [mail policy](mail-policy.md).

## Configure the listener and delivery relay

To enable the SMTPD module, add the following directives to your
NaviServer configuration file (e.g., `nsd.tcl`). Load the `nssmtpd.so`
module within your server's `modules` section and configure its
settings in a dedicated section:

```tcl
ns_section ns/server/${server}/modules {
  ns_param nssmtpd ${home}/bin/nssmtpd.so
}

ns_section ns/server/${server}/module/nssmtpd {
  #
  # Networking settings
  #
  ns_param port         2525
  ns_param address      127.0.0.1
  ns_param relay        localhost:25
  ns_param relaydomains {localhost example.org}
  ns_param localdomains {127.0.0.1}

  #
  # Tcl callback definitions
  #
  ns_param initproc     smtpd::init
  ns_param rcptproc     smtpd::rcpt
  ns_param dataproc     smtpd::data
  ns_param errorproc    smtpd::error

  # For STARTTLS functionality
  ns_param certificate "pathToYourCertificateChainFile.pem"
  ns_param key         "pathToYourCertificatePrivateKey.key"  ;# optional, PEM format
  ns_param cafile      ""
  ns_param capath      ""
  ns_param ciphers     "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305"
}
```

Note: before NaviServer 5.1, the certificate file had to include the
certificate chain and the private key. Starting with NaviServer 5.1, the
private key file (PEM format) can be specified optionally as a separate file.

`relaydomains` permits untrusted senders to address those recipient domains;
it does not establish that a mailbox exists. `localdomains` identifies trusted
**sending peers**, which may relay to arbitrary recipients and bypass incoming
policy. Keep it limited to trusted submitting hosts. Configure recipient domains
and aliases using [recipient routing](recipient-routing.md).

For public incoming mail in a container, bind a container-reachable address and
publish the SMTP port. See the [mail-path overview](../README.md#overview).

## Connect application mail to the listener

For NaviServer versions using the `ns/sendmail` configuration section, point
`ns_sendmail` at the nssmtpd listener, not at the upstream relay:

```tcl
ns_section ns/sendmail {
    ns_param smtphost 127.0.0.1
    ns_param smtpport 2525
}
```

Older NaviServer versions read these SMTP settings from `ns/parameters`.
If the application and listener are in different containers, use the listener's
reachable service hostname instead of `127.0.0.1`. This configuration affects
`ns_sendmail`; direct `ns_smtpd send` uses its own relay defaults or explicit
host/port arguments. See the [Tcl sending reference](tcl-api.md#send-a-message-from-an-application).

## Authenticate to an upstream relay

The `relay` parameter defines the SMTP server responsible for message
delivery. When using port `25`, the relay server is assumed to accept
messages without requiring further authentication. However, if you
configure the relay to use port `587`, the module supports PLAIN
password authentication. In this scenario, ensure that:

- The relay server supports STARTTLS.
- NaviServer and this module are compiled with OpenSSL support.

The URL format is intentionally designed to accommodate additional
authentication methods in the future. An example (with placeholders
in uppercase):

```tcl
ns_section ns/server/${server}/module/nssmtpd {
  # ...
  ns_param relay plain://USER:PWD@MAILHOST:587
  # ...
}
```

The username and password are carried in the URL's `userinfo` component.
Percent-encode credentials for URL parsing, for example with
`ns_urlencode -part oauth1 $credentials`.

**Security Note:** Be cautious when embedding credentials in
configuration files. To protect sensitive information, restrict file
permissions for the configuration file, verify user permissions on the
host machine, or consider using environment variables or reading
credentials from a secured file. Keep in mind that arbitrary Tcl
commands can be executed from within the configuration file.

## Renew or replace the incoming TLS certificate

On NaviServer 5.2 and newer, incoming STARTTLS reuses one server context per
driver/server mapping through `Ns_DriverGetServerCtx`. Host aliases for that server
share the context. It is initialized on the first STARTTLS attempt; a failed
initialization can be retried. Older NaviServer builds use one context per
module configuration instead. Both caches retain a bounded number of
contexts for the process lifetime, registered with NaviServer's certificate
reload machinery. Connection-level TLS objects and outgoing relay client
contexts are released when no longer needed.

After renewing the configured certificate/key files, invoke `ns_certctl reload`
in the running NaviServer, or send SIGHUP to its process. Merely replacing the
PEM no longer reloads it on each connection. Existing TLS connections remain
usable; new connections use the reloaded certificate. Check the system log
for reload errors and verify the served certificate externally. With Docker,
mount the certificate directory so atomic file replacement remains visible.

## Set SMTP I/O timeouts

SMTP `readtimeout` and `writetimeout` accept NaviServer time values such as
`500ms`, `1.5s`, or `1m`; both default to `60s`. Unitless values remain seconds.
The optional `segvtimeout` uses the same syntax, retaining its default `-1`
(no delay before termination).

## Verify the deployment

Start with send/event logging enabled using [monitoring](monitoring.md).
Confirm that application mail reaches the upstream relay. If receiving mail
from the Internet, test from an untrusted external host: a configured recipient
domain should be eligible for delivery, while an unrelated external destination
must remain relay-denied. Add strict recipient validation and mail policy only
after the base path works. Upstream acceptance is not final mailbox delivery.

For SMTP phase failures and receive counters, see the
[system-log reference](log-reference.md#interpret-system-log-io-and-protocol-diagnostics).

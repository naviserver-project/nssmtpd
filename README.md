# SMTPD Server/Proxy for NaviServer

**Release:** 2.8

The NaviServer SMTPD module implements the SMTP protocol and functions
as both an SMTP proxy and server. It provides an API for interacting
with the server directly via Tcl for e.g. sending mails and
interacting with the server. A typical setup uses a local Postfix
installation as the relay for further message delivery.

The module supports incoming SMTP, authenticated client submission over
STARTTLS, forwarding to an upstream mail server, and direct Tcl sending.
Optional features include envelope aliases, recipient policies, greylisting,
SPF checks, authentication diagnostics, and send/event logs with nsstats views.
Historical scanner integrations are described in the
[development reference](docs/development.md#maintain-historical-scanner-integrations).

## Choose your deployment scenario

| What you want to do | Start here | Then verify |
| --- | --- | --- |
| Send application mail through a local or container relay | [Connect application mail](docs/deployment.md#connect-application-mail-to-the-listener) | [Trace outgoing acceptance](docs/monitoring.md) |
| Receive Internet mail for selected domains and forward aliases | [Configure recipient routing](docs/recipient-routing.md) | Unknown-recipient rejection and relay denial from an untrusted client |
| Let mail clients submit with a separate SMTP login | [Enable authenticated submission](docs/client-submission.md) | STARTTLS, successful login and rejection of invalid credentials |
| Delay suspicious senders or hold mail for review | [Configure incoming mail policy](docs/mail-policy.md), then [quarantine](docs/quarantine.md) | Deferral/rejection reasons, retained messages and controlled release |
| Investigate missing mail, TLS failures or policy decisions | [Follow the delivery evidence](docs/monitoring.md) | Session/transaction Details and upstream relay logs |

These scenarios share the same module; they do not require separate SMTP
services. Enable only the parts needed for the installation. An upstream MTA
handles onward delivery, and the historical scanner interfaces are not a
maintained spam-filtering service.

## Overview

![SMTP paths, ports, and configuration sections](docs/smtp-paths.svg)

Ports in the diagram are examples. `SERVER` denotes the configured virtual
server name. Direct external mail and authenticated clients can share the
same listener. nssmtpd forwards accepted mail to an upstream MTA; that MTA
handles onward delivery. The direct Tcl send API bypasses the incoming listener.

| Path or responsibility | Configuration |
| --- | --- |
| Application → nssmtpd via `ns_sendmail` | `ns/sendmail`: `smtphost`, `smtpport`; older NaviServer versions use `ns/parameters` |
| Incoming nssmtpd listener | `ns/server/$server/module/nssmtpd`: `address`, `port` |
| Host port → container port | Docker Compose `ports`, e.g. `25:2525`; use a reachable listener address in the container |
| Incoming STARTTLS and client login | Same module section: `certificate`, `key`, `authproc`, `authfile` |
| Accepted recipient domains | Same module section: `relaydomains`; [aliases and validation](docs/recipient-routing.md) establish recipient handling |
| Trusted sending peers | Same module section: `localdomains`; matching peers receive LOCAL privileges and bypass built-in incoming policy |
| nssmtpd → upstream outgoing server | Same module section: `relay`, e.g. `mail-relay:25` or `plain://USER:PWD@HOST:587` |
| Direct `ns_smtpd send` | Optional `server` and `port` arguments override the configured relay defaults |

For a local-only listener, `address 127.0.0.1` and `port 2525` are sufficient.
For Docker-published incoming mail, bind a container-reachable address such as
`0.0.0.0`; binding only to loopback does not expose the listener through the
published port. `localhost` always refers to the current host or container,
so a separate relay container needs its reachable hostname.

## Install and bring up the base mail path

1. Check the [requirements](#requirements), then [build and install the module](docs/deployment.md#build-and-install).
2. Configure the listener and upstream relay. Use loopback for local application
   submission, or a reachable container address and published port for public mail.
3. Separate recipient-domain permission (`relaydomains`) from trusted sending
   peers (`localdomains`). Add [aliases and unknown-recipient checks](docs/recipient-routing.md)
   when receiving mail for a domain.
4. [Enable send and event logs](docs/monitoring.md), restart, and verify delivery
   through the upstream relay. Test relay restrictions from an untrusted client.
5. Add client authentication or incoming policy as required by the selected
   scenario. For suspicious-mail review, configure persistent quarantine before
   relying on a DATA rejection to retain a message.

The [complete DATA-policy example](examples/datapolicy-config.tcl) combines the
validated standard policy with persistent quarantine. It is an optional policy,
not a prerequisite for ordinary SMTP forwarding.

## Administration tasks

| Task | Procedure |
| --- | --- |
| Change the upstream server or its credentials | [Configure relay authentication](docs/deployment.md#authenticate-to-an-upstream-relay) |
| Renew certificates | [Reload the TLS certificate](docs/deployment.md#renew-or-replace-the-incoming-tls-certificate) |
| Add, change or remove SMTP users | [Manage the separate credential file](docs/client-submission.md#add-change-or-remove-smtp-users) |
| Add aliases, reject unknown users or accept validated bounces | [Maintain recipient routing](docs/recipient-routing.md) |
| Tune greylisting or SPF and DATA decisions | [Configure mail policy](docs/mail-policy.md) |
| Inspect or release held mail; recover an interrupted release | [Maintain quarantine](docs/quarantine.md) |
| Follow mail through recipient, policy and relay stages | [Use SMTP Events and SMTP Sent](docs/monitoring.md#use-the-nsstats-pages) |
| Configure log rotation or read-only MCP access | [Monitor delivery](docs/monitoring.md) |

`SUCCESS` in the send log means acceptance by the upstream SMTP server.
A greylist retry does not establish legitimacy, and DKIM key diagnostics do
not verify signatures. Quarantined mail has been accepted by nssmtpd but has
not been forwarded. Review [expiry and uncertain-delivery handling](docs/quarantine.md)
as part of regular administration.

## Requirements

The core module compiles with Tcl 8.5, 8.6, and 9.0. STARTTLS requires an
OpenSSL-enabled build and a suitable certificate. Optional Tcl helpers have
their own dependencies; the password-file helpers require Tcl 8.6 or newer
and NaviServer crypto support, as documented in the
[client-submission guide](docs/client-submission.md). An upstream SMTP server is
needed for forwarding. External spam/virus scanners are not required.

## Reference and development

- [Raw event formats and transport diagnostics](docs/log-reference.md)
- [Custom policy callbacks and findings](docs/policy-reference.md)
- [Tcl sending and session API](docs/tcl-api.md)
- [Configuration parameter definitions](doc/tcl/config-parameters.tcl) and [module manual source](doc/src/nssmtpd.man)
- [Regression tests, generated documentation and legacy integrations](docs/development.md)

## Licensing

This project is licensed under the Mozilla Public License, v. 2.0.
A copy of the MPL can be obtained from https://mozilla.org/MPL/2.0/.

## Authors

- **Vlad Seryakov** — <vlad@crystalballinc.com>
- **Gustaf Neumann** — <neumann@wu-wien.ac.at>


# SMTPD Server/Proxy for NaviServer

**Release:** 2.8  
**Author:** Vlad Seryakov (<vlad@crystalballinc.com>) Gustaf Neumann (<neumann@wu-wien.ac.at>)

---

# NaviServer SMTPD Module

The NaviServer SMTPD module implements the SMTP protocol and functions
as both an SMTP proxy and server. It provides an API for interacting
with the server directly via Tcl for e.g. sending mails and
interacting with the server. A typical setup uses a local Postfix
installation as the relay for further message delivery.

The module supports sending and receiving emails, including
STARTTLS, logging statistics with graphical display via nsstats, URIs
for relay host specification including relay authentication.  The
module features also built-in anti-spam and anti-virus capabilities
which require work to interact with newer releases of the external
packages.


```
    A NaviServer (Sender) → B (nssmptd, 127.0.0.1:smtpdport) → C (relay, localhost:25)
```

- **Compatibility:** Compiles with Tcl versions 8.5, 8.6, and 9.0.
- **Note:** By default, anti-spam and anti-virus support are deactivated. They may require additional configuration or updates to work with current libraries.

---


## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
  - [Anti-Spam Support](#anti-spam-support)
  - [Anti-Virus Support](#anti-virus-support)
- [Configuration](#configuration)
  - [Basic Setup](#basic-setup)
  - [Enabling Logging](#enabling-logging)
  - [Relay Authentication](#relay-authentication)
- [API Overview](#api-overview)
- [Usage Example](#usage-example)
- [License](#license)

--- 

## Overview

This module acts as an intermediary SMTP server. It accepts messages
via NaviServer or directly through its API and then forwards them to a
designated SMTP relay. This design enables integration with anti-spam
and anti-virus tools, providing an additional layer of email security.

### Anti-SPAM Support

Install one of the following to enable anti-spam features:

- **SpamAssassin:** [http://www.spamassassin.org/](http://www.spamassassin.org/)
- **DSPAM:** [http://www.nuclearelephant.com/projects/dspam/](http://www.nuclearelephant.com/projects/dspam/)  
  Patched version: [Download DSPAM 3.1.0 (Vlad)](http://www.crystalballinc.com/vlad/dspam-3.1.0-vlad-src.tar.gz)

### Anti-Virus Support

Install one of the following to enable anti-virus features:

- **ClamAV:** [http://www.clamav.net/](http://www.clamav.net/)
- **Sophos SAVI:** [http://sophos.com](http://sophos.com)

---

## Configuration

### Basic Setup

To enable the SMTPD module, add the following directives to your
NaviServer configuration file (e.g., `nsd.tcl`) Load the `nssmtpd.so`
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
  ns_param relaydomains "localhost domain.com"
  ns_param localdomains "localhost domain.com"
  ns_param spamd        localhost
  
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

### TLS context lifetime and certificate renewal

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

### Enabling Logging

For secure communication via STARTTLS and to enable logging, add these
parameters to the `nssmtpd` section.
  
```tcl
ns_section ns/server/${server}/module/nssmtpd {
  # ...
  # For logging "ns_smtpd send ..." operations
  ns_param logging    on           ;# default: off
  # ns_param logfile ${logroot}/smtpsend.log
  ns_param logrollfmt %Y-%m-%d     ;# rotation suffix for both send and event logs
  # ns_param logmaxbackup 100       ;# max number of backup log files
  # ns_param logroll true           ;# enable automatic log rolling
  # ns_param logrollonsignal true   ;# roll logs on SIGHUP
  # ns_param logrollhour 0          ;# specify the hour to roll logs
  # ...
}
```


The server log records ordinary relay denials and pre-DATA client EOF,
connection resets, and timeouts at `Notice` level. I/O failures during
DATA and internal errors remain at `Error` level. Diagnostics identify the
read or write operation and use its captured error, including TLS errors,
rather than a later value of `errno`. I/O diagnostics also include `last`
(the last SMTP command or connection stage, without arguments), and cumulative
connection byte counts `rx` and `tx`. These count successful SMTP reads and
writes, including partial transfers and traffic before and after STARTTLS,
but exclude TLS handshake and record framing bytes. Rejected input adds a cumulative `rejected` count and the most recent rejection's
`kind`: `unsupported-smtp` (a recognized but unimplemented SMTP verb),
`invalid-syntax`, `wrong-protocol`, `unknown-command`, `empty`, or `binary`
(including non-ASCII/control bytes). A `command` field contains only a complete
ASCII alphabetic token of at most 16 characters; arguments and other input
bytes are never included. Recognizable HTTP request lines or SSH identification
lines instead carry `protocol=HTTP` or `protocol=SSH`. Unknown extensions remain
`unknown-command`; the unsupported-command list is intentionally explicit.
`last` retains the last recognized SMTP command, whether accepted or rejected;
unrecognized input no longer replaces it with `UNKNOWN`. `rejected` counts
these input failures, not policy rejections or relay denials. Partial lines
which end before a newline contribute bytes but are not dispatched/classified.
Receive counts include
buffered read-ahead. RSET and new mail transactions do not reset the counters. Input excerpts are limited to 80 bytes
with control characters escaped; ordinary I/O diagnostics omit message data.

The existing `maxline` parameter (default `4096`) limits a received line,
including its line terminator. An oversized command receives `500 Line too
long`; an oversized DATA line receives `552 Data line too long`. The connection
is then closed without processing the remainder as another command or
accepting the message. Oversized relay replies also fail explicitly. This
limit is unchanged; the module no longer processes overlong lines as fragments.
Write readiness retries, including TLS retries, honor `writetimeout`.

### SMTP event logging

Optional authentication diagnostics can be added to the event Details:

```tcl
ns_section ns/server/$server/module/nssmtpd {
    ns_param eventlogging    true
    ns_param spfproc         smtpd::spfauto
    ns_param authdetailsproc smtpd::authdetails
}
```

`authdetailsproc` defaults to empty. It receives the SMTP session ID after
DATA headers have been parsed and before `dataproc`, independently of a custom
`dataproc`. It is informational: relay acceptance may already have happened.
Callback errors are logged without rejecting mail. Custom callbacks must not
change recipients, connection flags or SMTP replies.

`smtpd::authdetails` records the configured SPF evaluator's result, including
`none` (no SPF policy), `disabled`, `unavailable`, or `evaluation-error`.
It uses the actual connection peer, not a sender-supplied Received header;
replayed mail therefore describes the replaying relay. Local peers are marked
`not-checked-local`. Diagnostics run for every
completed external DATA transaction when this callback and event logging are enabled.

DKIM diagnostics require nsdns with `lookup -details -jointxt -timeout`.
They record each signature's domain, selector and key lookup status: `no-key`,
`revoked-key`, `key-present-not-verified`, or a distinct lookup/record error.
An unresolved CNAME is reported as such, not as an absent key. At most eight
signatures are inspected, with five seconds shared across DNS queries; repeated
key names are queried once per message. SPF has its evaluator's separate timeout.
**These checks do not verify DKIM signatures or evaluate DMARC policy.**

The `authentication` event is joined to the existing rows by server, session
and transaction in nsstats, where its metadata appears only under Details.
Old records cannot acquire diagnostics retroactively. Diagnostics run when
event logging or diagnostic headers are enabled. These observations do not
alter delivery. Explicit policy chains can use the same evaluators to decide
whether a message should be accepted.

To include link findings in mail forwarded through the configured relay:

```tcl
ns_param authdetailsproc   smtpd::authdetails
ns_param authdetailheaders true
```

`authdetailheaders` defaults to false. Enabling it buffers incoming relay DATA
up to `maxdata` before forwarding, overriding the fast-proxy buffer omission.
This adds memory use and diagnostic latency before the upstream transfer.
The original wire DATA, including signed headers, body and dot stuffing, is
preserved. Diagnostic failures omit additions without rejecting the message.
The default streaming relay path is unchanged. This option adds headers only
to the built-in relay path; custom delivery callbacks remain responsible for
their own output.

When findings exist, the callback returns a dynamic `ns_set` containing these fields:
`Nssmtpd-Link-Findings`, `Nssmtpd-Link-Host-Mismatch`, and
`Nssmtpd-Link-Embedded-Redirect`. The relay accepts only these names and bounded
ASCII values without control characters. These are informational custom
headers, not authentication verdicts or a spam classification.

To preserve DKIM, `smtpd::authdetails` omits any proposed name listed in any
DKIM-Signature or ARC-Message-Signature `h=` tag, including oversigned fields.
Malformed signature tags suppress all additions. Existing diagnostic fields
are neither replaced nor duplicated; received fields remain untrusted and must
not be interpreted as verified findings from this receiver. No Subject or body
rewriting, signature verification, or Authentication-Results header is added.
Custom callbacks returning header sets must provide equivalent
signature protection. Ownership of a returned set transfers to nssmtpd, which frees it after use.
An empty string means no additional headers.

The optional event log records incoming recipient decisions, applied alias
expansions, greylisting outcomes, and custom policy events. It is separate from
the existing SMTP send log and disabled by default:

```tcl
ns_section ns/server/${server}/module/nssmtpd {
  ns_param eventlogging true
  ns_param eventlogfile ${logroot}/smtpevents.log
  # ns_param eventlogroll true
  # ns_param eventlogrollhour 0
  # ns_param eventlogrollfmt %Y-%m-%d ;# optional override of logrollfmt
  # ns_param eventlogmaxbackup 100
  # ns_param eventlogrollonsignal false
}
```

Without `eventlogfile`, the filename is `smtpevents-${server}.log`. Relative
paths use the server log directory on NaviServer 5, or the home `logs`
directory on older versions. The resolved filename is published in the
configuration database for nsstats. Event-log rotation inherits `logroll`,
`logrollhour`, `logrollfmt`, `logmaxbackup`, and `logrollonsignal`, even when
send logging is disabled. Each corresponding `eventlog*` setting can override
the shared value. With neither setting configured, defaults are daily rotation
at midnight, numbered backups, 100 backups, and no rotation on SIGHUP.
Log enable switches and filenames remain independent.

Each SMTP transaction also emits a `transaction end` event before its envelope
is discarded. The reason distinguishes `quit-before-data`, `reset`, `disconnect`,
`aborted`, `transfer-failed`, `message-too-large`, `accepted`, `rejected`, and
`relay-accepted`. Details include the last command, received DATA bytes and,
when available, the relay's final reply (up to 511 bytes). DATA byte counts
include complete wire lines, including dot-stuffing, but exclude the terminator
and the generated Received header. An incomplete final line is not counted.
`relay-accepted=true` means the upstream accepted DATA, not final mailbox
delivery; it is retained even if replying to the original client then fails.

nsstats folds these records into matching session/transaction Details without
adding rows or changing recipient totals. Joining uses the selected log file;
older logs, active transactions and transactions spanning rotation may show
"Not recorded in this log". Logging remains disabled unless `eventlogging` is enabled.

Each physical line follows the access-log convention used by the SMTP send
log: a bracketed timestamp from `Ns_LogTime()`, the thread name, and fixed
positional fields separated by single spaces. The layout is:

```text
[timestamp] thread code event [peer] session transaction server sender recipient action reason target1,target2 key=value ...
```

For example, a greylisting deferral is recorded as:

```text
[29/Sep/2026:15:10:00 +0200] -nssmptd:12- 451 recipient [91.114.61.250] 1790690000-123456-8-12 1 openacs.org neumann@wu.ac.at webmaster@openacs.org defer greylist-new -
```

A separate `recipient` event records the resulting SMTP code, such as `451`.
The fixed fields are:

| Field | Meaning |
|---|---|
| `timestamp` | `DD/Mon/YYYY:HH:MM:SS ±HHMM`, including the UTC offset, as in the send log |
| `thread` | NaviServer thread name, as in the send log |
| `code` | SMTP response code, or `-` when the event has no response code |
| `event` | `recipient`, `alias`, `starttls`, or a custom event name |
| `peer` | Actual socket peer address, bracketed to support IPv6 |
| `session` | Identifier containing module start time, process and connection IDs |
| `transaction` | MAIL transaction counter within the session; zero before MAIL |
| `server` | Virtual server name |
| `sender` | Envelope sender |
| `recipient` | Original envelope recipient |
| `action` | Decision or operation, such as `accept`, `defer`, `reject`, or `expand` |
| `reason` | Reason such as `unknown-recipient`, `relay-denied`, `new`, or `retry` |
| `targets` | Comma-separated alias destinations |

Absent or empty fields are written as `-`. Within a field, spaces, control
bytes and backslashes are escaped as `\xHH`; for example, a space becomes
`\x20`. Quotes have no special meaning. Each field remains a single token,
so readers can split on spaces (the timestamp occupies two tokens).
Additional custom metadata is appended as `key=value` tokens with the same
escaping. The nsstats parser ignores this trailing metadata and displays
escaped field values literally, without decoding or evaluating log content.
The existing send-log format is unchanged.

Recipient events contain `recipient`, `action` (`accept`, `defer`, `reject`),
`code`, and `reason`. Alias events retain the original `recipient` and its
`targets`, and are emitted only for an applied, non-identity expansion.
Each RCPT attempt has one final `recipient` event. Policy details are folded
into it, with reasons `greylist-new`, `greylist-early`, `greylist-retry`,
`greylist-known`, `greylist-expired`, or `greylist-capacity`. LOCAL policy
bypasses use `local-bypass`. Custom policy results may supply a `reason`;
otherwise it defaults to `recipient-policy`. The final SMTP code and action
remain authoritative; a later alias failure or changed action takes precedence.
nsstats derives both recipient and greylisting charts from these records and
continues to read standalone greylist events in older logs.

STARTTLS failures produce a `starttls` event with action `fail`, reason
`context` or `handshake`, and the TLS diagnostic in a trailing `message=`
field. The fixed peer and session fields identify the actual connecting
client, even when failure occurs before MAIL or RCPT. No SMTP response code
is recorded for these events. The system log reports the same phase and
diagnostic, rather than the status of the preceding successful write.

Received messages acquire a leading `Received` header before buffered
processing or streaming relay. It records the actual socket peer (including
IPv6), server hostname, SMTP or ESMTPS transport, UTC time, and an identifier
of the form `session.transaction`, matching the event log's session and
transaction fields. Existing headers are preserved. This trace header is
added independently of event logging; direct `ns_smtpd send` does not add it.

During RCPT processing, `ns_smtpd logevent $id policy $details` attaches
metadata to the final recipient event instead of writing a separate row.
Other event names retain their independent logging behavior.

Within an SMTP callback, custom Tcl policies can call:


```tcl
smtpd::logevent $id policy [dict create \
    action reject reason denylist recipient $recipient code 550]
```

This wrapper does nothing when event logging is off and reports logging
errors without changing the SMTP decision. The underlying command is
`ns_smtpd logevent $id $event $detailsDict`; it requires the current callback
session, a lowercase event name of at most 64 letters/digits/underscores/hyphens,
and a dictionary of at most 16 KiB. The dictionary remains the Tcl API input;
it is serialized into the fixed fields above, with additional keys becoming
trailing `key=value` tokens. Keys must contain 1–64 letters, digits,
underscores or hyphens. A supplied `code` must be an integer from 100 to 599;
`targets` must be a Tcl list. Custom callbacks should use their own event
name or `policy`, leaving `recipient`, `alias`, and `greylist` to the built-in
emitters to avoid duplicate counts. Include only envelope/policy metadata,
not message content. No database is required.

The nsstats **SMTP Events** page provides separate charts for recipient
decisions and greylisting reasons, event totals, and the latest 200 matching
records. Its literal, case-insensitive filter covers peer, sender, original
recipient, targets, session, transaction, event, action and reason. Rotated
logs can be selected. Malformed or unsupported records are counted and skipped.
Never evaluate log records as Tcl code.

Recipient counts are SMTP RCPT attempts, **not delivered messages**;
greylisting deferrals are not spam classifications. Direct `ns_smtpd send`
operations continue to use the existing send log. Message outcomes and
connection/protocol events are not included in this first event-log version.

### Relay Authentication

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

Note that the USER:PWD infomation is passed in the "userinfo" part of
the URL (as defined in RFC 3207). To guarantee URL parsing, USER:PWD
has to be percent-encoded. This can be done e.g. with the NaviServer
command `ns_urlencode -part oauth1 $credentials`.

**Note:** The username and password (USER:PWD) are included in the
URL's "userinfo" segment, as defined by RFC 3207. To ensure correct
URL parsing, these credentials must be percent-encoded. For example,
you can use the NaviServer command `ns_urlencode -part oauth1 $credentials`
to perform this encoding.

**Security Note:** Be cautious when embedding credentials in
configuration files. To protect sensitive information, restrict file
permissions for the configuration file, verify user permissions on the
host machine, or consider using environment variables or reading
credentials from a secured file. Keep in mind that arbitrary Tcl
commands can be executed from within the configuration file.


## API Overview

### Optional envelope aliases

Alias handling is **disabled by default**. Omitting `aliasproc`, or setting
it to an empty string, preserves existing receiving and sending behavior.
No alias map, database connection, or queue is created implicitly.

To enable it, configure a Tcl command prefix in the module section:

```tcl
ns_section ns/server/${server}/module/nssmtpd {
  ns_param aliasproc mymail::aliases
  ns_param relaydomains "localhost openacs.org"
  ns_param localdomains "127.0.0.1"
  # Keep the existing delivery relay for this first implementation.
}
```

Define the callback in the server's Tcl library so it is available in every
interpreter:

```tcl
namespace eval mymail {}
proc mymail::aliases {args} {
    ns_parseargs {-recipient {-rejectunknown false}} $args
    switch -- $recipient {
        webmaster@openacs.org {
            return {maintainer@example.net backup@example.net}
        }
        default {
            # Pass through addresses that are not aliases.
            return [list $recipient]
        }
    }
}
```

The module appends -recipient followed by the envelope address. For LOCAL
submissions, direct sends and resolve calls it also appends -rejectunknown false.
Custom callbacks must accept these named arguments. The callback returns a Tcl list of
**final** envelope addresses. A command prefix with fixed arguments is also
supported, e.g. `ns_param aliasproc {mymail::aliases tenant1}`. The module
does not impose a storage backend: the proc can use a dictionary, file, or
an application API such as OpenACS. PostgreSQL is not required.

Callback contract:

- Return the original recipient as a one-element list for passthrough.
- Return one or more bare `user@domain` addresses for expansion. Display
  names and control characters are not accepted. The existing address
  parser defines the supported address syntax.
- Return an empty list to reject an unknown recipient. This is **not** a
  request to discard mail silently. For an alias-only local domain, the
  callback should reject unmapped local addresses rather than pass them through.
- Raise a Tcl error for a lookup/backend failure. Incoming SMTP returns
  `451`; an empty result or error code `NSSMTPD ALIAS UNKNOWN` returns `550`;
  exceeding `maxrcpt` returns `452`.
  Direct send/resolve calls return Tcl errors. Resolver failures never fall
  back to sending to the unresolved address.
- Resolve any alias chains inside the callback, with bounded recursion
  and cycle detection. The module calls it once per original recipient,
  not recursively. Final addresses should pass through unchanged if they
  traverse another alias-enabled submission path.
- The callback should perform lookups only; it must not send messages,
  call `ns_smtpd resolve` recursively, or mutate SMTP sessions. It can run
  concurrently in multiple interpreters.

Both SMTP reception and `ns_smtpd send` automatically use the configured
hook. Message headers and the envelope sender are unchanged. For receiving,
the original address first passes the existing peer/domain relay check, then
alias resolution, then `rcptproc`. Only accepted recipients are expanded; targets inherit that
recipient's flags and data, and domain routes are looked up for the targets.
`rcptproc` is not called again for each target. `dataproc` sees the expanded
list. Thus allowing a local alias to forward externally does not authorize
an untrusted peer to relay arbitrary external addresses.

Duplicate targets are removed within a single incoming expansion, or across
the recipient list of a direct send/resolve call. Separate incoming RCPT
commands retain the existing duplicate-recipient behavior. `maxrcpt` bounds
the expanded list and accounts for recipients already accepted in an SMTP
transaction. A failed expansion removes that original recipient without
removing previously accepted recipients.

For direct sending, expansion completes before any network connection.
Multiple expanded recipients use the explicit server or configured default
relay; they are not all routed through the first recipient's domain-specific
relay. This change does not add MX delivery or a persistent queue.

A transport-free command exposes the same resolution for application code
and a future Tcl queue:

```tcl
set recipients [ns_smtpd resolve {webmaster@openacs.org}]
```

It returns the original list unchanged when alias handling is disabled.
With aliases enabled, it shares the validation, deduplication and `maxrcpt`
limit of direct sending. Configuration belongs to the server/module; each
callback implementation owns its lookup backend. A future queue can use
the same approach with optional application-defined persistence procedures.

### Validated bounce-address fallback

The file resolver supports an optional `bouncevalidproc` command prefix. It is
called with the recipient as a positional argument only for an original recipient within
`aliasdomains` that matches no file alias (including virtual catch-alls).
It returns a boolean. True forwards to `bouncetarget`, which can itself be an
alias. False retains the usual `rejectunknownrecipients` behaviour. Errors or
non-boolean results cause a temporary SMTP failure (451).

For OpenACS with the public bounce validator installed:

```tcl
ns_section ns/server/${server}/module/nssmtpd {
    ns_param aliasproc smtpd::resolvefilealiases
    ns_param aliasfile /var/www/openacs/etc/mail/virtual
    ns_param aliasdomains {openacs.org}
    ns_param rejectunknownrecipients true
    ns_param bouncevalidproc acs_mail_lite::bounce_address_valid_p
    ns_param bouncetarget webmaster@openacs.org
}
```

The validator checks the configured bounce prefix and domain, signature and
expiry. Valid bounces expand through the configured webmaster alias. The target
is configurable; nssmtpd has no OpenACS or database dependency. Forwarding does
not process delivery-status reports or update OpenACS bounce counters.

Both settings default to empty. An unset or empty `bouncevalidproc` preserves
existing behaviour. Configuring a validator requires a bare envelope address
in `bouncetarget`; a missing or malformed target causes a configuration error
when the resolver is called. The resolver also accepts `-bouncevalidproc` and
`-bouncetarget` to override these settings. Fallback runs even with
`-rejectunknown false`, allowing tests with `ns_smtpd resolve` and consistent
local submission handling. Normal alias cycle checks, expansion limits and
final-recipient limits apply. Callbacks must not send mail or modify SMTP
sessions. Relay authorization and recipient policy checks still apply; this
does not exempt bounces from greylisting.

### Text alias files

`smtpd::resolvefilealiases` accepts named options
parsed by `ns_parseargs`: `-format` (`virtual` or `aliases`),
`-file` (map filename), and `-domains` (Tcl list of recipient domains).
Omitted options use the module settings `aliasformat`, `aliasfile`, and
`aliasdomains`, respectively. `aliasformat` defaults to `virtual`. File and
domains must each be provided either by an option or a module setting;
otherwise the callback raises a configuration error. Explicit options always
take precedence, including an explicitly empty domains list.
Options can appear in any order.
An empty domains list matches no domains. The module supplies the recipient with
`-recipient`, so a dash-prefixed address is unambiguous and no `--` separator is
needed. The `-rejectunknown` option defaults to `rejectunknownrecipients`
(`false` if unset). Custom command prefixes remain supported, but must accept
the new named arguments.

For a virtual map with strict incoming validation:

```tcl
ns_section "ns/server/$server/module/nssmtpd" {
    ns_param aliasfile               /var/www/openacs/etc/mail/virtual
    ns_param aliasdomains            {openacs.org}
    # ns_param aliasformat           virtual ;# default
    ns_param aliasproc               smtpd::resolvefilealiases
    ns_param rejectunknownrecipients true
}
```

These settings are read by the file resolver only and do not enable alias
resolution without aliasproc. The callback prefix may override them, for example
`{smtpd::resolvefilealiases -file /some/other/virtual}`.

The supplied `smtpd::resolvefilealiases` callback accepts an uncompiled traditional
`aliases` or Postfix `virtual` text file. For example:

```tcl
ns_section ns/server/${server}/module/nssmtpd {
    ns_param aliasproc [list smtpd::resolvefilealiases -format aliases -file /etc/aliases -domains {openacs.org}]
    ns_param relaydomains openacs.org
    ns_param localdomains 127.0.0.1
}
```

An aliases file can contain local names, bare local targets and full addresses:

```text
# Local names are looked up only in the configured domains.
webmaster: maintainers
maintainers: alice@example.net,
    bob@example.net
```

For virtual maps, use the command prefix
`[list smtpd::resolvefilealiases -file /etc/postfix/virtual -domains {openacs.org}]`:

```text
webmaster@openacs.org alice@example.net, bob@example.net
@openacs.org fallback@example.net
```

The module appends -recipient and the address after the configured options.
Both formats support blank lines, full-line `#` comments,
indented continuations and comma-separated destinations. Virtual maps also
accept destinations separated by spaces or tabs, including mixtures of
commas and whitespace. Empty comma-separated entries remain errors.
Classical aliases files require commas between destinations. Keys are matched
case-insensitively. Virtual exact-address keys take precedence over
`@domain` catch-alls. Bare targets acquire the domain of the address being
expanded. Chains are resolved within the configured domains, with cycle
detection, a 32-level depth bound and a 10,000-node work bound. A destination
equal to the address being expanded is terminal (an identity mapping).
Duplicate destinations are removed; the module also enforces `maxrcpt`.

Unmapped addresses and addresses outside `domains` pass through. This
provider does not assert that an unmapped local mailbox exists: deployments
that need unknown-user rejection can enable the incoming recipient policy
below. Listing a domain here does not authorize incoming relaying;
the existing `relaydomains` and recipient policy checks still apply.

This is an **address-forwarding subset**, not a full Postfix map interpreter.
It accepts simple unquoted local parts (letters, digits, `_ . + % -`) and
domains containing letters, digits, dots and hyphens. It does not implement
commands, file delivery, `:include:`, quoted/display-name addresses, inline
comments, owner/sender rewriting, automatic `+extension` stripping, virtual
bare-name/domain-marker keys, or `@otherdomain` destination rewriting.
Unsupported syntax and duplicate keys raise lookup errors; no commands or
Tcl code from the file are executed. Missing/unreadable files, malformed
entries and expansion failures produce temporary SMTP failure (`451`).

The text file is read and parsed once per in-scope recipient lookup, without
`newaliases`, `postmap`, or shared mutable cache state. Use atomic replacement
when updating it. Each lookup gets its own snapshot; updates can become
visible between recipients of the same transaction. Large maps or frequent
lookups can use a custom cached callback with the same interface. Nothing is
read unless this callback is explicitly configured. Both sending and receiving
use it; no PostgreSQL or other database dependency is added.

### Optional incoming recipient validation

The file resolver can reject unknown original recipients within `aliasdomains`:

```tcl
ns_section "ns/server/$server/module/nssmtpd" {
    ns_param aliasfile               /var/www/openacs/etc/mail/virtual
    ns_param aliasdomains            {openacs.org}
    ns_param aliasproc               smtpd::resolvefilealiases
    ns_param rejectunknownrecipients true
}
```

`rejectunknownrecipients` defaults to `false`. The resolver reads this setting
unless its `-rejectunknown` option supplies an override. An exact entry,
identity mapping or virtual catch-all establishes that a recipient is known.
Unknown recipients within the configured domains return `550 Unknown recipient`
when rejection is enabled. Other domains pass through this lookup; the existing
relay authorization still applies. Missing or malformed maps cause temporary
failure (`451`), never an unknown-user rejection.

For SMTP peers marked `LOCAL`, direct `ns_smtpd send`, and `ns_smtpd resolve`,
the module explicitly appends `-rejectunknown false`, overriding configuration
and fixed callback options. Unknown addresses then pass through, while known
aliases still expand. The connection peer determines LOCAL status, not the
sender or recipient address. A direct call to `smtpd::resolvefilealiases` without
`-rejectunknown` uses the configured default.

Resolution and the existence check use one file snapshot per original recipient.
The C module resolves after relay authorization and before `rcptproc` (including
greylisting), retaining the result until policy accepts the original recipient.
Only then does it replace the recipient with the saved destinations. Policy
rejection discards that result, preserving earlier recipients. Custom `rcptproc`
callbacks still see the original recipient. No separate membership callback is
needed: remove the former `recipientcheckproc` setting when migrating, and use
`rejectunknownrecipients true` to retain strict incoming validation. The removed
`smtpd::checkrecipient` and `smtpd::filealiasexists` helpers must also be removed
from custom Tcl code. Update custom alias callbacks to accept the named
`-recipient` and optional `-rejectunknown` arguments.

### Optional incoming policy and greylisting

To enable lightweight greylisting, add this to the existing module section.
Enable rejectunknownrecipients in the file resolver so unknown recipients are rejected before
creating greylist state. No database or additional daemon is needed.

```tcl
ns_section "ns/server/$server/module/nssmtpd" {
    ns_param recipientpolicyproc smtpd::greylist
    ns_param greylistdelay       300
    ns_param greylistretrywindow 14400
    ns_param greylistlifetime    604800
    ns_param greylistmaxentries  10000
}
```

`recipientpolicyproc` is disabled when unset or empty. The supplied
`smtpd::rcpt` invokes it after relay authorization and alias resolution/recipient validation,
before alias expansion and DATA. Trusted peers (`LOCAL`, set from
`localdomains`) bypass it. `ns_smtpd send` and `ns_smtpd resolve` do not invoke
it. Existing custom `rcptproc` callbacks are unchanged; to adopt greylisting,
call this helper before modifying the recipient or reply:

```tcl
if {![smtpd::checkpolicy $id]} {return}
```

The callback is a Tcl command prefix receiving one dictionary with `id`
(SMTP session ID), `peeraddr` (actual socket peer IP), `helo` (client HELO/EHLO identity), `sender` (envelope sender,
empty for a null sender), and `recipient` (original envelope recipient).
It must return a dictionary with `action` equal to `accept`, `defer`, or
`reject`. `accept` continues normal processing; it does not override later
checks. `defer` returns `451 4.7.1`, and `reject` returns `550 5.7.1`.
An optional `message` supplies 1–400 printable ASCII characters, without
newlines; otherwise a default message is used. Extra result keys are allowed.
Errors or invalid results produce `451 4.3.0 Recipient policy unavailable`.
Only the current recipient is removed on failure. Callbacks must not modify
SMTP sessions or send mail. The same interface can support a custom blacklist
or allowlist backed by Tcl or the OpenACS API, without a module database dependency.

`smtpd::greylist` uses the exact tuple of peer IP, envelope sender and original
recipient. A first attempt receives a temporary rejection. A retry at least
`greylistdelay` seconds later, but before `greylistretrywindow` seconds from the
first attempt, is accepted. Early retries do not extend either timer. Successful
retries allow that tuple for `greylistlifetime` seconds, refreshed on each
accepted attempt. A different sender or recipient creates a different tuple;
there is no blanket peer allowlist. The default values are five minutes, four
hours, seven days and 10,000 entries respectively. All values must be positive
integers; the retry window must exceed the delay.

State is shared by the server's Tcl interpreters and protected by a mutex.
Expired entries are reclaimed on incoming traffic, at most once per minute,
and an accessed expired entry is also removed immediately. At the configured
entry limit, new tuples **pass without being stored**, preserving existing
retry state and mail availability; the `capacity` log reason makes this visible.
This overload behavior weakens filtering and should be monitored.

`smtpd::init` initializes greylisting when a recipient policy is configured.
A custom `initproc` using greylisting must call `smtpd::greylistinit` once at
startup. Repeated initialization preserves existing entries. Missing
initialization causes a temporary policy failure.

Greylist entries are automatically preserved across orderly restarts in
`smtpgreylist-${server}.state` in the server's log directory. Use persistent
storage for that directory, or override the snapshot location:

```tcl
ns_param greylistfile /var/www/openacs/etc/mail/greylist.state
```

Relative `greylistfile` names are resolved against the server's log directory;
absolute paths are used directly. An empty value selects the default filename.
The directory must already exist and be writable. `ns_atprestartup` restores
pending and passed tuples before SMTP starts, and `ns_atshutdown`
saves a snapshot by atomic replacement. Original timestamps are retained;
expired entries and entries dated in the future are discarded on reload, and
`greylistmaxentries` bounds the restored table. File failures are logged without
preventing startup or mail processing. A missing file starts with an empty table.
The snapshot contains envelope addresses and peer IPs and is owner-readable.
An abrupt termination loses changes since the last orderly shutdown. Each
server instance needs its own file; this does not coordinate multiple instances.

Notice logs record policy deferrals/rejections and greylist `new`, `retry`,
`expired` and `capacity` decisions with envelope information. They contain no
message content. A passed greylist retry proves retry behavior, not sender
identity or absence of spam. Legitimate messages are delayed; sending systems
that change IP addresses between retries may be delayed repeatedly. Spammers
that retry can pass. This is a small SMTP policy, not content filtering. The
existing streaming relay still forwards before its message-data/spamd checks.

### Parsing and validating email addresses

```tcl
ns_smtpd parseemail {Example User <"john smith"@example.org>}
# localpart {john smith} domain example.org address {"john smith"@example.org} name {Example User}

ns_smtpd parseemail -syntax smtp {<"john smith"@example.org>}
# localpart {john smith} domain example.org address {"john smith"@example.org}
```

The default `header` syntax parses one complete mailbox, optionally with a
display name and angle brackets. Header comments and folding whitespace are
allowed between constituents; quoted local parts are decoded into `localpart`.
The `address` field retains the quoting/escaping needed for a valid mailbox.
`name` is present only for a display name. Groups, address lists, trailing
unparsed text, malformed domain labels/literals and unquoted spaces inside a
local part are rejected. Existing long local parts (including OpenACS bounce\naddresses) remain supported; parsing does not add a new SMTP mailbox-size\nrestriction. Domains are DNS-style labels or IPv4/IPv6 address
literals. Syntax validation performs no DNS lookup and grants no relay permission.

`-syntax smtp` parses a bare mailbox or angle path with SMTP quoting rules,
without header display names, comments or whitespace around `@`. It also accepts
`<>` as the null reverse path (empty `localpart` and `domain`), and validates and
ignores obsolete SMTP source routes. MAIL and RCPT use this syntax before any
normalization; a null RCPT is rejected. SIZE and BODY parameters of MAIL are
handled separately. Existing command-level handling of null senders remains.

Like `ns_parseurl`, a parse failure raises an ordinary Tcl error with a message
`Could not parse email "...": reason`, without a custom error code or partial
result. `ns_smtpd checkemail` uses the header parser and retains its string
contract: a valid serialized address or an empty string, without mutating its
Tcl input. It now rejects malformed addresses that the former phrase extractor
accepted. Header whitespace around `@` is legal; the corresponding SMTP path
is rejected. Valid local parts containing spaces remain quoted in the output.

### Explicit policy chains and accumulated findings

`recipientpolicyproc` remains a command prefix accepting an SMTP context and
returning an accept/defer/reject dictionary. Existing single callbacks keep
working. `smtpd::policychain rules context` also accepts an ordered list of Tcl
scripts. Each script sees `$context` and a shared `$findings` dictionary, can
call helpers or evaluate expressions, and returns `continue`, `accept`, `defer`,
`reject`, or a dictionary with `action`, optional `reason`, and optional `message`.
`continue` advances to the next script; any other action stops the chain. At the
end, the chain accepts. Tcl `continue`, `break` (accept), and `return` are also
supported. Errors and invalid results defer with reason `policy-rule-error`.
The result includes all accumulated `findings` and the one-based deciding
`policy-rule` index. These are included in event metadata. Rules are trusted
configuration scripts; they must not modify SMTP sessions or send mail.

RCPT contexts include `phase rcpt` and the original `recipient`. DATA contexts
include `phase data` and a `recipients` list (after alias expansion). Trusted
local clients bypass both policy hooks. Findings belong to one chain invocation;
there is no shared mutable dictionary across SMTP transactions or phases.

DKIM signatures are available only after DATA. Use `datapolicyproc` for a
combined SPF/DKIM rule. This optional hook runs before the built-in relay sends
message bytes or before `dataproc` for local delivery. It buffers relay DATA up
to `maxdata`, even without `authdetailheaders`, preserving original signed bytes
and dot stuffing. A rejection returns `550 5.7.1`; a deferral returns `451`.
Rejected messages are not queued by the relay. The event is `message-policy`,
and the transaction outcome is `message-policy-rejected`. Empty/unset leaves
the existing streaming behavior unchanged. Diagnostic callbacks remain purely
informational.

```tcl
ns_param spfproc smtpd::spfauto
ns_param recipientpolicyproc {
    smtpd::policychain {
        {smtpd::greylist $context}
    }
}
ns_param datapolicyproc {
    smtpd::policychain {
        {smtpd::spfpolicy $context findings}
        {smtpd::dkimkeypolicy $context findings}
        {
            if {[dict exists $findings spf-fail]
                && [dict exists $findings dkim-no-key]} {
                dict create action reject reason spf-fail-and-dkim-no-key \
                    message "Authentication policy failed"
            } else {
                continue
            }
        }
    }
}
```

`spfpolicy` collects `spf-result` and sets `spf-fail` only for `fail`; disabled,
unavailable, and evaluator-error results remain distinct. It always continues.
`dkimkeypolicy` collects the existing per-signature DNS diagnostics and sets
`dkim-no-key` only when at least one signature exists and **all** provided
signature keys are definitively absent. An unsigned message, a key lookup
error/timeout, invalid signature tags, any present/revoked key, or exceeding
the eight-signature limit does not produce that aggregate finding. Key presence
is not cryptographic verification. A DATA rejection affects all recipients of
the message. Neither configuring `spfproc` nor collecting findings implicitly
rejects mail; the visible chain owns the decision.

### Optional SPF-verified greylist exceptions

Large mail providers can retry from different IP addresses, repeatedly creating
new greylist tuples. A narrowly scoped exception can avoid this for wanted
report senders. Both settings below default to empty; existing installations
perform no SPF queries and retain their current policy.

```tcl
ns_section "ns/server/$server/module/nssmtpd" {
    ns_param recipientpolicyproc smtpd::greylist
    ns_param spfproc smtpd::spfquery
    ns_param greylistspfexceptions {
        {noreply-dmarc-support@google.com webmaster@openacs.org}
    }
}
```

The exception matches the exact, case-sensitive **envelope sender and original
recipient**, before alias expansion. Null envelope senders are not eligible for this exception, since the pair alone cannot constrain their HELO identity. Only an SPF `pass` for that pair bypasses
greylisting. Other results, disabled evaluation and callback errors follow
ordinary greylisting. Unmatched pairs do not cause an SPF lookup unless another
configured policy rule requests it. Relay authorization,
unknown-recipient rejection and later checks still apply. The recipient event
records an accepted exception with reason `verified-report-sender`.

SPF authorizes the connecting IP to send for the envelope identity. It does not
verify a DMARC report's contents, the visible From header, or DKIM signatures,
and does not establish that a message is free of spam. Do not exempt every
SPF-passing sender.

The SPF Tcl interface requires **NaviServer 5.0 or newer**, which provides
`ns_ip valid` for peer-address validation. SPF remains disabled by default;
this optional feature does not raise the minimum version for other module use.
With **nsdns supporting `lookup -details -jointxt -timeout`**, the optional
`smtpd::spf` backend evaluates SPF in Tcl, without an external executable:

```tcl
ns_section "ns/server/$server/module/nssmtpd" {
    ns_param spfproc smtpd::spf
}
# Test independently of the configured policy:
smtpd::spf -ip 209.85.160.73 \
    -sender noreply-dmarc-support@google.com -helo mail-oa1-f73.google.com
```

It implements the RFC 7208 mechanisms (`all`, `ip4`, `ip6`, `a`, `mx`,
`include`, `exists`, and `ptr`), `redirect`, and domain macros. It returns
only the SPF result; `exp` syntax is checked but explanation text is not
fetched. IPv4-mapped IPv6 peers use IPv4 policy. Invalid expanded names
produce `permerror`. Configuration/API errors remain Tcl errors; DNS
timeouts, network errors and unsuccessful DNS responses produce `temperror`.
Each completed call writes a system-log Notice prefixed `smtpd SPF Tcl:`,
including `peeraddr`, the original envelope `sender`, `helo`, `result`, and
`elapsed_ms`. This also applies to direct diagnostic calls and cache hits.
Unexpected evaluator errors are logged at Error severity with their error
code and are rethrown. Input control characters are rejected before logging.
Input validation uses Tcl's `string is print` (empty envelope senders remain
valid). Address-family and mapped-address checks use `ns_ip properties` and
`ns_ip match`, available in NaviServer 5.0. Tcl conversion is retained only
for extracting mapped IPv4 addresses and expanding IPv6 nibbles for macros;
no newer `ns_ip` operation is required.

The default evaluation deadline is 20 seconds; an explicit command prefix
such as `{smtpd::spf -timeout 30}` can change it (maximum 120 seconds).
All recursion shares the ten DNS-term and two void-lookup limits, with
additional MX/PTR and CNAME-chain bounds. Cache hits do not bypass limits.
Only DNS responses are shared via `ns_memoize`, keyed by normalized name
and record type. Their lifetime is bounded by DNS TTLs and capped at five
minutes. Negative caching requires an SOA and uses the smaller of its TTL
and MINIMUM. Transient errors are not cached. Complete SPF results are
never cached. To flush just this backend's DNS cache:

```tcl
ns_memoize_flush {::smtpd::SpfDnsFetch *}
```

Load nsdns on the same server as nssmtpd and configure its upstream resolver.
The required nsdns options are available in the October 2026 interface
update; older nsdns builds cannot be used with this backend. Selection is
explicit: installing nsdns does not change an existing `spfproc` setting.
The greylisting exception rules above remain unchanged.

For automatic runtime selection, configure:

```tcl
ns_param spfproc smtpd::spfauto
```

The callback checks availability on its first call and caches the selected
backend per interpreter, preferring the Tcl evaluator over external `spfquery`.
An unavailable result is cached as well. The initial decision is logged at
Notice severity once per interpreter, including when no backend is available.
Detection performs no DNS query or external execution. It checks the nsdns
option list or the installed executable
and nsproxy command; the executable is expected to be libspf2-compatible.
It does not retry another backend after an SPF result or an evaluation error.
Restart after changing installed backend availability.

If neither backend is available, `smtpd::spfauto` returns an empty value.
`smtpd::checkspf` reports this as `NSSMTPD SPF DEPENDENCY`, and greylisting
continues without an SPF exception. This differs from SPF `none`, which means
that the identity has no published SPF policy. Explicit `smtpd::spf` and
`smtpd::spfquery` callbacks remain supported; no configuration-time sourcing
or detection is needed. An empty `spfproc` still disables SPF evaluation.

For low-volume installations, `smtpd::spfquery` runs the external **libspf2**
utility. No native SPF support or development headers are needed. By default,
it uses `spfquery` in NaviServer’s configured helper directory:
`[file join [ns_info bindir] spfquery]`. This is the stable symlink
created by install-ns when nssmtpd is selected and the runtime package is
available. It follows NaviServer’s bindir setting rather than the location of the nsd binary.
Use `ns_param spfproc smtpd::spfquery`; `-command /absolute/path` remains an
override. The similarly named Perl Mail::SPF utility is not compatible.

Images rebuilt from the updated install-ns and nssmtpd sources need no extra
package setting when the installer has created the link. For images without
that link, install the package and configure an explicit executable:

| Container | Extra package | `spfproc` |
| --- | --- | --- |
| Debian Trixie | `spfquery` | `{smtpd::spfquery -command /usr/bin/spfquery.libspf2}` |
| Alpine | `libspf2-tools` | `{smtpd::spfquery -command /usr/bin/spfquery}` |

The docker-ns OpenACS container installs extra packages from the lowercase
`system_pkgs` environment variable on its **first startup**. Add the package to
any existing extra-package list in Compose, for example:

```yaml
environment:
  system_pkgs: "spfquery"  # Trixie; use "libspf2-tools" on Alpine
```

Recreate the container after changing this setting; a restart of an already
initialized container does not rerun package installation. No `WITH_SPF2=1`,
installer changes, or additional service are required. The image must include
this version of the Tcl adapter.

The adapter requires NaviServer's `nsproxy` module. Load it in the server's
modules section if it is not already present:

```tcl
ns_section "ns/server/$server/modules" {
    ns_param nsproxy nsproxy.so
}
```

It uses `ns_proxy eval` with a default 10-second evaluation timeout and releases
its proxy in a `finally` block, including after errors. Callback option
`-timeout 15` changes the timeout in seconds; the same limit applies separately
to waiting for a proxy handle. Option `-pool smtpd-spf` selects the proxy pool
(the default is `smtpd-spf`). Pool concurrency can be bounded with
`ns_proxy configure smtpd-spf -maxslaves 2` during startup. No external `timeout`
program is required.

An SMTP worker waits for each evaluation, so this backend is intended for low
volume and narrowly scoped exceptions. It has no persistent DNS cache. Output
is discarded and libspf2's exit status determines the SPF result. Missing tools,
proxy timeouts, crashes and unexpected statuses raise Tcl errors; the greylist
policy logs these and retains normal greylisting. A proxy timeout bounds the
caller's wait; nsproxy manages worker cleanup, not a process-group deadline for
all descendants of an external command. There is no automatic switch from a
configured native backend: choose this adapter explicitly via `spfproc`.

The optional native backend (`ns_param spfproc smtpd::libspf2`) additionally
requires a maintained libspf2 installation:

```sh
make clean
make WITH_SPF2=1
```

For nonstandard library locations, provide `SPF2_CFLAGS=-I/path/include` and
`SPF2_LIBS='-L/path/lib -lspf2'`. The default build has no libspf2 dependency.
The library and its runtime dependencies must also be present in the container.
Its resolver performs synchronous DNS lookups using system resolver timeouts;
SPF evaluation occupies the calling SMTP worker while they run. Each evaluation
owns and releases its library context, with no persistent module-wide DNS cache.

The public Tcl interface is:

```tcl
smtpd::checkspf -ip 209.85.167.202 \
    -sender noreply-dmarc-support@google.com -helo mail-example.google.com
```

It invokes `spfproc` as a command prefix with the named arguments `-ip`,
`-sender`, and `-helo`. The evaluator must return exactly one of `pass`, `fail`,
`softfail`, `neutral`, `none`, `temperror`, or `permerror`. A null sender is passed
as an empty string and must be evaluated using the HELO identity. The supplied
`smtpd::libspf2` adapter calls `ns_smtpd spf ip sender helo`; without library support
that command raises `NSSMTPD SPF UNAVAILABLE`. `smtpd::checkspf` raises
`NSSMTPD SPF DISABLED` if no evaluator is configured. Custom Tcl callbacks can
use another SPF implementation and provide their own caching/time limits.

`ns_smtpd gethelo id` exposes the actual client HELO/EHLO identity, rather than
the reverse DNS hostname. It is retained across MAIL/RSET and cleared after
STARTTLS and at session release. The policy context includes it as `helo`.
SPF evaluation alone does not impose a delivery decision. Use explicit policy
rules to interpret the result, as shown below. Outbound MX routing for future direct delivery remains separate.

For deployment, first run `make test`.
 After enabling the setting, verify from
an **untrusted external client** that a known alias receives `451` initially,
then `250` when the identical tuple retries after five minutes; send the message
with DATA to confirm delivery. An unknown local recipient should still receive
`550 Unknown recipient`, and an unrelated external destination should still
receive `550 ... Relaying denied`. Confirm outgoing OpenACS mail still works.
A manual `ns_smtpd resolve` does not exercise this incoming policy.

To run the isolated tests (Tcl 8.6+, OpenSSL CLI and an installed
NaviServer with OpenSSL support needed):

```sh
make test
# Optional: select an installation or filter test cases.
make test NAVISERVER=/usr/local/ns TCLTESTARGS='-match nssmtpd-*'
```

These tests use ephemeral loopback ports and a local SMTP sink. They exercise
basic `ns_sendmail` and `ns_smtpd send` submission as well as
unset/empty hooks, incoming and outgoing expansion, rejection and temporary
failures, recipient limits, callback compatibility and relay authorization.
The plain SMTP sink uses NaviServer's `ns_connchan` listener and callbacks.
Forwarding through STARTTLS uses a second nssmtpd instance within the test
server, since `ns_connchan` does not provide a STARTTLS-upgrade operation.
They do not contact external mail servers or require a database.
`make test` builds the module and runs the Tcl harness; it needs neither a
local Postfix service nor the `nsadmin` account. Failed tests cause a nonzero
make exit status. Aggregate envelope checks are skipped when filtering cases.

The module is managed via a single Tcl command, `ns_smtpd`, which
provides an extensive set of operations for interacting with the SMTP
server. Below is a summary of available commands:

- **General Commands:**
  - `ns_smtpd flag /name/`
  - `ns_smtpd send /sender_email/ /rcpt_email/ /data_varname/ ?server? ?port?`
- **Relay Management:**
  - `ns_smtpd relay add /domain/`
  - `ns_smtpd relay check /address/`
  - `ns_smtpd relay clear`
  - `ns_smtpd relay del /domain/`
  - `ns_smtpd relay get`
  - `ns_smtpd relay set /relay/ ?relay? ...`
- **Local Domains/IPs:**
  - `ns_smtpd local add /domain|ipaddr|`
  - `ns_smtpd local check /ipaddr|`
  - `ns_smtpd local clear`
  - `ns_smtpd local del /domain|ipaddr|`
  - `ns_smtpd local get`
  - `ns_smtpd local set /ipaddr/ ?ipaddr? ...`
- **Data Encoding/Decoding:**
  - `ns_smtpd encode /base64|hex|qprint/ /text/`
  - `ns_smtpd decode /base64|hex|qprint/ /text/`
- **Validation and Versioning:**
  - `ns_smtpd parseemail ?-syntax header|smtp? ?--? /email/` *(Returns parsed address constituents as a dictionary)*
  - `ns_smtpd checkemail /email/` *(Returns the parsed address, or an empty string on invalid input)*
  - `ns_smtpd checkdomain /domain/`
  - `ns_smtpd virusversion` &nbsp;&nbsp;&nbsp; *(Returns anti-virus tool version)*
  - `ns_smtpd spamversion` &nbsp;&nbsp;&nbsp; *(Returns anti-spam tool version)*
- **Spam and Virus Checks:**
  - `ns_smtpd checkspam /message/ ?email?`
  - `ns_smtpd trainspam 1|0 /email/ /message/ ?signature? ?mode? ?source?`
  - `ns_smtpd checkvirus /data/`
- **Session and Message Handling:**
  - `ns_smtpd sessions`
  - `ns_smtpd gethdr /name/`
  - `ns_smtpd gethdrs ?name?`
  - `ns_smtpd getbody`
  - `ns_smtpd getfrom`
  - `ns_smtpd getfromdata`
  - `ns_smtpd setfrom /address/`
  - `ns_smtpd setfromdata /data/`
  - `ns_smtpd getrcpt ?address|index?`
  - `ns_smtpd getrcptdata ?address|index?`
  - `ns_smtpd addrcpt /address/ ?flags? ?data?`
  - `ns_smtpd setrcptdata /address|index/ /data/`
  - `ns_smtpd delrcpt /address|index/`
  - `ns_smtpd setflag /address|index/ /flag/`
  - `ns_smtpd unsetflag /address|index/ /flag/`
  - `ns_smtpd getflag ?address|index?`
  - `ns_smtpd setreply /reply/`
  - `ns_smtpd getline`
  - `ns_smtpd dump /filename/`

The provided source code of the Tcl files  provide more details about
using the API.


## Usage Example

Once configured, the SMTPD module will act as an SMTP server, forwarding messages to the relay specified by the `relay` parameter. Additionally, you can interact with it via the `ns_smtpd` command to perform actions such as sending mail, checking spam/virus status, and managing session data.

For example, to send an email using the API:

```tcl
set message "From: sender@example.com
To: recipient@example.com
Date: [ns_httptime [clock seconds]]
Subject: Testmail
 
This is a test mail!
"

ns_smtpd send sender@example.com recipient@example.com message localhost 25
```

This command will deliver the message to the configured SMTP relay,
applying potentially anti-spam or anti-virus checks along the way.

---

## Licensing

This project is licensed under the Mozilla Public License, v. 2.0.
A copy of the MPL can be obtained from https://mozilla.org/MPL/2.0/.

---

## Authors

- **Vlad Seryakov** - <vlad@crystalballinc.com>
- **Gustaf Neumann** - <neumann@wu-wien.ac.at>

### SMTP receive failures

Outgoing `ns_smtpd send` reports the SMTP phase and destination for receive
failures, with Tcl error codes `{NSSMTPD READ TIMEOUT}`, `{NSSMTPD READ EOF}`
or `{NSSMTPD READ ERROR}`. For example, a silent SMTP peer produces
`nssmtpd: send: greeting read from mail-relay:25 failed: timeout after 60 seconds`
instead of reporting a stale `Resource temporarily unavailable` error.
Relay greeting failures use the captured receive error as well.

The local receive implementation handles both would-block values, interrupted
operations, and TLS WANT_READ/WANT_WRITE through readiness waits. Retries share
one deadline per receive-buffer refill; this is not an overall SMTP transaction
or line deadline. `readtimeout` retains its existing configuration and default.
No private driver socket fields or new NaviServer socket accessors are required.
The test suite includes silent peers, EOF, truncated greetings, EOF after HELO,
and successful delivery after a delayed greeting, using `ns_connchan` fixtures.

HTML link diagnostics are also included in `authdetailsproc` Details. They flag
hostname link text that differs from the actual URL host, and URL-valued query
parameters pointing to another host. These are informational indicators, not
spam verdicts: legitimate tracking links can produce the same findings. No links
are fetched and only hostnames are logged, not URL paths or recipient-bearing
queries. At most one example of each indicator is retained per message.

Link inspection requires Tcllib `mime` and NaviServer HTML/URL parsing commands.
It decodes quoted-printable/base64 HTML, including multipart messages. Messages
over 256 KiB are skipped; traversal is limited to 64 MIME parts and 100 anchors
per HTML part. `link-status` reports missing dependencies, skipped messages, or
parse errors; `link-limit` reports anchor truncation. An inspected message with
no findings is not a guarantee that all phishing techniques were checked.

### Parsed header sets (NaviServer 5+)

`ns_smtpd headers $id` returns a detached, case-insensitive `ns_set` in parsing
order, retaining duplicate fields and empty values. NaviServer reclaims this
temporary set when the SMTP connection ends (which may span multiple mail
transactions). Changes to this copy do not affect the SMTP transaction.
The parsed view retains the existing address normalization; it is not a raw
representation suitable for signature verification or reserializing received mail.

`gethdr` and `gethdrs` keep their existing reverse parsing order and filtering of
empty values in named lookups. Forwarding uses the original wire data, not a
serialization of the parsed set. NaviServer 4.99 remains a compilation target;
the new case-insensitive Tcl interface and diagnostic features target 5+.

SMTP `readtimeout` and `writetimeout` accept NaviServer time values such as
`500ms`, `1.5s`, or `1m`; both default to `60s`. Unitless values remain seconds.
The optional `segvtimeout` uses the same syntax, retaining its default `-1`
(no delay before termination).

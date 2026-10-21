# Trace mail delivery and investigate problems

[Administration guide](../README.md)

Start here when a sender reports a rejection, a recipient cannot find mail,
or a policy outcome needs explanation. Send logging, event logging and the
system log answer different questions; upstream SMTP acceptance is not proof
of final mailbox delivery.

Tasks in this guide:

- [Choose the evidence for the question](#choose-the-evidence-for-the-question)
- [Enable the send log](#enable-the-send-log)
- [Enable the event log and rotation](#enable-the-event-log-and-rotation)
- [Use the nsstats pages](#use-the-nsstats-pages)
- [Add authentication and link diagnostics](#add-authentication-and-link-diagnostics)
- [Expose read-only diagnostics through MCP](#expose-read-only-diagnostics-through-mcp)
- [Follow a rejected, missing or delayed message](#follow-a-rejected-missing-or-delayed-message)

## Choose the evidence for the question

| Task | Where to look |
| --- | --- |
| Did an outgoing attempt reach the relay? | SMTP Sent log: source, result and relay outcome |
| Why was a recipient deferred or rejected? | SMTP Events: original recipient, action, SMTP code and reason |
| Where did an alias forward? | SMTP Events: original recipient and expanded targets |
| What happened after DATA? | Event Details: transaction end, DATA policy and findings |
| Was mail retained instead of forwarded? | Sent log's Quarantine view; inspect state and findings |
| Did TLS or socket I/O fail? | System log: phase and captured diagnostic |
| What happened across several rows? | Correlate server, session and transaction within the selected log |

## Enable the send log

To record direct sends and incoming forwarding attempts, add these
parameters to the `nssmtpd` section. STARTTLS is configured independently.

```tcl
ns_section ns/server/${server}/module/nssmtpd {
  # ...
  # Log direct sends and incoming forwarding attempts
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

## Enable the event log and rotation

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

## Use the nsstats pages

`make install` installs `lib/nsstats-sent.adp`, `lib/nsstats-events.adp`
and their shared `lib/nsstats.tcl` beneath the module Tcl directory.
During startup, `nssmtpd-nsstats.tcl` publishes both pages in the server-scoped
`nsstats:plugins` registry under provider `nssmtpd`. An nsstats version with
page-registry support displays them in **Logs**, retaining the existing
`?@page=log.smtpsent` and `?@page=log.smtpevents` URLs. Restart after first
installation to publish the registry entries; subsequent page changes deploy
with nssmtpd. Nsstats is optional and need not be loaded during registration.

The sent-log page includes quarantine inspection, escaped message previews,
`.eml` downloads and confirmed manual release. These use the host's admin
access checks and admin-bound POST token. Direct download/error responses
produce no additional page markup. Recovery, uncertain-delivery retries and
deletion remain nscp operations. The event page provides SMTP diagnostics,
recipient decisions and greylisting charts. Shared file selection and chart
helpers come from nsstats; SMTP parsing, rendering and styles live here.

The nsstats **SMTP Events** page provides separate charts for recipient
decisions and greylisting reasons, event totals, and the latest 200 matching
records. Its literal, case-insensitive filter covers peer, sender, original
recipient, targets, session, transaction, event, action and reason. Rotated
logs can be selected. Malformed or unsupported records are counted and skipped.
Never evaluate log records as Tcl code.

Recipient counts are SMTP RCPT attempts, **not delivered messages**;
greylisting deferrals are not spam classifications. The send log records both direct `ns_smtpd send` operations and incoming
SMTP forwarding attempts. New records append a tab-separated `source=send`
or `source=relay` attribute after the recipient list; older records have no
source attribute. `SUCCESS` means acceptance by the upstream SMTP server,
not final mailbox delivery. Relay failures and policy/size rejections are
also recorded; failed attempts report zero sent bytes. Relay elapsed time
covers the forwarding attempt, including time spent receiving client DATA.

## Add authentication and link diagnostics

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
They record each signature's algorithm, domain, selector and key lookup status: `no-key`,
`revoked-key`, `key-present-not-verified`, or a distinct lookup/record error.
`rsa-sha1` produces a per-signature `algorithm-status obsolete` and a shared
`dkim-obsolete-algorithm true` finding, independent of key availability. This
is an algorithm diagnostic, not a cryptographic signature check.
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

### Inspect links without fetching them

HTML link diagnostics are also included in `authdetailsproc` Details.
`link-destination-hosts` records up to 100 unique HTTP(S) anchor destination
hosts per message, including generic buttons such as "View Document".
`link-destination-limit exceeded` indicates additional hosts were omitted.
They also flag
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

## Expose read-only diagnostics through MCP

Nssmtpd installs `mcp/smtp-tools.tcl` and announces its provider through the
server-scoped `nsmcp:providers` registry from `nssmtpd-mcp.tcl`. This needs no
nsmcp dependency at SMTP startup. With the updated nsmcp installed, configure
the dedicated MCP subsection:

```tcl
ns_section ns/server/$server/module/nssmtpd/mcp {
    ns_param enabled true
    ns_param logReadBytes 1MiB
}
```

The installed `examples/mcp-config.tcl` provides this block. Defaults are disabled
and a 1MiB read budget (maximum 16MiB). Explicit false disables the provider;
empty or invalid values are errors. Endpoint and credential settings remain in
nsmcp. Install both updated modules and restart after migration.

The existing **smtp_logs** tool and arguments are unchanged. It reads configured
event or send logs, including delivery outcomes, policy findings and quarantine
event identifiers when recorded; it does not send mail, change settings or
release quarantined messages. Log access requires `diagnostics.logs.read`;
explicit peer disclosure additionally requires `diagnostics.logs.peers.read`.
Paths come from the authenticated server's loaded module configuration, never
from callers. Redaction, bounded reads, current-file coverage and per-server
runtime tool switches remain in effect. No message bodies are exposed.

## Follow a rejected, missing or delayed message

1. Find its sender, original recipient or session on **SMTP Events** and inspect
   the final recipient action and SMTP reply. A greylist `451` is a deferral;
   it is not a delivered message or a spam verdict.
2. Inspect DATA policy findings and the transaction outcome. If it was held,
   use the [quarantine workflow](quarantine.md) rather than expecting a relay
   delivery record.
3. For forwarded mail, check **SMTP Sent** and the upstream reply. Continue
   with the upstream server's logs when it accepted the message.
4. Select rotated logs when necessary. A transaction spanning rotation or an
   older record may lack joined details; missing evidence is not proof that
   a phase did not happen.
5. For transport failures, inspect the [I/O and protocol diagnostics](log-reference.md#interpret-system-log-io-and-protocol-diagnostics).

For raw event-field meanings or custom readers, see the
[log reference](log-reference.md). For unavailable admin pages, check that the
module's Tcl/ADP files were installed and that the server restarted after the
initial provider installation.

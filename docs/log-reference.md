# Read raw SMTP logs and transport diagnostics

[Administration guide](../README.md)

This reference supplements the administrator's
[delivery investigation workflow](monitoring.md). Event records count SMTP
operations, not unique messages or final mailbox deliveries. Treat all log
values as data, never executable Tcl.

## Parse event records and custom metadata

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

The `recipient` event records the resulting SMTP code, such as `451`.
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
escaping. The SMTP admin reader decodes supported trailing metadata without evaluating
commands or variables. Fixed positional values retain their escaped form.
Mail-controlled values are escaped when rendering HTML.
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

## Interpret system-log I/O and protocol diagnostics

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

## Diagnose receive failures by phase

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

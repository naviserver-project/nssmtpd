
# SMTPD Server/Proxy for NaviServer

**Release:** 2.7  
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

### Enabling Logging

For secure communication via STARTTLS and to enable logging, add these
parameters to the `nssmtpd` section.
  
```tcl
ns_section ns/server/${server}/module/nssmtpd {
  # ...
  # For logging "ns_smtpd send ..." operations
  ns_param logging    on           ;# default: off
  # ns_param logfile ${logroot}/smtpsend.log
  ns_param logrollfmt %Y-%m-%d     ;# format appended to log filename
  # ns_param logmaxbackup 100       ;# max number of backup log files
  # ns_param logroll true           ;# enable automatic log rolling
  # ns_param logrollonsignal true   ;# roll logs on SIGHUP
  # ns_param logrollhour 0          ;# specify the hour to roll logs
  # ...
}
```


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
(SMTP session ID), `peeraddr` (actual socket peer IP), `sender` (envelope sender,
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
startup. Initialization clears previous state; do not call it per connection.
State is in memory only: restarting NaviServer resets it, and the next delivery
may be delayed again. There is no persistence or cross-instance coordination
in this first implementation. Missing initialization causes a temporary policy
failure, not an unfiltered acceptance.

Notice logs record policy deferrals/rejections and greylist `new`, `retry`,
`expired` and `capacity` decisions with envelope information. They contain no
message content. A passed greylist retry proves retry behavior, not sender
identity or absence of spam. Legitimate messages are delayed; sending systems
that change IP addresses between retries may be delayed repeatedly. Spammers
that retry can pass. This is a small SMTP policy, not content filtering. The
existing streaming relay still forwards before its message-data/spamd checks.

For deployment, first run `make test`. After enabling the setting, verify from
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
  - `ns_smtpd checkemail /email/` &nbsp;&nbsp;&nbsp; *(Returns a valid email in the form name@domain)*
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

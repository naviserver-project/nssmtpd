# Route recipients and maintain aliases

[Administration guide](../README.md)

Use this guide to receive mail for selected domains, forward named addresses,
and reject unknown recipients. Alias processing is opt-in and does not require
a database. Start with a text map; use a callback when routing depends on an
application or another data source.

Tasks in this guide:

- [Configure and update a text alias map](#configure-and-update-a-text-alias-map)
- [Reject unknown incoming recipients](#reject-unknown-incoming-recipients)
- [Accept validated OpenACS bounce addresses](#accept-validated-openacs-bounce-addresses)
- [Implement application-specific alias routing](#implement-application-specific-alias-routing)
- [Verify recipient changes](#verify-recipient-changes)

## Configure and update a text alias map

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
that need unknown-user rejection can enable [unknown-recipient rejection](#reject-unknown-incoming-recipients). Listing a domain here does not authorize incoming relaying;
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

### Override resolver options

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

## Reject unknown incoming recipients

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

## Accept validated OpenACS bounce addresses

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

## Implement application-specific alias routing

Alias handling is **disabled by default**. Omitting `aliasproc`, or setting
it to an empty string, preserves existing receiving and sending behavior.
No alias map, database connection, or queue is created implicitly.

To enable it, configure a Tcl command prefix in the module section:

```tcl
ns_section ns/server/${server}/module/nssmtpd {
  ns_param aliasproc mymail::aliases
  ns_param relaydomains "localhost openacs.org"
  ns_param localdomains "127.0.0.1"
  # Keep the configured delivery relay.
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

## Verify recipient changes

Test an alias, an unknown address in the configured domain, and an unrelated
external domain from an untrusted SMTP peer. The outcomes should distinguish
successful expansion, unknown-recipient rejection and relay denial. A manual
`ns_smtpd resolve` is useful for expansion checks but deliberately bypasses
strict incoming validation and recipient policy. Check the original recipient
and expanded targets in [SMTP Events](monitoring.md#use-the-nsstats-pages).

# Delay or hold suspicious incoming mail

[Administration guide](../README.md)

Use this guide for untrusted incoming mail: enable greylisting, choose an SPF
evaluator, then apply explicit DATA decisions. For initial review, combine
rejections with [persistent quarantine](quarantine.md) so held messages can be
inspected and released. No policy decision is enabled merely by collecting
findings or configuring SPF.

Tasks in this guide:

- [Choose where a decision belongs](#choose-where-a-decision-belongs)
- [Enable greylisting and preserve its state](#enable-greylisting-and-preserve-its-state)
- [Choose and test an SPF evaluator](#choose-and-test-an-spf-evaluator)
- [Apply validated DATA rules](#apply-validated-data-rules)
- [Exempt a narrowly scoped verified report sender](#exempt-a-narrowly-scoped-verified-report-sender)
- [Verify policy changes before relying on them](#verify-policy-changes-before-relying-on-them)

## Choose where a decision belongs

Recipient policy runs at RCPT, on the original recipient before alias expansion.
DATA policy runs after message headers/body are available and before built-in
forwarding. A DATA decision affects the whole message and all accepted recipients.
Trusted/local and authenticated submission bypasses remain in effect; test with
an untrusted client. DATA policy buffers relay mail up to `maxdata`.

Use `smtpd::standardpolicy` for the supported authentication, retry-count and
exact-link-host checks. See [custom policy callbacks](policy-reference.md) only
when those options do not express the rule you need.

## Enable greylisting and preserve its state

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
it. Custom recipient callbacks are described in the
[policy reference](policy-reference.md#implement-a-recipient-policy-callback).

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

## Choose and test an SPF evaluator

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
The [verified report-sender exception](#exempt-a-narrowly-scoped-verified-report-sender)
uses these evaluator results; installing nsdns alone does not enable it.

### Select a backend automatically

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

### Use an external libspf2 helper

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

### Build with native libspf2 support

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

### Test the configured evaluator

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
rules to interpret the result, as shown in [validated DATA rules](#apply-validated-data-rules).
Outbound MX routing remains separate.

## Apply validated DATA rules

For the common authentication, retry and exact-link-host checks, prefer the
validated command prefix below instead of embedding Tcl decision scripts:

The link-host list below comes from operator-confirmed spam examples. Maintain
an exact list based on your own review; it does not block every site on the
same hosting service. See [quarantine review](quarantine.md) for held messages.

```tcl
ns_param datapolicyproc {
    smtpd::standardpolicy
    -rejectSpfFailWithoutDkimKey true
    -maxGreylistEarlyRetries 10
    -blockedLinkHosts {
        accuse-de-reception-de-courrier-recommande-3.jimdosite.com
        voir-mon-doc-1.jimdosite.com
    }
}
```

`smtpd::standardpolicy` calls `collectfindings` once, preserving seeded recipient
and greylisting findings. It checks authentication first, then retry count, then
link hosts. Rejection reasons remain `spf-fail-and-dkim-no-key`,
`excessive-greylist-early-retries` and `known-spam-link-host`; a link rejection
also records `blocked-link-host`. No match returns `accept: policy-chain-end`.
The retry threshold is inclusive: 10 rejects at 10 or more early retries.

All checks default to disabled: the boolean defaults to false, the retry limit
to `{}` and the host list to `{}`. Hostnames are exact matches, normalized to
lower case without a trailing dot; URLs and wildcard patterns are invalid.
Use ASCII/punycode hostnames. This does not block the entire hosting domain.

The default `smtpd::init` calls `smtpd::policyinit` to validate a direct
`smtpd::standardpolicy` or `::smtpd::standardpolicy` prefix at startup without
inspecting messages or doing DNS. Unknown/duplicate options, invalid booleans,
nonpositive retry limits and invalid hosts produce startup errors. Custom
`initproc` callbacks must call `smtpd::policyinit` as well. Options are also
validated on invocation; a runtime failure is handled as a temporary policy
failure. Validation does not execute arbitrary custom policy callbacks.

See [the complete quarantine configuration example](../examples/datapolicy-config.tcl).
`policychain` and the individual collectors remain available for custom rules.

Findings such as SPF pass, DKIM key presence or successful greylist retry do
not establish that a message is legitimate. `dkim-no-key` is set only when a
signature exists and every supplied signature key is definitively absent;
unsigned mail does not set it. DKIM signatures are not cryptographically verified.
The early-retry count belongs to a peer/sender/original-recipient tuple, not
necessarily one message. With multiple recipients the transaction counter is
the maximum of the accepted original recipients, not a sum. See the
[findings reference](policy-reference.md#retain-recipient-provenance-at-data).

## Exempt a narrowly scoped verified report sender

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

## Verify policy changes before relying on them

First [run the regression tests](development.md#run-isolated-smtp-regression-tests).
After enabling greylisting, verify from
an **untrusted external client** that a known alias receives `451` initially,
then `250` when the identical tuple retries after five minutes; send the message
with DATA to confirm delivery. An unknown local recipient should still receive
`550 Unknown recipient`, and an unrelated external destination should still
receive `550 ... Relaying denied`. Confirm outgoing OpenACS mail still works.
A manual `ns_smtpd resolve` does not exercise this incoming policy.

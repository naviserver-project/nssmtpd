# Write custom policies and interpret findings

[Administration guide](../README.md)

This is the extension reference for operators who need custom Tcl decisions.
For routine configuration, start with the validated
[standard DATA policy](mail-policy.md#apply-validated-data-rules).

## Compose callbacks and collect findings

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

`datapolicyproc` is a Tcl command-prefix **list** (command name followed by
arguments), not a directly evaluated Tcl script. Braces preserve the multiline
configuration value; newlines separate list elements, so multiline options need
no backslash continuations. The dispatcher invokes it with
`uplevel #0 [list {*}$prefix $context]`, appending the DATA context as one argument.
Rule bodies passed to `smtpd::policychain` remain Tcl scripts; their command
boundaries follow ordinary Tcl syntax.

```tcl
ns_param spfproc smtpd::spfauto
ns_param recipientpolicyproc {
    smtpd::policychain {
        {smtpd::greylist $context}
    }
}
ns_param datapolicyproc {
    smtpd::policychain {
        {smtpd::collectfindings $context findings}
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

Use `{smtpd::collectfindings $context findings}` as the first DATA-chain rule.
This public helper collects SPF, DKIM-key and link findings in order, preserving
existing recipient/greylisting findings before any decision can reject the mail.
The individual collectors remain available for custom policies. Each decision
script must be enclosed in its own braces: the chain is a Tcl list of scripts,
not one script. Rule execution errors are logged at Error and defer delivery.

`smtpd::linkpolicy context findingsVar` is a public DATA-only collector, used
like `spfpolicy` and `dkimkeypolicy`. It merges the existing bounded MIME/HTML
link diagnostics into the caller's findings and returns `continue`; it never
rejects a message, resolves/fetches a link, or modifies message bytes. SPF, DKIM
and recipient findings are preserved. `link-status` and the limit fields report
unavailable dependencies, skipped data, parsing errors and incomplete inspection.
An absent destination list is not proof that a message is safe.

For example, after collecting findings, append this rule after the
authentication/retry decisions:

```tcl
{
    if {[dict exists $findings link-destination-hosts]} {
        foreach host [dict get $findings link-destination-hosts] {
            if {$host in {
                accuse-de-reception-de-courrier-recommande-3.jimdosite.com
                voir-mon-doc-1.jimdosite.com
            }} {
                dict set findings blocked-link-host $host
                return {action reject reason known-spam-link-host}
            }
        }
    }
    continue
}
```

These are exact, normalized hostnames observed in operator-confirmed spam;
the example does not block every `jimdosite.com` site or all unsigned mail.
It does not identify the entire campaign. See
[examples/datapolicy-config.tcl](../examples/datapolicy-config.tcl) for a complete
configuration retaining the SPF-fail/missing-DKIM-key rule and the ten-early-retry
threshold, plus persistent quarantine. With `quarantinePolicyRejects true` and
a configured persistent directory, `reject` becomes a durable hold. Without
that setting it is an SMTP rejection. The matching `blocked-link-host` remains
in the DATA policy findings for inspection and manual release.

Link diagnostics displayed by `authdetailsproc` are independent of policy
collection; use `collectfindings` (or `linkpolicy` alone) when a DATA rule uses them. Inspection
limits are the same in both paths. No cryptographic DKIM verification is added.

Greylist decisions include `greylist-early-retries` and
`greylist-elapsed-seconds` in their findings. The count covers early RCPT
attempts for the same peer/sender/original-recipient tuple, not necessarily
one message; elapsed seconds are measured from that tuple's first attempt.
These observations do not change greylisting or automatically reject mail.
Counts persist with the greylist state; older snapshots without counts load
with zero. A policy chain merges a rule's returned findings into its shared
findings. DATA policy events also record the expanded recipient list, shown
in nsstats Details alongside policy findings.

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

## Implement a recipient-policy callback

Existing custom `rcptproc` callbacks are unchanged; to adopt greylisting,
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

## Retain recipient provenance at DATA

Accepted original recipients retain their policy findings for the current
SMTP transaction, independently of event logging and before alias addresses
are replaced by their targets. `ns_smtpd getrcptfindings SESSION` returns a
recipient-to-findings dictionary from the current SMTP callback session.
The DATA callback context exposes it as `recipient-findings`.

The context's `findings` dictionary contains the maximum of each available
`greylist-early-retries` and `greylist-elapsed-seconds` value across accepted
recipients. `smtpd::policychain` seeds its findings from this dictionary, so
SPF/DKIM rules can add their results without discarding the retry counters.
Absent counters remain absent, not zero. Rejected/deferred recipients do not
contribute; RSET, a new MAIL transaction, completion and connection cleanup
clear the retained findings. Authenticated/local policy bypasses are unchanged.

For example, the final DATA rule can require excessive early retries **and**
both authentication findings before rejecting:

```tcl
if {[dict exists $findings greylist-early-retries]
    && [dict get $findings greylist-early-retries] > 20
    && [dict exists $findings spf-fail]
    && [dict exists $findings dkim-no-key]} {
    return {action reject reason early-retries-spf-fail-and-dkim-no-key}
}
continue
```

The threshold is an example; this change does not install a rejection rule.
With several accepted recipients, a message-wide rejection affects all of them;
use `recipient-findings` when the rule needs recipient-specific interpretation.
Deploy the native module and Tcl helpers together.

### Quarantine-only DATA decisions

The opt-in `standardpolicy -quarantineSpfSoftfailUnsigned true` rule requires
SPF `softfail`, explicit DKIM status `unsigned`, and zero signatures. Matching
results use reason `spf-softfail-and-unsigned` and carry `quarantine-only true`.
With `quarantinePolicyRejects true`, the existing persistent hold path handles
the rejection. With quarantine disabled, DATA handling converts a marked
rejection to temporary deferral, including if the setting changed after the
callback ran. Unmarked rejection decisions retain their existing behavior.

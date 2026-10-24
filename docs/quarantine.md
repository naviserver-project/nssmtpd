# Inspect, release and maintain quarantined mail

[Administration guide](../README.md)

Quarantine holds a DATA-policy rejection for administrator review instead of
forwarding it. First configure [DATA policy](mail-policy.md#apply-validated-data-rules),
then choose spool limits and review held mail regularly. The
[nsstats sent-log page](monitoring.md#use-the-nsstats-pages) offers inspection
and confirmed manual release; nscp also supports recovery and deletion.

## Enable quarantine for DATA rejections

To inspect false positives before delivery, keep the existing DATA policy
and enable quarantine for all of its `reject` decisions:

```tcl
ns_section ns/server/$server/module/nssmtpd {
    ns_param quarantinePolicyRejects true
    ns_param quarantineDirectory /usr/local/ns/data/smtp-quarantine/$server
    ns_param quarantineRetention 7d
    ns_param quarantineMaxBytes 1GiB
    ns_param quarantineMaxMessages 10000
}
```

To hold SPF-softfailing, explicitly unsigned messages, add
`-quarantineSpfSoftfailUnsigned true` to `smtpd::standardpolicy`. This opt-in
rule requires the quarantine setting above. It records reason
`spf-softfail-and-unsigned`; unknown DKIM status and signed messages are excluded.
Matching messages defer if quarantine is disabled or cannot store them.

## Keep the spool private and persistent

Mount this directory on persistent storage in a container. Use a dedicated
private directory for each virtual server, owned by the NaviServer user. Only
one running NaviServer process may own a given spool. The default `smtpd::init`
initializes quarantine; a custom `initproc` must call `smtpd::quarantineinit`.
This feature uses `ns_baseunit` and requires a NaviServer version providing it.
No database, external mail command, or additional Tcl package is required.

## Understand acceptance and storage failures

After a DATA-policy rejection, nssmtpd writes and syncs the complete message and
metadata, atomically publishes the message directory, then returns SMTP **250**.
It takes responsibility for holding that message and does not forward it.
Storage errors and capacity exhaustion return **451**. With quarantine disabled,
the existing **550** rejection remains unchanged. Recipient-policy rejections,
DATA-policy deferrals and trusted/local submission bypasses remain unchanged.
The DATA policy already buffers incoming mail up to `maxdata`; quarantine does
not permit oversized messages.

Each opaque ID identifies two private files:

* `message.eml`: binary RFC message, including the server's Received trace,
  without SMTP dot stuffing. Open it in a mail client or inspect it as text.
* `metadata.tcl`: UTF-8 Tcl **dictionary data**, never sourced or evaluated.
  Includes the envelope sender, resolved delivery recipients, original-recipient
  findings where available, policy decision and findings, process/session context,
  timestamps, per-recipient delivery state and administrative audit history.

## Inspect and release held messages

The nsstats quarantine list shows a **Signal** column next to the policy reason.
Inspection shows the label and its basis. These labels describe the triggering
rule, not a verified spam verdict or a numeric probability:

| Signal | Triggering policy reasons |
| --- | --- |
| Strong | Operator-configured spam link host/domain; guarded local-domain DKIM impersonation |
| Weak | SPF softfail with explicitly unsigned mail; SPF fail with absent DKIM keys; excessive early greylist retries |
| Unknown | Custom, missing, or otherwise unclassified policy reason |

Classification uses the stored decision reason, so it also applies to older
retained entries without rewriting their metadata. A Strong label does not
establish cryptographic DKIM verification. Labels do not change quarantine,
release, or delivery behavior.

Use single-line commands in nscp:

```tcl
smtpd::quarantine status
smtpd::quarantine list -limit 20 -offset 0
smtpd::quarantine show MESSAGE_ID
smtpd::quarantine message MESSAGE_ID
smtpd::quarantine release MESSAGE_ID
smtpd::quarantine delete MESSAGE_ID
smtpd::quarantine cleanup
```

`list` returns `entries`, `total`, `nextOffset` and `more`; pass the next offset
until `more` is false. `show` includes the `.eml` path. `message` returns the
message bytes; use `show` first for large messages. Manual release sends to each
**recorded expanded recipient**, bypassing alias expansion and the incoming DATA
policy, through the currently configured relay. Successful delivery means upstream
SMTP acceptance, not final mailbox delivery. Delivered recipients are not resent.
Released files remain available for inspection until deletion or expiry. Release
and deletion require trusted nscp access; there is no automatic or MCP release.

## Resolve uncertain or interrupted deliveries

A failed or disconnected SMTP exchange can have an uncertain delivery outcome.
Such recipients stay `uncertain`; they are never automatically retried or expired.
After checking the upstream logs, explicitly authorize a retry if needed:

```tcl
smtpd::quarantine retry MESSAGE_ID recipient@example.org -confirm
smtpd::quarantine release MESSAGE_ID
```

A process crash during release leaves the entry `releasing`. After restart,
inspect it and run `smtpd::quarantine recover MESSAGE_ID`; recipients marked
`sending` become `uncertain`. Recovery cannot unlock a release belonging to the
current process. A retry may duplicate a delivery already accepted upstream.
A local write failure during a live release also leaves it locked; investigate
storage and restart before recovery. SMTP and spool state cannot commit atomically.

## Review expiry, capacity and crash leftovers

Expired `held` and `released` entries are removed on admission and hourly, or by
`cleanup`. **Expiry discards held mail without a bounce.** Allow enough time for
review. Unexpired mail is never evicted to make space. Byte limits cover retained
message/metadata files with an admission reserve for metadata updates; filesystem
overhead, temporary replacement files and unpublished `.pending-*` directories
need additional disk space. After a crash, inspect `.pending-*` directories
manually: they were never acknowledged as successfully stored. A published entry
whose final directory sync failed may also correspond to a sender retry.

Use a local filesystem supporting atomic rename and file/directory `fsync`.
Unsupported or failed sync is an error, never successful acceptance. Quarantine
operations are recorded in the system log; incoming event logs include
`action quarantine`, `policy-action reject`, the policy findings and
`quarantine-id`. Release uses the ordinary send log, with its ID correlated through
the system log and metadata audit. Back up the spool as sensitive mail data.

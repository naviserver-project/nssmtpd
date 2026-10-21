# Module-owned configuration documentation; generated fragments use this source.
namespace eval ::ns_configdoc {}
dict set ::ns_configdoc::data modules nssmtpd {


            :title {nssmtpd}
            :scope server
            :desc {
                The nssmtpd module provides an SMTP server for NaviServer. It can be
                used to receive mail locally, relay messages to another mail server,
                filter incoming messages, and dispatch SMTP processing to Tcl callback
                procedures.

                The optional aliasproc command prefix provides envelope alias resolution.
                The supplied smtpd::resolvefilealiases resolver supports classical aliases
                and Postfix virtual address-forwarding maps without requiring a database.
                It can also reject unknown incoming recipients using the same lookup.
                The separate recipientpolicyproc supports SMTP policies such as greylisting.
                Alias handling, unknown-recipient rejection and SMTP policy are disabled
                by default. Message headers and envelope senders are not rewritten.

                For file-based aliases, configure aliasfile and aliasdomains, then set
                aliasproc to smtpd::resolvefilealiases. aliasformat defaults to virtual.
                Enable rejectunknownrecipients for alias-only incoming domains. LOCAL
                submissions, direct sends and resolve operations retain passthrough for
                unknown addresses while still expanding known aliases.

                Alias resolution does not add a persistent delivery queue or direct
                MX delivery. Retain an upstream MTA for these functions. In the
                streaming relay path, forwarding precedes the message-data callback
                and spam checks; these checks cannot prevent delivery already made
                to the relay.

                The module is an external NaviServer module and must be compiled and
                installed separately. For new mail-related applications, nssmtpd or
                Tcl library based mail support is usually preferable to the legacy
                ns_sendmail command.

                The logging parameters documented here apply to SMTP sending operations
                performed by the module. A graphical viewer for the log file is included
                in the nsstats module.
            }
            :see {
                {uri https://github.com/naviserver-project/nssmtpd nssmtpd}
            }
            :example {
                ns_section ns/server/$server/modules {
                    ns_param nssmtpd nssmtpd
                }

                ns_section ns/server/$server/module/nssmtpd {
                    ns_param port        2525
                    ns_param address     127.0.0.1
                    ns_param relay       localhost:25
                    ns_param spamd       localhost

                    ns_param initproc    smtpd::init
                    ns_param rcptproc    smtpd::rcpt
                    ns_param dataproc    smtpd::data
                    ns_param errorproc   smtpd::error

                    ns_param relaydomains "localhost"
                    ns_param localdomains "localhost"

                    ns_param logging     on
                    ns_param logfile     smtpsend.log
                    ns_param logrollfmt  %Y-%m-%d

                    # Optional file aliases and strict incoming recipient validation.
                    # These are disabled until explicitly configured.
                    # Also change relaydomains above to {localhost example.org}.
                    
                    # ns_param aliasfile               /var/www/openacs/etc/mail/virtual
                    # ns_param aliasdomains            {example.org}
                    # ns_param aliasformat             virtual ;# default; may be omitted
                    # ns_param aliasproc               smtpd::resolvefilealiases
                    # ns_param rejectunknownrecipients true
                    
                    # Alternative aliasproc value; configure only one aliasproc:
                    # ns_param aliasproc {smtpd::resolvefilealiases -file /another/virtual}

                    # Optional greylisting of incoming mail from non-LOCAL peers.
                    # ns_param recipientpolicyproc smtpd::greylist
                    # ns_param greylistdelay       300
                    # ns_param greylistretrywindow 14400
                    # ns_param greylistlifetime    604800
                    # ns_param greylistmaxentries  10000

                    # Public reception also requires a reachable listener address
                    # and port; the loopback listener above is for local submission.
                }
            }

            address {
                type address
                desc {Local address on which the SMTP server listens}
            }

            port {
                type integer
                default {25}
                desc {TCP port on which the SMTP server listens}
            }
            relay {
                type address
                desc {Upstream SMTP server or mail relay used for forwarding messages}
            }

            spamd {
                type address
                desc {Spamd or SpamAssassin daemon used for filtering messages}
            }

            initproc {
                type proc
                default {smtpd::init}
                desc {Tcl initialization procedure invoked at server startup. The supplied procedure populates relay and trusted-peer rules from relaydomains and localdomains, and initializes the greylist when recipientpolicyproc is configured}
            }

            heloproc {
                type proc
                default {}
                desc {Optional Tcl callback procedure for HELO/EHLO handling; receives the SMTP session ID}
            }

            mailproc {
                type proc
                default {}
                desc {Optional Tcl callback procedure for MAIL FROM handling; receives the SMTP session ID}
            }

            rcptproc {
                type proc
                default {smtpd::rcpt}
                desc {
                    Tcl callback receiving the SMTP session ID after relay authorization
                    and alias resolution, before applying the saved expansion. It sees
                    the original recipient. The supplied smtpd::rcpt invokes the optional
                    recipientpolicyproc; custom callbacks adopt that policy by calling
                    smtpd::checkpolicy and stopping when it returns false. Alias resolution
                    errors skip rcptproc and return the appropriate SMTP failure.
                }
            }

            aliasproc {
                type list
                default {}
                desc {
                    Tcl command prefix returning a list of final envelope destinations.
                    The module appends -recipient and the original address. For LOCAL
                    SMTP submissions, ns_smtpd send and ns_smtpd resolve it also appends
                    -rejectunknown false, overriding fixed callback options. Custom
                    callbacks must accept these named arguments. A dash-prefixed address
                    is passed as the value of -recipient, so no -- separator belongs in
                    the configured prefix. Unset or empty disables alias handling and
                    retains existing behavior.

                    Return the original address for passthrough or final addresses for
                    expansion. An empty list or error code NSSMTPD ALIAS UNKNOWN rejects
                    an unknown recipient (550 for incoming SMTP). Lookup errors produce
                    451, and recipient-limit overflow produces 452. Direct operations
                    report Tcl errors. The module resolves once per original recipient
                    after relay authorization, before rcptproc and greylisting. It applies
                    the saved expansion only after rcptproc accepts, inheriting flags/data
                    from the original recipient and looking up destination transport routes.
                    Duplicate targets within an expansion are removed; maxrcpt bounds it.

                    The supplied smtpd::resolvefilealiases resolver uses aliasformat,
                    aliasfile, aliasdomains, bouncevalidproc, bouncetarget and rejectunknownrecipients.
                    Explicit -format, -file, -domains, -bouncevalidproc, -bouncetarget and
                    -rejectunknown options override these settings. Arguments
                    are parsed by ns_parseargs. aliasformat defaults to virtual and
                    rejectunknownrecipients to false. File and domains must each be
                    supplied by an option or module setting. The file resolver supports
                    aliases/virtual maps, bounded chains, identity mappings and virtual
                    catch-alls. It performs membership checking and expansion from one
                    snapshot. Callbacks must not send mail or mutate SMTP sessions.

                    When migrating earlier experimental configurations, rename filealiases
                    to resolvefilealiases, remove trailing -- separators and replace
                    recipientcheckproc with rejectunknownrecipients true where strict
                    incoming validation is required. Custom alias callbacks must accept
                    -recipient and the optional -rejectunknown override.
                }
            }

            rejectunknownrecipients {
                type boolean
                default {false}
                desc {
                    Default for smtpd::resolvefilealiases -rejectunknown. When true, an
                    unknown original recipient within the effective domain scope
                    (aliasdomains or an explicit -domains option) raises NSSMTPD ALIAS UNKNOWN,
                    producing 550 Unknown recipient for incoming SMTP. Exact entries,
                    identity mappings and virtual catch-alls count as known. Out-of-scope
                    addresses pass through the resolver; relay authorization still applies.
                    Missing or malformed maps cause lookup failure, not an unknown-user
                    rejection. LOCAL submissions, direct sends and resolve operations
                    explicitly pass -rejectunknown false, so unknown addresses pass through.
                    Known aliases expand in all contexts. This setting is read by the file
                    resolver; it does not enable aliasproc and is not a separate C policy.
                    A direct Tcl call to smtpd::resolvefilealiases uses this configured
                    default unless -rejectunknown is explicitly supplied; this differs
                    from ns_smtpd resolve, which always supplies -rejectunknown false.
                }
            }

            bouncevalidproc {
                type list
                default {}
                desc {
                    Optional command prefix used by smtpd::resolvefilealiases for an
                    original recipient within aliasdomains with no matching file alias.
                    Exact aliases and virtual catch-alls take precedence. Receives
                    the recipient as a positional argument. Return a boolean: true
                    forwards to bouncetarget; false retains the usual unknown-recipient
                    rejection or passthrough behaviour. Errors or non-boolean results
                    cause temporary SMTP failure (451). The destination undergoes
                    normal file alias expansion, cycle checks and recipient limits.
                    The callback also runs when -rejectunknown is false, including
                    ns_smtpd resolve and local submissions. It must not send mail or
                    modify SMTP sessions. Recipient policy still applies. An explicit
                    -bouncevalidproc option overrides this setting; unset or empty disables
                    the fallback. This setting alone does not enable aliasproc.
                    OpenACS installations can use acs_mail_lite::bounce_address_valid_p.
                    This forwards validated bounces; it does not update bounce counters.
                }
            }

            bouncetarget {
                type string
                default {}
                desc {
                    Bare envelope address to receive validated bounces, for example
                    webmaster@openacs.org. It can itself be a file alias. Required when
                    bouncevalidproc is configured; a missing or malformed target causes
                    a configuration error when the resolver is called. An explicit
                    -bouncetarget option overrides this setting. Without bouncevalidproc
                    this setting has no effect. Normal alias expansion and limits apply.
                }
            }

            aliasformat {
                type string
                default {virtual}
                desc {Default file format for smtpd::resolvefilealiases: virtual or aliases. An explicit -format option overrides this setting. This setting alone does not enable aliasproc}
            }

            aliasfile {
                type path
                desc {Default map filename for smtpd::resolvefilealiases. An explicit -file option overrides this setting. A filename must be supplied here or by the callback option; there is no implicit map path. This setting alone does not enable aliasproc}
            }

            aliasdomains {
                type list
                desc {Default recipient-domain scope for smtpd::resolvefilealiases. An explicit -domains option overrides this setting. Domains must be supplied here or by the callback option; an explicitly empty list matches no domains. These are recipient domains, not trusted peers, and this setting neither enables aliasproc nor grants relay authorization}
            }

            recipientpolicyproc {
                type list
                default {}
                desc {
                    Optional Tcl command prefix called by smtpd::checkpolicy from the
                    supplied smtpd::rcpt, after relay authorization and alias resolution
                    with optional recipient validation, before applying the saved expansion
                    and before DATA. Unset or empty disables this policy. Trusted LOCAL
                    peers bypass it, as do direct ns_smtpd send and ns_smtpd resolve operations.

                    Receives a dictionary with id (SMTP session ID), peeraddr (socket
                    peer IP), helo (client HELO/EHLO identity), sender (envelope sender, empty for a null sender), and
                    recipient (original envelope recipient), and phase (rcpt). Returns a dictionary with
                    action accept, defer (451 4.7.1), or reject (550 5.7.1). Use smtpd::policychain with a list of configuration scripts to collect findings and make explicit decisions. Each script sees context and findings, returns continue/accept/defer/reject or a decision dictionary; Tcl continue/break/return are also supported. The chain accepts at end and defers on errors, recording its findings and deciding rule. An optional
                    message for defer/reject must contain 1 to 400 printable ASCII
                    characters without newlines. Errors or invalid results cause
                    451 4.3.0 Recipient policy unavailable. Only the current recipient
                    is removed on failure. Callbacks must not modify SMTP sessions or
                    send mail. Accept continues normal processing, including later checks.

                    The supplied smtpd::greylist callback uses a mutex-protected shared
                    table of exact peer-IP, sender and original-recipient tuples. A
                    mature retry grants a sliding allowance for that tuple. State is
                    bounded and persisted via greylistfile across orderly restarts.
                    No database is required.
                    At capacity, new tuples pass without being stored; existing entries
                    remain. Notice logs record deferrals, rejections and new/retry/
                    expired/capacity greylist decisions. Legitimate delivery is delayed,
                    senders changing IPs may be delayed repeatedly, and spammers that
                    retry can pass. This is not content filtering.

                    smtpd::init initializes greylisting when a recipient policy is
                    configured. Custom initproc callbacks using greylisting must call
                    smtpd::greylistinit once at startup; repeated initialization preserves state.
                }
            }

            authdetailsproc {
                type list
                default {}
                desc {
                    Optional informational callback after DATA headers have been parsed,
                    before dataproc. Receives the SMTP session ID. Empty disables it.
                    Callback errors are logged without rejecting mail; callbacks must
                    not change recipients, flags or SMTP replies. Relay acceptance may
                    already have occurred, so this is not a rejection policy hook.
                    Use smtpd::authdetails with eventlogging true to record SPF results
                    via spfproc and DKIM signature key availability via ns_dns. Requires
                    the updated nsdns lookup -details -jointxt -timeout interface for
                    DNS diagnostics. nsstats joins authentication events into transaction
                    Details without extra rows. Local peers skip SPF and DKIM checks.
                    Also inspects HTML links for hostname-label mismatches and embedded
                    cross-host redirect URLs, using Tcllib mime and NaviServer HTML/URL
                    parsers. No URLs are fetched; only hostname evidence is logged.
                    Messages over 256 KiB are skipped; traversal is limited to 64 MIME
                    parts and 100 anchors per HTML part. Missing dependencies, parse
                    errors and inspection limits are recorded. Link findings are
                    informational and may also occur in legitimate mail.
                    SPF uses the actual socket peer, never a supplied Received header.
                    Key checks cover at most eight signatures with a shared five-second
                    DNS deadline. SPF uses the configured evaluator's timeout separately.
                    DKIM cryptographic verification and DMARC policy evaluation are not
                    performed. A present key does not imply a valid signature. No DNS
                    diagnostics run when both eventlogging and authdetailheaders are disabled.
                }
            }

            authdetailheaders {
                type boolean
                default false
                desc {
                    Buffer built-in relay DATA up to maxdata. Use the dynamic ns_set
                    returned by authdetailsproc to prepend informational link headers.
                    Use smtpd::authdetails. Adds memory use and diagnostic latency; overrides
                    fast-proxy buffer omission. The default streaming path is unchanged.
                    Only Nssmtpd-Link-Findings, Nssmtpd-Link-Host-Mismatch and
                    Nssmtpd-Link-Embedded-Redirect with bounded ASCII values are accepted.
                    The original wire DATA is preserved. Callback errors omit additions
                    without rejecting mail. smtpd::authdetails skips existing names and names
                    listed in any DKIM/ARC message signature h= tag, including oversigned
                    fields; malformed signatures suppress all additions. Custom callbacks
                    must provide equivalent protection. Ownership of a returned set transfers
                    to nssmtpd, which frees it; an empty string means no additions.
                    Received diagnostic fields remain untrusted. No Subject/body rewriting or cryptographic verification.
                    Applies only to the built-in relay, not custom delivery callbacks.
                }
            }

            spfproc {
                type list
                default {}
                desc {Optional SPF evaluator command prefix used by smtpd::checkspf. It does not impose rejection by itself; explicit policychain rules interpret the findings from smtpd::spfpolicy. The SPF Tcl interface requires NaviServer 5.0 or newer for ns_ip valid; disabled SPF introduces no such dependency. Receives -ip (actual socket peer), -sender (envelope sender, empty for null sender), and -helo (client SMTP identity). Returns pass, fail, softfail, neutral, none, temperror, or permerror. Empty disables evaluation. The smtpd::spfauto callback lazily selects the Tcl evaluator first, then external spfquery, caching the selection (including unavailable) per interpreter. It returns empty when neither is available; checkspf reports NSSMTPD SPF DEPENDENCY and greylisting proceeds without an exception. Selection does not perform DNS queries or external execution and never retries another backend after an SPF result or execution error. Restart after changing installed backend availability. No configuration-time detection is needed. The optional Tcl backend smtpd::spf requires nsdns with lookup -details -jointxt -timeout (October 2026 interface update), without an external program. It supports IPv4/IPv6, SPF mechanisms, redirect and domain macros; exp text is not fetched because this interface returns only a result. Its -timeout option defaults to 20 seconds (maximum 120). DNS responses alone are shared through ns_memoize, respecting DNS TTLs with a five-minute cap; negative caching requires an SOA, transient errors are not cached, and per-evaluation lookup limits also apply to cache hits. The external smtpd::spfquery backend defaults to the spfquery executable in the helper directory returned by ns_info bindir, using the stable link created by install-ns. Override it with -command /absolute/path. Other optional arguments are -timeout seconds (default 10) and -pool name (default smtpd-spf). It requires the libspf2 command-line utility and the nsproxy module, but no native SPF build support or external timeout program. ns_proxy eval bounds the evaluation wait; the same timeout applies separately when obtaining a proxy handle. Handles are released on success and failure. Use /usr/bin/spfquery.libspf2 from Debian package spfquery or /usr/bin/spfquery from Alpine package libspf2-tools; the Perl utility is incompatible. Queries occupy an SMTP worker until completion or the deadline. Execution failures raise errors and retain normal greylisting. The optional smtpd::libspf2 backend requires building nssmtpd with WITH_SPF2=1 and a maintained libspf2 installation. Its DNS resolution is synchronous and uses system resolver timeouts; custom evaluators can implement their own DNS caching and time limits. SPF evaluates sending authorization, not message content or DKIM/DMARC alignment}
            }

            greylistspfexceptions {
                type list
                default {}
                desc {Optional list of exact case-sensitive envelope-sender/original-recipient pairs eligible for an SPF-verified greylist exception. Null senders are not eligible: their HELO identity would need a separate constraint. For example: {{noreply-dmarc-support@google.com webmaster@openacs.org}}. Used only by smtpd::greylist. A matching pair bypasses greylisting only when smtpd::checkspf returns pass; Other results and evaluator errors fall back to ordinary greylisting. Unmatched pairs cause no SPF lookup unless an explicit policy rule requests it. Requires spfproc. An accepted exception is logged with reason verified-report-sender. This does not bypass relay authorization, alias validation or later checks and does not authenticate a report's contents}
            }

            greylistdelay {

                type integer
                default {300}
                desc {Positive minimum number of seconds from first attempt to an accepted greylist retry. Early retries do not reset the first-attempt time. Used by smtpd::greylist when explicitly enabled via recipientpolicyproc}
            }

            greylistretrywindow {
                type integer
                default {14400}
                desc {Seconds from first attempt before a pending greylist tuple expires. Must exceed greylistdelay; a later attempt starts a new waiting period}
            }

            greylistlifetime {
                type integer
                default {604800}
                desc {Positive lifetime in seconds of a passed greylist tuple, refreshed on each accepted attempt. Different peers, senders or recipients use separate tuples}
            }

            greylistfile {
                type string
                default {smtpgreylist-${server}.state}
                desc {Greylist snapshot file, defaulting to smtpgreylist-${server}.state in the server log directory. Relative names use that directory; absolute paths override it. Empty selects the default. The directory must exist and be writable; use persistent storage. Restored before startup and atomically replaced on orderly shutdown. Preserves pending delays and passed lifetimes; expired and future-dated entries are discarded, and greylistmaxentries bounds reloads. Missing files start empty; read/write failures are logged. Use a separate file per server instance; abrupt termination loses changes since the last shutdown}
            }

            greylistmaxentries {
                type integer
                default {10000}
                desc {Positive maximum number of pending and passed greylist tuples per server. Expired entries are swept on traffic at most once per minute; an accessed expired entry is also removed immediately. At capacity, new tuples pass without being remembered, preserving mail availability while weakening filtering; monitor capacity log entries}
            }

            datapolicyproc {
                type list
                default {}
                desc {Optional Tcl command prefix receiving a context dictionary after DATA is parsed and before message forwarding or dataproc. Contains id, phase data, peeraddr, sender, helo and recipients (after alias expansion). Returns action accept, defer or reject with optional reason/message, like recipientpolicyproc; trusted local clients bypass it. Use smtpd::policychain to accumulate findings and express combined policies. Its first DATA rule can call smtpd::collectfindings $context findings to collect SPF, DKIM-key and link observations together, preserving existing recipient findings before decision rules. Each rule must be one braced script; rule execution errors log at Error and defer delivery. Individual collectors remain available: smtpd::spfpolicy collects SPF without rejecting, smtpd::dkimkeypolicy collects key diagnostics and sets dkim-no-key only when every provided signature key is definitively absent. Unsigned messages, lookup errors, invalid tags and signature-limit exhaustion do not set that finding; keys are not cryptographically verified. smtpd::linkpolicy collects bounded MIME/HTML link diagnostics into the shared findings and returns continue; explicit rules can match exact link-destination-hosts and record blocked-link-host. It neither fetches links nor changes DATA bytes; unavailable/skipped/limited inspection is reported in link-status/limit findings. See examples/datapolicy-config.tcl for a targeted known-spam-host quarantine example retaining the authentication/retry checks. Configuring this hook buffers relay DATA up to maxdata before forwarding, preserving original wire bytes. Rejection returns 550 5.7.1 for the whole message unless quarantinePolicyRejects converts it into a durable hold; errors defer with 451. Decisions are logged as message-policy with accumulated findings. Empty preserves existing streaming behavior}
            }

            quarantinePolicyRejects {
                type boolean
                default {false}
                desc {Convert every DATA-policy reject into a durable quarantine hold. The policy chain remains unchanged. Return SMTP 250 only after message and metadata are synced; storage or capacity failures return 451. Does not affect recipient-policy rejections, deferrals or trusted-client bypasses. Requires an absolute private quarantineDirectory and the default smtpd::init, or an explicit smtpd::quarantineinit call from a custom initproc}
            }

            quarantineDirectory {
                type string
                default {}
                desc {Absolute private persistent spool directory, one dedicated directory per virtual server and running NaviServer process. Created with mode 0700; files use 0600. Mount it on persistent storage in containers. Each opaque message directory contains message.eml and metadata.tcl (a data dictionary, never sourced). Temporary .pending-* directories are unpublished incomplete writes and require manual inspection after crashes. Use a local filesystem supporting atomic rename and file/directory fsync; unsupported sync fails closed with 451}
            }

            quarantineRetention {
                type time
                default {7d}
                desc {Positive age limit for held and released entries. Expired entries are removed on admission, by hourly cleanup, or by smtpd::quarantine cleanup. Interrupted and uncertain deliveries are preserved for manual review even beyond this age. Expiration discards held mail without a bounce; choose retention to allow administrative inspection}
            }

            quarantineMaxBytes {
                type memory
                default {1GiB}
                desc {Positive admission limit for stored message and metadata file bytes, including a reserve for metadata updates. Filesystem overhead, unpublished temporary directories and temporary replacement files are not included; provision extra disk space. No capacity-based eviction of unexpired messages. Capacity or disk exhaustion defers new rejected mail with SMTP 451}
            }

            quarantineMaxMessages {
                type integer
                default {10000}
                desc {Positive maximum number of retained quarantine entries, including released messages kept for inspection. Capacity exhaustion defers new policy-rejected mail with 451; it never silently discards or forwards it}
            }

            dataproc {
                type proc
                default {smtpd::data}
                desc {Tcl callback procedure invoked for processing SMTP message data}
            }

            errorproc {
                type proc
                default {smtpd::error}
                desc {Tcl callback procedure invoked for SMTP error handling}
            }

            relaydomains {
                type list
                default {localhost}
                desc {Recipient-domain relay rules loaded by smtpd::init. Permit untrusted peers to address these domains; this does not establish that an individual recipient exists. Configure aliasproc with rejectunknownrecipients for alias-only domains}
            }

            localdomains {
                type list
                default {localhost}
                desc {Trusted sending-peer addresses, networks or hostnames loaded by smtpd::init. Matching connections receive the LOCAL flag and may relay to arbitrary recipient domains; they also bypass unknown-recipient rejection and recipientpolicyproc. This is not a list of local recipient domains. Restrict it to trusted submitting peers}
            }

            readtimeout {
                type time
                default {60s}
                desc {Receive timeout, accepting time units and fractional seconds. Unitless values are seconds. The local receive implementation shares a deadline across readiness retries for one buffer refill, not across an entire SMTP line or transaction}
            }

            writetimeout {
                type time
                default {60s}
                desc {Timeout for outbound SMTP and spamd connection establishment and for each local send operation, including readiness and TLS retries. Accepts time units and fractional seconds; unitless values are seconds. This is not an overall SMTP transaction deadline}
            }

            segvtimeout {
                type time
                default {-1}
                desc {Delay before terminating after a trapped SEGV or panic when SEGV handling is enabled. Accepts time units and fractional seconds; unitless values are seconds. The default -1 terminates without waiting}
            }

            bufsize {
                type integer
                default {4096}
                desc {Size of the SMTP receive buffer in bytes}
            }

            maxrcpt {
                type integer
                default {100}
                desc {Maximum number of recipients; alias expansion also enforces this limit, accounting for recipients already accepted in an incoming transaction}
            }

            maxline {
                type integer
                default {4096}
                desc {SMTP input-line length limit in bytes}
            }

            maxdata {
                type integer
                default {10485760}
                desc {Maximum SMTP message data size in bytes}
            }

            logging {
                type boolean
                default {false}
                desc {Enable logging for SMTP sending operations performed by the module}
            }

            eventlogging {
                type boolean
                default {false}
                desc {Enable a separate structured SMTP event log for incoming recipient decisions, applied alias expansions, greylisting outcomes, transaction outcomes and custom Tcl policy events. Transaction-end records are folded into matching nsstats Details and include the last command, DATA byte count and available relay reply; relay acceptance does not establish mailbox delivery. Does not change mail policy or the existing SMTP send log. The nsstats SMTP Events page displays charts and a filterable event table. Records contain envelope addresses but no message bodies or subjects; recipient acceptance does not establish final delivery}
            }

            eventlogfile {
                type path
                default {smtpevents-${server}.log}
                desc {SMTP event log filename. Relative paths use the server log directory on NaviServer 5, or the home logs directory on older versions. The resolved path is available in the configuration database. Single-line records use access-log-style positional fields with the same timestamp convention as the SMTP send log, fixed recipient, action, reason and comma-separated targets fields; custom metadata uses trailing key=value tokens. Empty fields use a dash. Spaces, backslashes and control bytes within fields are escaped as \xHH, allowing readers to split on spaces. This log covers incoming SMTP callbacks rather than direct ns_smtpd send operations}
            }

            eventlogmaxbackup {
                type integer
                default {100}
                desc {Maximum number of rotated SMTP event log files to retain. Inherits logmaxbackup when omitted, even when send logging is disabled; the fallback is 100}
            }

            eventlogroll {
                type boolean
                default {true}
                desc {Enable daily rotation of the SMTP event log when eventlogging is enabled. Inherits logroll when omitted, even when send logging is disabled; the fallback is true}
            }

            eventlogrollfmt {
                type string
                desc {Optional strftime suffix format overriding logrollfmt for SMTP event log rotation. When omitted, inherit logrollfmt even if SMTP send logging is disabled; when neither format is configured, use numbered backups}
            }

            eventlogrollhour {
                type integer
                default {0}
                desc {Hour of day, from 0 through 23, for daily SMTP event log rotation. Inherits logrollhour when omitted, even when send logging is disabled; the fallback is 0}
            }

            eventlogrollonsignal {
                type boolean
                default {false}
                desc {Rotate the SMTP event log on SIGHUP when eventlogging is enabled. Inherits logrollonsignal when omitted, even when send logging is disabled; the fallback is false}
            }

            logfile {
                type path
                desc {Log file for SMTP sending operations; relative paths are resolved according to the module's logging rules}
            }

            logmaxbackup {
                type integer
                default {100}
                desc {Maximum number of rotated SMTP sending log files to keep}
            }

            logroll {
                type boolean
                default {true}
                desc {Enable automatic rotation of the SMTP sending log}
            }

            logrollfmt {
                type string
                desc {Optional strftime suffix format used when rotating SMTP send and event logs. The event log inherits this setting unless eventlogrollfmt is configured. Without a format, use numbered backups}
            }

            logrollhour {
                type integer
                default {0}
                desc {Hour of day at which to rotate the SMTP sending log}
            }

            logrollonsignal {
                type boolean
                default {false}
                desc {Rotate the SMTP sending log when the server receives a SIGHUP signal}
            }

            certificate {
                type path
                desc {Certificate chain file used for STARTTLS support}
            }

            cafile {
                type path
                desc {CA certificate file used for TLS certificate validation}
            }

            capath {
                type path
                desc {Directory containing CA certificates used for TLS certificate validation}
            }

            ciphers {
                type string
                desc {OpenSSL cipher list for TLS 1.2 and older STARTTLS connections}
            }
        }

# MCP settings have their own section; SMTP listener settings remain above.
dict set ::ns_configdoc::data sections {ns/server/*/module/nssmtpd/mcp} {
    :title {Nssmtpd MCP diagnostics}
    :desc {Configure these settings in ns/server/$server/module/nssmtpd/mcp. Requires the nsmcp provider interface. No mail sending, configuration mutation or quarantine release tool is exposed.}
    :example {
        ns_section ns/server/$server/module/nssmtpd/mcp {
            ns_param enabled true
            ns_param logReadBytes 1MiB
        }
    }
    enabled {
        type boolean default false
        desc {Enable the read-only smtp_logs MCP tool for this virtual server. An explicit false disables it.}
    }
    logReadBytes {
        type memory default 1MiB
        desc {Maximum current-file tail read by smtp_logs, between 1 byte and 16MiB. Rotated logs are not scanned. Explicit empty or invalid values are errors.}
    }
}

# SMTP administration views included by nsstats after its access checks.
# Shared log selectors, charts and formatting remain in the host.

proc ::_ns_stats.log.chart.parse-module/nssmtpd {line} {
    set fields [split $line]
    lassign $fields ts tz id status statuscode url elapsed sent sender rcpt
    set ts0 [string range $ts 1 end]
    #[25/Sep/2023:00:02:48 +0200] -sched:...- 250 SUCCESS [smtp.wu.ac.at]:25 0.009911 13313 sender RCPT: USER@HOST
    set host $url

    return [list \
                ts0 $ts0 \
                id $id \
                status $status \
                method "" \
                host $host \
                url $url \
                elapsed $elapsed \
                sent $sent \
                received 0 \
                reused 0 \
                cause "" \
                errorLine [expr {$statuscode ne "SUCCESS" ? $line : ""}] \
               ]
}

proc ::_ns_stats.log.smtpsent {} {
    if {[info commands ::smtpd::quarantine] eq ""} {
        return [::_ns_stats.log.mkchart module/nssmtpd logfile "SMTP Sent Log"]
    }
    if {[ns_queryget smtpView {}] eq "quarantine" || [ns_queryget smtpQuarantineAction {}] ne ""} {
        return [::_ns_stats.smtp.quarantine.page]
    }
    set html [::_ns_stats.log.mkchart module/nssmtpd logfile "SMTP Sent Log"]
    return "[::_ns_stats.smtp.quarantine.navigation sent]$html"
}
# Quarantine is a delivery view of the SMTP sent log, not a separate menu page.
proc ::_ns_stats.smtp.quarantine.navigation {view} {
    set html {<nav class='ns-smtp-views' aria-label='SMTP deliveries'>}
    foreach {name label} {sent {Delivery log} quarantine Quarantine} {
        set current [expr {$name eq $view ? " aria-current='page'" : ""}]
        append html "<a href='?@page=log.smtpsent&amp;smtpView=$name'$current>[ns_quotehtml $label]</a> "
    }
    return "$html</nav>"
}

proc ::_ns_stats.smtp.quarantine.tokenKey {} {
    return smtp-quarantine:[::_ns_stats.identity]
}

proc ::_ns_stats.smtp.quarantine.token {} {
    set key [::_ns_stats.smtp.quarantine.tokenKey]
    if {![nsv_exists _ns_stats $key]} {
        nsv_set _ns_stats $key [ns_crypto::randombytes -encoding hex 32]
    }
    return [nsv_get _ns_stats $key]
}

# Called only through log.smtpsent after the normal nsstats access check. GET
# never releases mail; POST additionally requires the admin-bound token and an
# explicit confirmation. Redirect after release to prevent refresh resubmission.
proc ::_ns_stats.smtp.quarantine.release {} {
    if {[ns_conn method] ne "POST"} {
        ns_return 405 text/plain "Use POST to release quarantined mail."
        return ""
    }
    set key [::_ns_stats.smtp.quarantine.tokenKey]
    set token [ns_queryget smtpQuarantineToken {}]
    if {$token eq "" || ![nsv_exists _ns_stats $key] || $token ne [nsv_get _ns_stats $key]} {
        ns_return 403 text/plain "Invalid quarantine token; reload the inspection page."
        return ""
    }
    if {[ns_queryget smtpQuarantineAction {}] ne "release"
        || [ns_queryget smtpQuarantineConfirm {}] ne "1"} {
        ns_return 400 text/plain "Confirm release of the pending recipients."
        return ""
    }
    set id [ns_queryget id {}]
    if {![regexp {^[0-9a-f]{32}$} $id]} {
        ns_return 400 text/plain "Invalid quarantine id."
        return ""
    }
    if {[catch {::smtpd::quarantine release $id} message]} {
        ns_return 409 text/plain "Release did not complete: $message. Inspect the entry before retrying."
        return ""
    }
    ns_set iupdate [ns_conn outputheaders] Location "[ns_conn url]?@page=log.smtpsent&smtpView=quarantine&id=$id&released=1"
    ns_return 303 text/plain "Release attempt finished; inspect recipient outcomes."
    return ""
}

# Tables deliberately use the same compact classes as the other admin pages.
# All mail-controlled values are escaped, including findings and error strings.
proc ::_ns_stats.smtp.quarantine.table {columns rows} {
    set html {<div class='w3-responsive ns-quarantine-scroll'><table class='data data-table w3-table w3-hoverable ns-quarantine-table'><thead><tr>}
    foreach column $columns {append html "<th>[ns_quotehtml $column]</th>"}
    append html {</tr></thead><tbody>}
    foreach row $rows {
        append html <tr>
        foreach value $row {append html "<td>[ns_quotehtml $value]</td>"}
        append html </tr>
    }
    return "$html</tbody></table></div>"
}

proc ::_ns_stats.smtp.quarantine.value {dictionary key {default {}}} {
    if {[dict exists $dictionary $key]} {return [dict get $dictionary $key]}
    return $default
}

proc ::_ns_stats.smtp.quarantine.page {} {
    ns_set iupdate [ns_conn outputheaders] Cache-Control no-store
    ns_set iupdate [ns_conn outputheaders] Referrer-Policy no-referrer
    ns_set iupdate [ns_conn outputheaders] X-Content-Type-Options nosniff
    if {[ns_conn method] eq "POST" || [ns_queryget smtpQuarantineAction {}] ne ""} {
        return [::_ns_stats.smtp.quarantine.release]
    }
    if {[ns_conn method] ne "GET"} {
        ns_return 405 text/plain "Use GET for quarantine inspection."
        return ""
    }
    set id [ns_queryget id {}]
    if {$id ne "" && ![regexp {^[0-9a-f]{32}$} $id]} {
        ns_return 400 text/plain "Invalid quarantine id."
        return ""
    }
    if {[ns_queryget download {}] eq "1"} {
        if {$id eq "" || [catch {
            set metadata [::smtpd::quarantine show $id]
            set path [dict get $metadata messagePath]
            if {[file type $path] ne "file"} {error "Message file unavailable"}
        } message]} {
            ns_return 404 text/plain "Quarantine message is unavailable."
            return ""
        }
        ns_set iupdate [ns_conn outputheaders] Content-Disposition "attachment; filename=\"quarantine-$id.eml\""
        ns_returnfile 200 message/rfc822 $path
        return ""
    }
    ::_ns_stats.header "SMTP sent log: Quarantine"
    set html [::_ns_stats.smtp.quarantine.navigation quarantine]
    if {[catch {::smtpd::quarantine status} status]} {
        append html "<p>Quarantine is unavailable: [ns_quotehtml $status]</p>"
        return "$html[::_ns_stats.footer]"
    }
    set rows {}
    foreach {key label} {enabled {Quarantine mail rejections} directory {Persistent directory} messages {Retained messages} states {Message states} maxMessages {Message limit}} {
        if {[dict exists $status $key]} {
            set value [dict get $status $key]
            if {$key eq "enabled"} {set value [expr {$value ? "true" : "false"}]}
            lappend rows [list $label $value]
        }
    }
    foreach {key label} {bytes {Stored file bytes} maxBytes {Admission byte limit}} {
        if {[dict exists $status $key]} {lappend rows [list $label "[::_ns_stats.hr [dict get $status $key]]B"]}
    }
    if {[dict exists $status retention]} {
        lappend rows [list Retention "[format %.1f [expr {[dict get $status retention]/86400.0}]] days"]
    }
    append html [::_ns_stats.smtp.quarantine.table {Setting Value} $rows]
    append html {<p>Held mail has been accepted by SMTP but not forwarded. Expiry discards held mail without a bounce; uncertain deliveries are preserved for review.</p>}
    if {$id ne ""} {
        if {[catch {::smtpd::quarantine show $id} metadata]} {
            append html "<p role='alert'>Cannot inspect entry: [ns_quotehtml $metadata]</p>"
        } else {
            append html [::_ns_stats.smtp.quarantine.detail $metadata]
        }
    } else {
        append html [::_ns_stats.smtp.quarantine.list]
    }
    return "$html[::_ns_stats.footer]"
}

proc ::_ns_stats.smtp.quarantine.list {} {
    set offset [ns_queryget offset 0]
    if {![string is integer -strict $offset] || $offset < 0} {set offset 0}
    set limit 25
    if {[catch {::smtpd::quarantine list -limit $limit -offset $offset} report]} {
        return "<p>Cannot list quarantine: [ns_quotehtml $report]</p>"
    }
    set html {<h3>Quarantined messages</h3><div class='w3-responsive ns-quarantine-scroll'><table class='data data-table w3-table w3-hoverable ns-quarantine-table'><thead><tr><th>Received</th><th>Sender</th><th>Recipients</th><th>Reason</th><th>State</th><th>Inspect</th></tr></thead><tbody>}
    foreach entry [dict get $report entries] {
        set id [dict get $entry id]
        append html <tr>
        foreach value [list [clock format [dict get $entry createdAt] -format {%Y-%m-%d %H:%M:%S %Z}] \
            [dict get $entry sender] [join [dict keys [dict get $entry recipients]] {, }] \
            [::_ns_stats.smtp.quarantine.value [dict get $entry decision] reason {Policy rejection}] [dict get $entry state]] {
            append html "<td>[ns_quotehtml $value]</td>"
        }
        append html "<td><a href='?@page=log.smtpsent&amp;smtpView=quarantine&amp;id=[ns_urlencode $id]'>Inspect [ns_quotehtml [string range $id 0 7]]</a></td></tr>"
    }
    append html "</tbody></table></div><p>[dict get $report total] retained entries. "
    if {$offset > 0} {
        set previous [expr {max(0,$offset-$limit)}]
        append html "<a href='?@page=log.smtpsent&amp;smtpView=quarantine&amp;offset=$previous'>Previous</a> "
    }
    if {[dict get $report more]} {
        set next [dict get $report nextOffset]
        append html "<a href='?@page=log.smtpsent&amp;smtpView=quarantine&amp;offset=$next'>Next</a>"
    }
    return "$html</p>"
}

proc ::_ns_stats.smtp.quarantine.detail {metadata} {
    set id [dict get $metadata id]
    set context [dict get $metadata context]
    set decision [dict get $metadata decision]
    set state [dict get $metadata state]
    set html "<p><a href='?@page=log.smtpsent&amp;smtpView=quarantine'>All quarantined messages</a></p><h3>Message [ns_quotehtml $id]</h3>"
    if {[ns_queryget released {}] eq "1"} {
        append html {<p role='status'>Release attempt finished. Check the recipient outcomes below; upstream acceptance does not establish final mailbox delivery.</p>}
    }
    set rows [list [list State $state] [list {Envelope sender} [dict get $context sender]] \
        [list Received [clock format [dict get $metadata createdAt] -format {%Y-%m-%d %H:%M:%S %Z}]] \
        [list Reason [::_ns_stats.smtp.quarantine.value $decision reason {Policy rejection}]] \
        [list {Message size} "[::_ns_stats.hr [dict get $metadata bytes]]B"]]
    append html [::_ns_stats.smtp.quarantine.table {Field Value} $rows]
    append html {<h4>Delivery recipients</h4>}
    set rows {}
    set pending 0
    dict for {recipient outcome} [dict get $metadata recipients] {
        if {$outcome eq "pending"} {incr pending}
        set detail {}
        if {[dict exists $metadata deliveryErrors $recipient]} {set detail [dict get $metadata deliveryErrors $recipient]}
        lappend rows [list $recipient $outcome $detail]
    }
    append html [::_ns_stats.smtp.quarantine.table {Recipient State Details} $rows]
    if {$state eq "releasing"} {
        append html {<p>Release is active or was interrupted. After a process restart, inspect the upstream logs and use <code>smtpd::quarantine recover ID</code> through nscp before proceeding.</p>}
    }
    if {$state eq "uncertain"} {
        append html {<p role='alert'>Some delivery outcomes are uncertain. They will not be resent automatically. Inspect upstream logs; an explicit retry through nscp may duplicate delivery.</p>}
    }
    if {$state in {held uncertain} && $pending > 0} {
        set token [::_ns_stats.smtp.quarantine.token]
        append html "<form method='post' action='[ns_quotehtml [ns_conn url]]' class='ns-quarantine-release'>\
            <input type='hidden' name='@page' value='log.smtpsent'>\
            <input type='hidden' name='smtpView' value='quarantine'>\
            <input type='hidden' name='id' value='[ns_quotehtml $id]'>\
            <input type='hidden' name='smtpQuarantineAction' value='release'>\
            <input type='hidden' name='smtpQuarantineToken' value='[ns_quotehtml $token]'>\
            <label><input type='checkbox' name='smtpQuarantineConfirm' value='1' required> I have inspected this message and approve delivery to its $pending pending recipient(s).</label>\
            <p><button type='submit'>Release pending recipients</button></p></form>"
    }
    set findings [::_ns_stats.smtp.quarantine.value $decision findings]
    if {$findings ne ""} {
        set rows {}
        dict for {key value} $findings {lappend rows [list $key $value]}
        append html "<h4>Policy findings</h4>[::_ns_stats.smtp.quarantine.table {Finding Value} $rows]"
    }
    append html "<details><summary>Complete metadata and audit history</summary><pre class='ns-quarantine-preview'>[ns_quotehtml $metadata]</pre></details>"
    append html "<h4>Message</h4><p><a href='?@page=log.smtpsent&amp;smtpView=quarantine&amp;id=[ns_urlencode $id]&amp;download=1'>Download message.eml</a></p>"
    set path [dict get $metadata messagePath]
    if {[catch {
        if {[file type $path] ne "file"} {error "Message file unavailable"}
        set channel [open $path rb]
        try {set preview [read $channel 65536]} finally {close $channel}
    } message]} {
        append html "<p>Cannot read preview: [ns_quotehtml $message]</p>"
    } else {
        append html {<p>Plain-text source preview, up to 64KiB. HTML, links and attachments are not rendered; download the .eml for complete inspection.</p>}
        append html "<pre class='ns-quarantine-preview'>[ns_quotehtml [encoding convertfrom utf-8 $preview]]</pre>"
    }
    return $html
}

proc ::_ns_stats.log.smtpevents {} {
    return [::_ns_stats.log.mkchart module/nssmtpd eventlogfile "SMTP Events" \
                ::_ns_stats.log.smtpevents.chart]
}

proc ::_ns_stats.log.chart.parse-smtpevents {line} {
    set fields [split $line " "]
    lassign $fields date zone thread code event peer session transaction server sender recipient action reason targets
    if {[llength $fields] < 14 || [regexp {[\r\n]} $line]
        || ![regexp {^(-|[1-5][0-9]{2})$} $code]
        || ![regexp {^[a-z0-9_-]+$} $event]
        || ![string is integer -strict $transaction]} {
        error {invalid event record}
    }
    set timestamp [expr {1000 * [clock scan [string range "$date $zone" 1 end-1] \
                                   -format {%d/%b/%Y:%H:%M:%S %z}]}]
    foreach name {server sender recipient action reason targets code} {
        if {[set $name] eq "-"} {set $name ""}
    }
    set metadata {}
    foreach field [lrange $fields 14 end] {
        if {[regexp {^([a-z0-9-]+)=(.*)$} $field -> key value]
            && ($key in {last-command message-bytes relay-accepted relay-reply recipients findings recipient-findings policy-rule greylist-early-retries greylist-elapsed-seconds
                         link-status link-limit link-host-mismatch link-embedded-redirect link-destination-hosts link-destination-limit dkim-obsolete-algorithm spf-result spf-peer spf-helo spf-errorcode dkim-signatures dkim-status dkim-limit}
                || [regexp {^dkim-[1-8]-(domain|selector|key|verification|algorithm|algorithm-status)$} $key])} {
            # Decode the writer's byte escapes without evaluating log content.
            set decoded ""
            while {[regexp -indices {\\x[0-9a-fA-F]{2}} $value match]} {
                lassign $match first last
                append decoded [string range $value 0 $first-1] \
                    [format %c [scan [string range $value $first+2 $last] %x]]
                set value [string range $value $last+1 end]
            }
            dict set metadata $key $decoded$value
        }
    }
    return [dict create timestamp $timestamp thread $thread server $server \
        session $session transaction $transaction peer [string range $peer 1 end-1] \
        sender $sender event $event recipient $recipient action $action reason $reason \
        code $code targets [expr {$targets eq "" ? {} : [split $targets ,]}] metadata $metadata]
}

proc ::_ns_stats.log.smtpevents.read {path filter} {
    set rows {}
    set counts {}
    set buckets {}
    set total 0
    set invalid 0
    set filter [string tolower $filter]
    set channel [open $path r]
    fconfigure $channel -encoding utf-8
    try {
        while {[gets $channel line] >= 0} {
            if {$line eq ""} {continue}
            try {
                set record [::_ns_stats.log.chart.parse-smtpevents $line]
            } on error {message options} {
                incr invalid
                continue
            }
            if {[dict get $record event] eq "message-policy"} {
                # DATA decisions apply to this transaction, including rows whose
                # original recipient matched a filter but the DATA row did not.
                set joined {}
                foreach row $rows {
                    if {[dict get $row server] eq [dict get $record server]
                        && [dict get $row session] eq [dict get $record session]
                        && [dict get $row transaction] eq [dict get $record transaction]} {
                        dict set row dataPolicy $record
                    }
                    lappend joined $row
                }
                set rows $joined
                # Keep the policy event itself and existing event totals.
            }
            if {[dict get $record event] in {transaction authentication}} {
                # Fold transaction-wide details into retained rows before
                # filtering: they have no recipient but must join alias searches.
                set joined {}
                foreach row $rows {
                    if {[dict get $row server] eq [dict get $record server]
                        && [dict get $row session] eq [dict get $record session]
                        && [dict get $row transaction] eq [dict get $record transaction]} {
                        set field [expr {[dict get $record event] eq "transaction" ? "outcome" : "authentication"}]
                        dict set row $field $record
                    }
                    lappend joined $row
                }
                set rows $joined
                continue
            }
            set searchable {}
            foreach key {server session transaction peer sender event recipient action reason targets} {
                lappend searchable [dict get $record $key]
            }
            if {$filter ne "" && [string first $filter [string tolower [join $searchable " "]]] < 0} {continue}
            incr total
            set event [dict get $record event]
            set action [dict get $record action]
            set reason [dict get $record reason]
            dict incr counts [list $event $action $reason]
            set minute [expr {[dict get $record timestamp] / 60000 * 60000}]
            # Separate denominators: policies and alias events are not RCPT attempts.
            if {$event eq "recipient" && $action in {accept defer reject}} {
                dict incr buckets [list recipient $action $minute]
            }
            # Consolidated recipient events and historical greylist records.
            if {$event eq "recipient" && [string match greylist-* $reason]} {
                set reason [string range $reason 9 end]
                if {$reason ni {new early retry known expired capacity}} {set reason other}
                dict incr buckets [list greylist $reason $minute]
            } elseif {$event eq "greylist"} {
                if {$reason ni {new early retry known expired capacity}} {set reason other}
                dict incr buckets [list greylist $reason $minute]
            }
            lappend rows $record
            if {[llength $rows] > 200} {set rows [lrange $rows end-199 end]}
        }
    } finally {close $channel}
    return [dict create rows $rows counts $counts buckets $buckets total $total invalid $invalid]
}

proc ::_ns_stats.log.smtpevents.series {buckets event categories} {
    set series {}
    foreach category $categories {
        set points {}
        dict for {key count} $buckets {
            lassign $key kind label minute
            if {$kind eq $event && $label eq $category} {
                lappend points [list $minute $count]
            }
        }
        set data {}
        foreach point [lsort -integer -index 0 $points] {
            lassign $point minute count
            lappend data "\[$minute,$count\]"
        }
        # Categories are fixed literals; only integers enter the JavaScript data.
        lappend series "{name:'$category',data:\[[join $data ,]\]}"
    }
    return [join $series ,]
}

proc ::_ns_stats.log.smtpevents.chart {path section param title} {
    set files [::_ns_stats.log.logfiles $section $param]
    set filter [ns_queryget filter ""]
    set report [::_ns_stats.log.smtpevents.read $path $filter]
    set html [::_ns_stats.log.fileform $files $path log.smtpevents [dict create filter $filter]]
    append html {<p>Recipient counts describe SMTP RCPT attempts, not delivered messages.
        Greylisting deferrals are not spam classifications. Filter matches peer, sender,
        original recipient, targets, session, transaction, event, action, or reason.</p>}
    set recipientSeries [::_ns_stats.log.smtpevents.series [dict get $report buckets] recipient {accept defer reject}]
    set greySeries [::_ns_stats.log.smtpevents.series [dict get $report buckets] greylist {new early retry known expired capacity other}]
    append html "<div id=\"smtp-recipient-events\"></div><div id=\"smtp-greylist-events\"></div><script>\
        Highcharts.chart('smtp-recipient-events', {chart:{type:'column'}, title:{text:'Recipient decisions per minute'},\
        xAxis:{type:'datetime'}, yAxis:{title:{text:'RCPT attempts'},allowDecimals:false}, series:\[$recipientSeries\]});\
        Highcharts.chart('smtp-greylist-events', {chart:{type:'column'}, title:{text:'Greylisting events per minute'},\
        xAxis:{type:'datetime'}, yAxis:{title:{text:'Events'},allowDecimals:false}, series:\[$greySeries\]});</script>"
    append html {<h4>Event totals</h4><table class="table"><tr><th>Event</th><th>Action</th><th>Reason</th><th>Count</th></tr>}
    dict for {key count} [dict get $report counts] {
        append html <tr>
        foreach value [list {*}$key $count] {append html "<td>[ns_quotehtml $value]</td>"}
        append html </tr>
    }
    append html "</table><p>[dict get $report total] matching events; showing the last 200 at most. \
        [dict get $report invalid] malformed or unsupported records skipped.</p>"
    set rows [lreverse [dict get $report rows]]
    set servers [lsort -unique [lmap row $rows {dict get $row server}]]
    if {[llength $servers] == 1} {
        append html "<p>Server: [ns_quotehtml [lindex $servers 0]]</p>"
    }
    append html {<div class="table-responsive"><table class="table table-sm text-nowrap"><thead><tr><th>Time</th><th>Peer</th><th>Sender</th><th>Recipient</th><th>Event</th><th>Action</th><th>Reason</th><th>Code</th><th>Details</th></tr></thead><tbody>}
    set previousDate ""
    foreach row $rows {
        set seconds [expr {[dict get $row timestamp] / 1000}]
        set date [clock format $seconds -format {%Y-%m-%d %z}]
        set timestamp [clock format $seconds -format {%Y-%m-%d %H:%M:%S %z}]
        if {$date ne $previousDate} {
            append html "<tr class=\"table-light\"><th colspan=\"9\" scope=\"rowgroup\">[ns_quotehtml $date]</th></tr>"
            set previousDate $date
        }
        append html "<tr><td title=\"[ns_quotehtml $timestamp]\">[clock format $seconds -format {%H:%M:%S}]</td>"
        foreach key {peer sender recipient event action reason code} {
            set value [ns_quotehtml [dict get $row $key]]
            if {$key in {peer sender recipient reason}} {
                # Keep the full value in the DOM for copying, and in the
                # disclosure below for keyboard/touch access without hovering.
                append html "<td><span class=\"d-inline-block text-truncate align-middle\" style=\"max-width: 24ch\" title=\"$value\">$value</span>"
                if {$key eq "recipient" && [dict get $row event] eq "alias"
                    && [dict get $row action] eq "expand"} {
                    foreach target [dict get $row targets] {
                        append html "<div class=\"text-wrap\" style=\"width: 24ch; overflow-wrap: anywhere\">&#8594; [ns_quotehtml $target]</div>"
                    }
                }
                append html </td>
            } else {
                append html "<td>$value</td>"
            }
        }
        append html {<td><details><summary>Details</summary><dl class="mb-0 text-wrap" style="width: 24rem; max-width: 60vw; overflow-wrap: anywhere">}
        append html "<dt>Time</dt><dd>[ns_quotehtml $timestamp]</dd>"
        foreach {key label} {server Server session Session transaction Transaction peer Peer sender Sender recipient Recipient reason Reason targets Targets} {
            set value [dict get $row $key]
            if {$key eq "targets"} {set value [join $value {, }]}
            append html "<dt>$label</dt><dd>[ns_quotehtml $value]</dd>"
        }
        if {[dict exists $row metadata recipients] && ![catch {llength [dict get $row metadata recipients]}]} {
            append html "<dt>Expanded recipients</dt><dd>[ns_quotehtml [join [dict get $row metadata recipients] {, }]]</dd>"
        }
        foreach key {greylist-early-retries greylist-elapsed-seconds} {
            if {[dict exists $row metadata $key]} {
                append html "<dt>[ns_quotehtml $key]</dt><dd>[ns_quotehtml [dict get $row metadata $key]]</dd>"
            }
        }
        set policy {}
        if {[dict exists $row dataPolicy]} {set policy [dict get $row dataPolicy]}
        if {[dict get $row event] eq "message-policy"} {set policy $row}
        if {$policy ne ""} {
            append html "<dt>DATA policy</dt><dd>[ns_quotehtml [dict get $policy action]]: [ns_quotehtml [dict get $policy reason]]</dd>"
            if {[dict exists $policy metadata findings]} {
                set findings [dict get $policy metadata findings]
                if {![catch {dict size $findings}]} {
                    append html {<dt>DATA policy findings</dt><dd>Transaction findings; greylisting counters are maxima across accepted original recipients.</dd>}
                    dict for {key value} $findings {
                        append html "<dt>[ns_quotehtml $key]</dt><dd>[ns_quotehtml $value]</dd>"
                    }
                }
            }
            if {[dict exists $policy metadata recipient-findings]
                && ![catch {dict size [dict get $policy metadata recipient-findings]}]} {
                dict for {recipient findings} [dict get $policy metadata recipient-findings] {
                    append html "<dt>Original recipient</dt><dd>[ns_quotehtml $recipient]</dd>"
                    if {![catch {dict size $findings}]} {
                        dict for {key value} $findings {
                            append html "<dt>[ns_quotehtml $key]</dt><dd>[ns_quotehtml $value]</dd>"
                        }
                    }
                }
            } else {
                append html {<dt>Recipient provenance</dt><dd>Not recorded in this log entry.</dd>}
            }
        }
        if {[dict exists $row metadata findings]} {
            set findings [dict get $row metadata findings]
            if {![catch {dict size $findings}] && [dict size $findings] > 0} {
                append html {<dt>Policy findings</dt><dd>Observations used or collected by the policy chain.</dd>}
                dict for {key value} $findings {
                    append html "<dt>[ns_quotehtml $key]</dt><dd>[ns_quotehtml $value]</dd>"
                }
            }
        }
        if {[dict exists $row authentication]} {
            append html {<dt>Authentication and link diagnostics</dt><dd>Informational; DKIM signatures are not cryptographically verified.</dd>}
            dict for {key value} [dict get $row authentication metadata] {
                append html "<dt>[ns_quotehtml $key]</dt><dd>[ns_quotehtml $value]</dd>"
            }
        }
        if {[dict exists $row outcome]} {
            set outcome [dict get $row outcome]
            append html "<dt>Transaction outcome</dt><dd>[ns_quotehtml [dict get $outcome reason]]</dd>"
            append html "<dt>Ended</dt><dd>[ns_quotehtml [clock format [expr {[dict get $outcome timestamp] / 1000}] -format {%Y-%m-%d %H:%M:%S %z}]]</dd>"
            foreach {key label} {last-command {Last SMTP command} message-bytes {Message bytes (wire DATA)} relay-accepted {Relay accepted} relay-reply {Relay reply}} {
                if {[dict exists $outcome metadata $key]} {
                    append html "<dt>$label</dt><dd>[ns_quotehtml [dict get $outcome metadata $key]]</dd>"
                }
            }
        } else {
            append html {<dt>Transaction outcome</dt><dd>Not recorded in this log</dd>}
        }
        append html </dl></details></td></tr>
    }
    append html </tbody></table></div>
    return $html
}

# Shared selector for request logs and event logs. Full paths distinguish logs
# from different servers; mkchart also accepts legacy basename query values.

# Author: Vlad Seryakov vlad@crystalballinc.com
# Gustaf Neumann

namespace eval smtpd {}

# Optional evaluator contract: named SMTP inputs in, one SPF result out.
proc smtpd::checkspf {args} {
    ns_parseargs {-ip -sender -helo} $args
    foreach name {ip sender helo} {
        if {![info exists $name]} {::error "missing required option -$name"}
        set value [set $name]
        if {[string length $value] > 1024 || [regexp {[\x00-\x1f\x7f]} $value]} {
            ::error "invalid SPF input -$name"
        }
    }
    if {$ip eq "" || $helo eq ""} {::error "SPF requires a peer IP and HELO identity"}
    if {[namespace which -command ::ns_ip] eq ""} {
        return -code error -errorcode {NSSMTPD SPF NAVISERVER_VERSION} \
            "smtpd::checkspf requires NaviServer 5.0 or newer (ns_ip valid)"
    }
    if {![ns_ip valid $ip]} {::error "invalid SPF peer IP"}
    if {$sender eq "<>"} {set sender ""}
    set prefix [ns_config ns/server/[ns_info server]/module/nssmtpd spfproc ""]
    if {$prefix eq ""} {
        return -code error -errorcode {NSSMTPD SPF DISABLED} "SPF evaluation is disabled"
    }
    set result [uplevel #0 [list {*}$prefix -ip $ip -sender $sender -helo $helo]]
    if {$result ni {pass fail softfail neutral none temperror permerror}} {
        ::error "SPF evaluator returned an invalid result"
    }
    return $result
}

# External libspf2 utility (not the incompatible Mail::SPF Perl utility).
# Run in a NaviServer proxy with a bounded wait. Discard diagnostic output:
# libspf2 defines the result through its exit status.
proc smtpd::spfquery {args} {
    ns_parseargs {-command {-timeout 10} {-pool smtpd-spf} -ip -sender -helo} $args
    foreach name {command ip sender helo} {
        if {![info exists $name]} {::error "missing required option -$name"}
    }
    if {![string is integer -strict $timeout] || $timeout <= 0} {
        ::error "SPF timeout must be a positive number of seconds"
    }
    if {[namespace which -command ::ns_proxy] eq ""} {
        return -code error -errorcode {NSSMTPD SPF EXEC} \
            "smtpd::spfquery requires the nsproxy module"
    }
    set proxy ""
    try {
        set proxy [ns_proxy get $pool -timeout $timeout]
        # Use --option=value so an SMTP identity can never become a Tcl exec
        # pipeline/redirection operator or a separate command-line option.
        ns_proxy eval $proxy [list exec -- $command \
            --ip=$ip --sender=$sender --helo=$helo > /dev/null 2> /dev/null] $timeout
    } trap CHILDSTATUS {message options} {
        set status [lindex [dict get $options -errorcode] 2]
        if {$status >= 1 && $status <= 7} {
            return [lindex {invalid neutral pass fail softfail none temperror permerror} $status]
        }
        return -code error -errorcode {NSSMTPD SPF EXEC} \
            "SPF utility failed or timed out (exit status $status)"
    } on error {message options} {
        return -code error -errorcode {NSSMTPD SPF EXEC} \
            "SPF utility could not complete: $message"
    } finally {
        if {$proxy ne ""} {ns_proxy put $proxy}
    }
    # Zero is SPF_RESULT_INVALID, not success, for libspf2's spfquery.
    return -code error -errorcode {NSSMTPD SPF EXEC} \
        "SPF utility returned an invalid result (exit status 0)"
}

# Optional native backend. Custom evaluators implement the same named options.
proc smtpd::libspf2 {args} {
    ns_parseargs {-ip -sender -helo} $args
    return [ns_smtpd spf $ip $sender $helo]
}


# Shared by SMTP reception, ns_smtpd send, and ns_smtpd resolve.
# The resolver is a command prefix returning FINAL envelope recipients.
# Backend access and recursive alias policy belong to the configured proc.
proc smtpd::resolvealiases {resolver recipients maxrcpt passthrough} {
    set resolved {}
    set seen [dict create]
    foreach recipient $recipients {
        set command [list {*}$resolver -recipient $recipient]
        # Outgoing sends, resolve, and LOCAL submissions must override any
        # rejection default in the configuration or callback prefix.
        if {$passthrough} {lappend command -rejectunknown false}
        set targets [uplevel #0 $command]
        if {[llength $targets] == 0} {
            return -code error -errorcode {NSSMTPD ALIAS UNKNOWN} \
                "unknown recipient: $recipient"
        }
        foreach target $targets {
            # Require one bare envelope address, never SMTP commands or an
            # address list embedded inside a single list element.
            if {$target eq "" || [regexp {[\x00-\x1f\x7f]} $target]
                || [ns_smtpd checkemail $target] ne $target} {
                return -code error -errorcode {NSSMTPD ALIAS INVALID} \
                    "alias resolver returned an invalid envelope recipient"
            }
            if {![dict exists $seen $target]} {
                dict set seen $target 1
                lappend resolved $target
                if {[llength $resolved] > $maxrcpt} {
                    return -code error -errorcode {NSSMTPD ALIAS LIMIT} \
                        "too many recipients after alias expansion"
                }
            }
        }
    }
    return $resolved
}

# Optional address-only aliases(5)/virtual(5) text-file backend. Read one
# snapshot per lookup; administrators can replace the file atomically.
proc smtpd::resolvefilealiases {args} {
    lassign [smtpd::ParseFileAliasArgs $args] format filename domains recipient rejectunknown
    set domains [lmap domain $domains {string tolower $domain}]
    set domain [string tolower [lindex [split $recipient @] end]]
    if {$domain ni $domains} {return [list $recipient]}
    set map [smtpd::ReadAliasFile $format $filename]
    if {$rejectunknown && [smtpd::FileAliasKey $format $map $recipient] eq ""} {
        return -code error -errorcode {NSSMTPD ALIAS UNKNOWN} \
            "unknown recipient: $recipient"
    }
    set budget 10000
    return [smtpd::ExpandFileAlias $format $map $domains $recipient {} budget]
}

# Named options for alias expansion and optional recipient validation.
# The module appends -recipient and, for passthrough, -rejectunknown false.
proc smtpd::ParseFileAliasArgs {arguments} {
    ns_parseargs {-format -file -domains -recipient -rejectunknown} $arguments
    if {![info exists recipient]} {::error "missing required option -recipient"}
    set path ns/server/[ns_info server]/module/nssmtpd
    if {![info exists rejectunknown]} {
        set rejectunknown [ns_config $path rejectunknownrecipients false]
    }
    if {![string is boolean -strict $rejectunknown]} {
        ::error "rejectunknownrecipients / -rejectunknown must be a boolean"
    }
    if {![info exists format]} {
        set format [ns_config $path aliasformat virtual]
    }
    foreach option {file domains} {
        if {![info exists $option]} {
            set section [ns_configsection $path]
            if {$section eq "" || [ns_set ifind $section alias$option] < 0} {
                ::error "provide -$option or configure alias$option"
            }
            set $option [ns_config $path alias$option]
        }
    }
    if {$format ni {aliases virtual}} {
        ::error "alias file format must be aliases or virtual"
    }
    return [list $format $file $domains $recipient $rejectunknown]
}

proc smtpd::ReadAliasFile {format filename} {
    if {$format ni {aliases virtual}} {
        ::error "alias file format must be aliases or virtual"
    }
    set channel [open $filename r]
    try {
        fconfigure $channel -encoding utf-8
        set lines {}
        set logical ""
        while {[gets $channel line] >= 0} {
            if {[string trim $line] eq "" || [regexp {^\s*#} $line]} {continue}
            if {[regexp {^\s} $line]} {
                if {$logical eq ""} {::error "alias file has an orphan continuation"}
                append logical " " [string trim $line]
            } else {
                if {$logical ne ""} {lappend lines $logical}
                set logical $line
            }
        }
        if {$logical ne ""} {lappend lines $logical}
    } finally {
        close $channel
    }
    set map {}
    foreach line $lines {
        if {$format eq "aliases"} {
            set valid [regexp {^([^:\s]+)\s*:\s*(.+)$} $line -> key value]
        } else {
            set valid [regexp {^(\S+)\s+(.+)$} $line -> key value]
        }
        if {!$valid} {::error "invalid $format entry in $filename: $line"}
        set key [string tolower $key]
        if {$format eq "aliases"} {
            set valid [regexp {^[a-z0-9_.+%-]+$} $key]
        } else {
            set valid [regexp {^([a-z0-9_.+%-]+)?@[a-z0-9.-]+$} $key]
        }
        if {!$valid} {::error "unsupported $format key: $key"}
        if {[dict exists $map $key]} {::error "duplicate alias key: $key"}
        set targets {}
        foreach group [split $value ,] {
            set group [string trim $group]
            if {$group eq ""} {::error "empty alias destination for $key"}
            # Virtual maps also allow whitespace-separated destinations.
            # Split comma groups first so empty comma entries remain errors.
            if {$format eq "virtual"} {
                set addresses [regexp -all -inline {\S+} $group]
            } else {
                set addresses [list $group]
            }
            foreach target $addresses {
                # Deliberately exclude programs, files, includes, quoted/display
                # addresses and Tcl evaluation. This backend only forwards mail.
                if {![regexp {^[a-zA-Z0-9_.+%-]+(@[a-zA-Z0-9.-]+)?$} $target]} {
                    ::error "unsupported alias destination for $key: $target"
                }
                lappend targets $target
            }
        }
        dict set map $key $targets
    }
    return $map
}

# Shared matching order for validation and expansion.
proc smtpd::FileAliasKey {format map recipient} {
    set address [string tolower $recipient]
    lassign [split $address @] local domain
    set key [expr {$format eq "aliases" ? $local : $address}]
    if {[dict exists $map $key]} {return $key}
    if {$format eq "virtual" && [dict exists $map @$domain]} {return @$domain}
    return ""
}

# Bound both chain depth and total work, including wide recursive maps.
proc smtpd::ExpandFileAlias {format map domains recipient path budgetVar} {
    upvar 1 $budgetVar budget
    if {[incr budget -1] < 0 || [llength $path] >= 32} {
        ::error "alias expansion exceeds file resolver limit"
    }
    set address [string tolower $recipient]
    lassign [split $address @] local domain
    if {$domain ni $domains} {return [list $recipient]}
    set key [smtpd::FileAliasKey $format $map $recipient]
    if {$key eq ""} {return [list $recipient]}
    if {$address in $path} {::error "alias cycle at $recipient"}
    lappend path $address
    set result {}
    foreach target [dict get $map $key] {
        if {[string first @ $target] < 0} {append target @$domain}
        # A self destination is terminal, as in a virtual identity mapping.
        if {[string equal -nocase $target $recipient]} {
            dict set result $target 1
        } else {
            foreach final [smtpd::ExpandFileAlias $format $map $domains $target $path budget] {
                dict set result $final 1
            }
        }
    }
    return [dict keys $result]
}

proc smtpd::init {} {

    set path "ns/server/[ns_info server]/module/nssmtpd"
    ns_smtpd relay set {*}[ns_config $path relaydomains "localhost"]
    ns_log notice "smtpd::init: Relay Domains: [ns_smtpd relay get]"
    ns_smtpd local set {*}[ns_config $path localdomains "localhost"]
    ns_log notice "smtpd::init: Local Domains: [ns_smtpd local get]"
    if {[ns_config $path recipientpolicyproc ""] ne ""} {
        smtpd::greylistinit
    }
}

# Decode message header
proc smtpd::decodeHdr { str } {

    set b [string first "=?" $str]
    if { $b >= 0 } {
        set b [string first "?" $str $b+2]
        if { $b > 0 } {
            set e [string first "?=" $str $b]
            if { $e == -1 } { set e end } else { incr e -1 }
            switch [string index $str $b+1] {
                Q {
                    set str [ns_smtpd decode qprint [string range $str $b+3 $e]]
                }
                B {
                    set str [ns_smtpd decode base64 [string range $str $b+3 $e]]
                }
            }
        }
    }
    return $str
}

# Parses bounces
proc smtpd::decodeBounce { id body } {

    set sender_email ""
    set filters {
        {The following addresses had permanent fatal errors -----[\r\n]+<?([^>\r\n]+)} {}
        {The following addresses had permanent delivery errors -----[\r\n]+<?([^>\r\n]+)} {}
        {The following addresses had delivery errors---[\r\n]+<?([^> \r\n]+)} {}
        {<([^>]+)>:[\r\n]+Sorry, no mailbox here by that name.} {}
        {Your message.+To:[ \t]+([^ \r\n]+)[\r\n]+.+did not reach the following recipient} {}
        {Your message cannot be delivered to the following recipients:.+Recipient address: ([^ \r\n]+)} {}
        {Failed addresses follow:.+<([^>]+)>} {}
        {[\r\n]+([^ \t]+) - no such user here.} {}
        {qmail-send.+permanent error.+<([^>]+)>:} {}
        {Receiver not found: ([^ \r\n\t]+)} {%s@compuserve.com}
        {Failed to deliver to '<([^>]+)>'} {}
        {The following address\(es\) failed:[\r\n\t ]+([^ \t\r\n]+)} {}
        {User<([^>]+)>.+550 Invalid recipient} {}
        {Delivery to the following recipients failed.[\r\n\t ]+([^ \t\r\n]+)} {}
        {<([^>]+)>:[\r\n]+Sorry.+control/locals file, so I don't treat it as local} {}
        {RCPT To:<([^>]+)>.+550} {}
        {550.*<([^>]+)>... User unknown} {}
        {550.*unknown user <([^<]+)>} {}
        {could not be delivered.+The .+ program[^<]+<([^<]+)>} {}
        {The following text was generated during the delivery attempt:------ ([^ ]+) ------} {}
        {The following addresses were not valid[\r\n\t ]+<([^>]+)>} {}
        {These addresses were rejected:[\r\n\t ]+([^ \t\r\n]+)} {}
        {Unexpected recipient failure - 553 5.3.0 <([^>]+)>} {}
        {not able to deliver to the following addresses.[\r\n\t ]+<([^>]+)>} {}
        {cannot be sent to the following addresses.[\r\n\t ]+<([^>]+)>} {}
        {was not delivered to:[\r\n\t ]+([^ \r\n]+)} {}
        {<([^>]+)>  delivery failed; will not continue trying} {}
        {User mailbox exceeds allowed[^:]+: ([^ \n\r\t]+)} {}
        {could not be delivered[^<]+<([^>]+)>:} {}
        {undeliverable[^<]+<([^@]+@[^>]+)>} {}
        {could not be delivered.+Bad name:[ \t]+([^ \r\n\t]+)} {%s@oracle.com}
    }

    foreach { filter data } $filters {
        if { [regexp -nocase $filter $body d sender_email] } {
            if { $data ne "" } { set sender_email [format $data $sender_email] }
            break
        }
    }
    if { $sender_email ne "" } {
        foreach rcpt [ns_smtpd getrcpt $id] {
            lassign $rcpt user_email user_flags spam_score
            ns_log Error smtpd::decodeBounce: $id: $user_email: $sender_email
        }
    }
    return $sender_email
}

# Mailing list/Sender detection
proc smtpd::decodeSender { id } {

    set From [ns_smtpd getfrom $id]
    if { [set Sender [ns_smtpd checkemail [ns_smtpd gethdr $id Sender]]] ne "" } {
        return $Sender
    }
    if { [set ReplyTo [ns_smtpd checkemail [ns_smtpd gethdr $id Reply-To]]] ne "" && $ReplyTo ne $From } {
        return $ReplyTo
    }
    if { [set XSender [ns_smtpd checkemail [ns_smtpd gethdr $id X-Sender]]] ne "" } {
        return $XSender
    }
    # Try for old/obsolete mailing lists
    if { [ns_smtpd gethdr $id Mailing-List] ne "" ||
         [ns_smtpd gethdr $id List-Help] ne "" ||
         [ns_smtpd gethdr $id List-Unsubscribe] ne "" ||
         [ns_smtpd gethdr $id Precedence] in {"bulk" "list"}
     } {
        if { $ReplyTo ne "" } {
            return $ReplyTo
        } else {
            return $From
        }
    }
    return $From
}

proc smtpd::helo { id } {
    ns_log Debug(smtpd) "### smtpd::helo $id"
}

proc smtpd::mail { id } {
    ns_log Debug(smtpd) "### smtpd::mail $id"
}

# An optional RCPT policy, separate from recipient existence checks. The
# callback sees the original envelope and must not mutate the SMTP session.
proc smtpd::checkpolicy {id} {
    set prefix [ns_config ns/server/[ns_info server]/module/nssmtpd recipientpolicyproc ""]
    if {$prefix eq ""} {
        return 1
    }
    if {[ns_smtpd getflag $id -1] & [ns_smtpd flag LOCAL]} {
        smtpd::logevent $id policy [dict create action accept reason local-bypass \
                                      recipient [lindex [ns_smtpd getrcpt $id 0] 0]]
        return 1
    }
    try {
        set sender [ns_smtpd getfrom $id]
        if {$sender eq "<>"} {set sender ""}
        set context [dict create id $id peeraddr [ns_conn peeraddr] \
                         sender $sender helo [ns_smtpd gethelo $id] \
                         recipient [lindex [ns_smtpd getrcpt $id 0] 0]]
        set result [uplevel #0 [list {*}$prefix $context]]
        set action [dict get $result action]
        set details [dict merge {reason recipient-policy} $result \
                         [dict create recipient [dict get $context recipient]]]
        switch -- $action {
            accept {
                smtpd::logevent $id policy $details
                return 1
            }
            defer {set code "451 4.7.1"; set message "Please try again later"}
            reject {set code "550 5.7.1"; set message "Recipient rejected by policy"}
            default {::error "recipientpolicyproc returned an invalid action"}
        }
        if {[dict exists $result message]} {set message [dict get $result message]}
        # One bounded ASCII line: never let a callback inject SMTP replies.
        if {[string length $message] > 400 || ![regexp {^[\x20-\x7e]+$} $message]} {
            ::error "recipientpolicyproc returned an invalid message"
        }
        set reply "$code $message\r\n"
        smtpd::logevent $id policy $details
        ns_log Notice "smtpd policy: $action [list $context]"
    } on error {message options} {
        ns_log Error "smtpd recipient policy failed: $message"
        smtpd::logevent $id policy [dict create action defer reason callback-error code 451]
        set reply "451 4.3.0 Recipient policy unavailable\r\n"
    }
    ns_smtpd delrcpt $id 0
    ns_smtpd setreply $id $reply
    return 0
}

# Called once at startup by smtpd::init when a recipient policy is enabled.
# Custom initproc implementations using greylisting must call this too.
proc smtpd::greylistinit {} {
    set path ns/server/[ns_info server]/module/nssmtpd
    # Null senders require a separately constrained HELO identity; an empty
    # sender/recipient pair alone would authorize any SPF-passing HELO domain.
    foreach exception [ns_config $path greylistspfexceptions {}] {
        if {[llength $exception] != 2 || [lindex $exception 0] in {{} <>}
            || [lindex $exception 1] eq ""} {
            ::error "greylistspfexceptions requires nonempty sender/recipient pairs"
        }
    }
    set config {}

    foreach {name default} {delay 300 retrywindow 14400 lifetime 604800 maxentries 10000} {
        set value [ns_config $path greylist$name $default]
        if {![string is integer -strict $value] || $value <= 0} {
            ::error "greylist$name must be a positive integer (seconds for time values)"
        }
        dict set config $name $value
    }
    if {[dict get $config retrywindow] <= [dict get $config delay]} {
        ::error "greylistretrywindow must exceed greylistdelay"
    }
    if {![nsv_exists smtpd-greylist mutex]} {
        nsv_set smtpd-greylist mutex [ns_mutex create smtpd-greylist]
    }
    ns_mutex eval [nsv_get smtpd-greylist mutex] {
        nsv_set smtpd-greylist config $config
        nsv_set smtpd-greylist sweep 0
        nsv_array reset smtpd-greylist-entries {}
    }
}

proc smtpd::greylist {context} {
    set path ns/server/[ns_info server]/module/nssmtpd
    set pair [list [dict get $context sender] [dict get $context recipient]]
    # Match exact identities before spending any time on DNS. SPF pass alone
    # must never exempt arbitrary senders from greylisting.
    foreach exception [ns_config $path greylistspfexceptions {}] {
        if {[llength $exception] != 2} {error "greylistspfexceptions requires sender/recipient pairs"}
        if {[lindex $exception 0] eq [lindex $pair 0]
            && [lindex $exception 1] eq [lindex $pair 1]} {
            try {
                set result [smtpd::checkspf -ip [dict get $context peeraddr] \
                                -sender [dict get $context sender] -helo [dict get $context helo]]
                if {$result eq "pass"} {
                    return [dict create action accept reason verified-report-sender]
                }
            } on error {message options} {
                ns_log Warning "smtpd SPF exception evaluation failed: $message"
            }
            break
        }
    }
    set key [list [dict get $context peeraddr] \
                 [dict get $context sender] [dict get $context recipient]]
    set decision [smtpd::GreylistCheck $key [clock seconds]]
    # No message body or subject is logged.
    if {[dict get $decision reason] in {new retry expired capacity}} {
        ns_log Notice "smtpd greylist: [dict get $decision reason] [list $key]"
    }
    dict set decision reason greylist-[dict get $decision reason]
    return $decision
}

# Logging is observational: a logging failure must not change mail policy.
# Custom callbacks can use this wrapper or ns_smtpd logevent directly.
proc smtpd::logevent {id event details} {
    if {![ns_config -bool ns/server/[ns_info server]/module/nssmtpd eventlogging false]} {return}
    try {
        ns_smtpd logevent $id $event $details
    } on error {message options} {
        ns_log Error "smtpd event logging failed: $message"
    }
}

# The explicit time argument permits deterministic tests of expiry boundaries.
# The mutex covers both the transition and capacity checks across interpreters.
proc smtpd::GreylistCheck {key now} {
    ns_mutex eval [nsv_get smtpd-greylist mutex] {
        set config [nsv_get smtpd-greylist config]
        if {$now >= [nsv_get smtpd-greylist sweep]} {
            foreach {entry record} [nsv_array get smtpd-greylist-entries] {
                lassign $record first expires passed
                if {$now >= $expires} {nsv_unset smtpd-greylist-entries $entry}
            }
            nsv_set smtpd-greylist sweep [expr {$now + 60}]
        }
        set reason new
        if {[nsv_get smtpd-greylist-entries $key record]} {
            lassign $record first expires passed
            if {$now < $expires && $now >= $first} {
                if {$passed || $now - $first >= [dict get $config delay]} {
                    nsv_set smtpd-greylist-entries $key \
                        [list $first [expr {$now + [dict get $config lifetime]}] 1]
                    return [dict create action accept reason [expr {$passed ? "known" : "retry"}]]
                }
                # Early retries must not move the first-seen time or expiry.
                return [dict create action defer reason early]
            }
            nsv_unset smtpd-greylist-entries $key
            set reason expired
        }
        if {[nsv_array size smtpd-greylist-entries] >= [dict get $config maxentries]} {
            # Preserve existing entries and mail availability under overload.
            # New tuples pass without being remembered until space is reclaimed.
            return [dict create action accept reason capacity]
        }
        nsv_set smtpd-greylist-entries $key \
            [list $now [expr {$now + [dict get $config retrywindow]}] 0]
        return [dict create action defer reason $reason]
    }
}

proc smtpd::rcpt { id } {
    if {![smtpd::checkpolicy $id]} {return}

    # Current recipient
    lassign [ns_smtpd getrcpt $id 0] user_email user_flags spam_score

    ns_log Debug(smtpd) "### smtpd::rcpt $id $user_email ($user_flags & [ns_smtpd flag RELAY])"

    # Non-relayable user, just pass it through
    if { !($user_flags & [ns_smtpd flag RELAY]) } {
        ns_smtpd setflag $id 0 VERIFIED
        ns_log Debug(smtpd) "### smtpd::rcpt $id $user_email .... pass through"
        return
    }
    # Example of checking by recipient
    switch -regexp -- $user_email {
        "joe@domain.com" -
        "joe@localhost" {
            # User is not allowed to receive any mail
            ns_smtpd setreply $id "550 ${user_email}... User unknown\r\n"
            ns_smtpd delrcpt $id 0
            ns_log Debug(smtpd) "### smtpd::rcpt $id $user_email .... not allowed"
            return
        }

        default {
            # Check everything for this domain
            ns_smtpd setflag $id 0 VIRUSCHECK
            ns_smtpd setflag $id 0 SPAMCHECK
            #return
        }
    }
    ns_log Debug(smtpd) "### smtpd::rcpt $id $user_email VERIFIED"

    # All other emails are allowed
    ns_smtpd setflag $id 0 VERIFIED
}

proc smtpd::data { id } {
    ns_log Debug(smtpd) "### smtpd::data $id"

    # Global connection flags
    set conn_flags [ns_smtpd getflag $id -1]
    # Sender email
    set sender_email [smtpd::decodeSender $id]
    # Subject from the headers
    set subject [ns_smtpd gethdr $id Subject]
    # Special headers
    set signature [ns_smtpd gethdr $id X-Smtpd-Signature]
    set virus_status [ns_smtpd gethdr $id X-Smtpd-Virus-Status]
    # Message data
    lassign [ns_smtpd getbody $id] body body_offset body_size

    # Find users who needs verification
    foreach rcpt [ns_smtpd getrcpt $id] {
        lassign $rcpt deliver_email user_flags spam_score
        # Non-relayable user
        if { !($user_flags & [ns_smtpd flag RELAY]) } {
            ns_log Debug(smtpd) "### smtpd::data $id $ $rcpt .... Non-relayable"
            continue
        }
        # SPAM detected
        if { $user_flags & [ns_smtpd flag GOTSPAM] } {
            ns_log Debug(smtpd) "### smtpd::data $id $ $rcpt .... GOTSPAM"
            continue
        }
        # Already delivered user
        if { $user_flags & [ns_smtpd flag DELIVERED] } {
            ns_log Debug(smtpd) "### smtpd::data $id $ $rcpt .... DELIVERED"
            continue
        }
        # Virus detected
        if { $conn_flags & [ns_smtpd flag GOTVIRUS] } {
            ns_log Debug(smtpd) "### smtpd::data $id $ $rcpt .... GOTVIRUS"
            continue
        }
        # Recipient is okay
        set users($deliver_email) $spam_score
    }
    if { [array size users] > 0 } {
        # Build attachments list
        foreach file [ns_smtpd gethdrs $id X-Smtpd-File] {
            append attachments $file " "
        }
        # Save the message in the database or do other things to the message,
        # i will save in the mailbox just as an example
        if { [catch {
            set fd [open /tmp/mailbox a]
            puts $fd "From $sender_email [ns_fmttime [ns_time]]\n$body"
            close $fd
        } errmsg] } {
            ns_smtpd setflag $id -1 ABORT
            ns_log Error smtpd:data: $errmsg
            ns_smtpd setreply $id "421 Transaction failed (Msg)\r\n"
        }
    }
}


proc smtpd::error { id } {
    ns_log Debug(smtpd) "### smtpd::error $id"

    set line [ns_smtpd getline $id]
    # sendmail 550 user unknown reply
    if { [regexp -nocase {RCPT TO: <([^@ ]+@[^ ]+)>: 550} $line d user_email] } {
        ns_log notice "smtpd::error: $id: Dropping $user_email"
    }
}


#
# Local variables:
#    mode: tcl
#    tcl-indent-level: 4
#    indent-tabs-mode: nil
# End:

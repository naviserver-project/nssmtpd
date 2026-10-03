# Optional SPF result evaluator (RFC 7208), using nsdns and ns_memoize.
# No dependency is required until smtpd::spf is called. All helpers are private.
namespace eval smtpd {}

proc smtpd::SpfError {result message} {
    return -code error -errorcode [list NSSMTPD SPF RESULT $result] $message
}

proc smtpd::SpfRemaining {deadline} {
    set ms [expr {$deadline - [clock milliseconds]}]
    if {$ms <= 0} {SpfError temperror "SPF evaluation deadline exceeded"}
    return [expr {$ms / 1000.0}]
}

proc smtpd::SpfName {name} {
    if {[string index $name end] eq "."} {set name [string range $name 0 end-1]}
    return [string tolower $name]
}

proc smtpd::SpfDomainValid {name} {
    # Utility labels (_spf) and macro-expanded printable labels are allowed.
    if {[string length $name] > 253 || [regexp {[^\x21-\x7e]} $name]} {return 0}
    set labels [split $name .]
    if {[llength $labels] < 2} {return 0}
    foreach label $labels {
        if {$label eq "" || [string length $label] > 63} {return 0}
    }
    return 1
}

proc smtpd::spf {args} {
    ns_parseargs {{-timeout 20} -ip -sender -helo} $args
    foreach name {ip sender helo} {
        if {![info exists $name]} {::error "missing required option -$name"}
        # An empty envelope sender is valid; control characters are not.
        if {[string length [set $name]] > 1024 || ![string is print [set $name]]} {
            ::error "invalid SPF input -$name"
        }
    }
    set started [clock milliseconds]
    set inputs [list peeraddr $ip sender $sender helo $helo]
    try {
        set result [SpfCheck $ip $sender $helo $timeout]
    } on error {message options} {
        ns_log Error "smtpd SPF Tcl: $inputs result error errorcode [list [dict get $options -errorcode]] elapsed_ms [expr {[clock milliseconds]-$started}]"
        return -options $options $message
    }
    ns_log Notice "smtpd SPF Tcl: $inputs result $result elapsed_ms [expr {[clock milliseconds]-$started}]"
    return $result
}

proc smtpd::SpfCheck {ip sender helo timeout} {
    foreach command {ns_ip ns_dns} {
        if {[namespace which -command ::$command] eq ""} {
            return -code error -errorcode {NSSMTPD SPF DEPENDENCY} \
                "smtpd::spf requires NaviServer 5.0+ and nsdns with -details, -jointxt and -timeout ($command unavailable)"
        }
    }
    if {![string is double -strict $timeout] || !($timeout > 0 && $timeout <= 120)} {
        ::error "SPF timeout must be greater than zero and at most 120 seconds"
    }
    if {$helo eq "" || ![ns_ip valid $ip]} {::error "SPF requires a valid peer IP and HELO identity"}
    set ip [SpfNormalizeIP $ip]
    set family [expr {[dict get [ns_ip properties $ip] type] eq "IPv4" ? 4 : 6}]
    if {$sender in {"" <>}} {set sender postmaster@$helo}
    set at [string last @ $sender]
    if {$at < 0} {set sender postmaster@$sender; set at [string last @ $sender]}
    set local [string range $sender 0 $at-1]
    if {$local eq ""} {set local postmaster; set sender $local$sender}
    set origin [string range $sender [expr {[string last @ $sender]+1}] end]
    set domain [SpfName $origin]
    if {![SpfDomainValid $domain]} {return none}
    set ctx [dict create ip $ip family $family sender $sender local $local origin $origin helo $helo \
                 deadline [expr {[clock milliseconds]+wide($timeout*1000)}] terms 0 voids 0 active {}]
    try {
        return [SpfEvaluate ctx $domain]
    } trap {NSSMTPD SPF RESULT} {message options} {
        return [lindex [dict get $options -errorcode] 3]
    }
}

# Address representation helpers accept addresses already validated by ns_ip.
# TODO (NaviServer 5.2): add ns_ip normalize and a packed-byte operation, then
# use them here when available, retaining these fallbacks for NaviServer 5.0.
proc smtpd::SpfNormalizeIP {ip} {
    # SPF treats IPv4-mapped IPv6 as IPv4. Preserve other addresses unchanged.
    if {[dict get [ns_ip properties $ip] type] eq "IPv6"
        && [ns_ip match ::ffff:0:0/96 $ip]} {
        set hex [SpfIPv6Hex $ip]
        set bytes {}
        foreach {a b} [split [string range $hex 24 end] ""] {
            scan $a$b %x byte
            lappend bytes $byte
        }
        return [join $bytes .]
    }
    return $ip
}

proc smtpd::SpfIPv6Hex {ip} {
    # Return 32 lowercase hex digits in network byte order for a valid IPv6 IP.
    if {[string first . $ip] >= 0} {
        set colon [string last : $ip]
        lassign [split [string range $ip $colon+1 end] .] a b c d
        set ip [string range $ip 0 $colon][format %x:%x [expr {$a*256+$b}] [expr {$c*256+$d}]]
    }
    set gap [string first :: $ip]
    if {$gap >= 0} {
        set left [split [string range $ip 0 $gap-1] :]
        set right [split [string range $ip $gap+2 end] :]
        set words [concat $left [lrepeat [expr {8-[llength $left]-[llength $right]}] 0] $right]
    } else {set words [split $ip :]}
    set hex ""
    foreach word $words {scan $word %x n; append hex [format %04x $n]}
    return $hex
}

proc smtpd::SpfTerm {context} {
    upvar 1 $context ctx
    dict incr ctx terms
    if {[dict get $ctx terms] > 10} {SpfError permerror "SPF DNS term limit exceeded"}
}

proc smtpd::SpfDnsFetch {name type} {
    # This interpreter-local deadline is scoped by SpfDnsResponse. It is not
    # part of the cache key: it controls waiting, not the DNS answer.
    variable spfDnsDeadline
    set started [clock milliseconds]
    lassign $spfDnsDeadline deadline token
    try {
        set response [ns_dns lookup -details -jointxt -timeout [SpfRemaining $deadline] -- $name $type]
    } trap NS_TIMEOUT {message} {
        SpfError temperror $message
    } trap {NSDNS NETWORK} {message} {
        SpfError temperror $message
    } trap {NSDNS PROTOCOL} {message} {
        SpfError temperror $message
    }
    if {[dict get $response truncated] || [dict get $response rcode] ni {0 3}} {
        SpfError temperror "unsuccessful DNS response for $name $type"
    }
    # Cap cache retention at five minutes; never extend any DNS TTL. Negative
    # responses require an SOA, with min(SOA TTL, SOA MINIMUM), RFC 2308.
    set ttl 300
    set answer [dict get $response answer]
    if {[dict get $response rcode] == 3 || $answer eq ""} {
        set ttl 0
        foreach rr [dict get $response authority] {
            if {[lindex $rr 1] eq "SOA"} {
                set ttl [expr {min(300, [lindex $rr end], [lindex $rr 8])}]
                break
            }
        }
    }
    foreach rr $answer {set ttl [expr {min($ttl, [lindex $rr end])}]}
    return [list [expr {$started + 1000*$ttl}] $response $token]
}

proc smtpd::SpfDnsResponse {context name type} {
    upvar 1 $context ctx
    variable spfDnsDeadline
    set saved [info exists spfDnsDeadline]
    if {$saved} {set previous $spfDnsDeadline}
    set deadline [dict get $ctx deadline]
    set token [list [ns_thread id] [clock clicks]]
    set spfDnsDeadline [list $deadline $token]
    set key [list ::smtpd::SpfDnsFetch $name $type]
    try {
        set remaining [SpfRemaining $deadline]
        lassign [ns_memoize -timeout $remaining -expires 300 -- $key] expires response fetchedBy
        if {$expires <= [clock milliseconds]} {
            # ns_memoize accepts expiry before evaluating its script. Inspect
            # the returned DNS expiry as well, and evict only this exact key.
            # Escape glob characters from macro-expanded names.
            ns_memoize_flush [regsub -all {[][\\*?]} $key {\\&}]
            if {$fetchedBy ne $token} {
                lassign [ns_memoize -timeout [SpfRemaining $deadline] -expires 300 -- $key] expires response fetchedBy
            }
            if {$expires <= [clock milliseconds]} {
                ns_memoize_flush [regsub -all {[][\\*?]} $key {\\&}]
            }
        }
        SpfRemaining $deadline
        return $response
    } trap NS_TIMEOUT {message} {
        SpfError temperror $message
    } finally {
        if {$saved} {set spfDnsDeadline $previous} else {unset spfDnsDeadline}
    }
}

proc smtpd::SpfDns {context name type} {
    upvar 1 $context ctx
    set name [SpfName $name]
    if {![SpfDomainValid $name]} {SpfError permerror "invalid SPF DNS name"}
    set seen {}
    for {set hop 0} {$hop < 16} {incr hop} {
        if {$name in $seen} {SpfError temperror "DNS CNAME loop"}
        lappend seen $name
        set response [SpfDnsResponse ctx $name $type]
        if {[dict get $response rcode] == 3 || [dict get $response answer] eq ""} {
            dict incr ctx voids
            if {[dict get $ctx voids] > 2} {SpfError permerror "SPF void lookup limit exceeded"}
            return {}
        }
        # Follow only the queried owner and its CNAME chain, never unrelated
        # answers or additional-section addresses.
        set records [dict get $response answer]
        set queried $name
        while {1} {
            set found {}; set alias ""
            foreach rr $records {
                if {[SpfName [lindex $rr 0]] ne $name} {continue}
                if {[lindex $rr 1] eq $type} {lappend found $rr}
                if {[lindex $rr 1] eq "CNAME"} {set alias [SpfName [lindex $rr 2]]}
            }
            if {$found ne ""} {return $found}
            if {$alias eq ""} {
                if {$name eq $queried} {return {}}
                break
            }
            if {$alias in $seen || [llength $seen] >= 16} {SpfError temperror "DNS CNAME loop or limit"}
            if {![SpfDomainValid $alias]} {SpfError temperror "invalid DNS CNAME"}
            if {$name ne $queried} {lappend seen $name}
            set name $alias
        }
    }
    SpfError temperror "DNS CNAME limit exceeded"
}

proc smtpd::SpfMacroTokens {text {domainSpec 1}} {
    set tokens {}
    for {set pos 0} {$pos < [string length $text]} {} {
        set rest [string range $text $pos end]
        if {[regexp {^[^%]+} $rest literal]} {
            if {[regexp {[^\x21-\x7e]} $literal]} {SpfError permerror "invalid SPF macro literal"}
            lappend tokens [list literal $literal]
            incr pos [string length $literal]
        } elseif {[regexp {^%[%_-]} $rest literal]} {
            lappend tokens [list literal [dict get {%% % %_ { } %- %20} $literal]]
            incr pos 2
        } elseif {[regexp -nocase {^%\{([slodiphv])([0-9]*)(r?)([.\-+,/_=]*)\}} $rest whole letter count reverse delimiters]} {
            if {$count ne "" && [string trimleft $count 0] eq ""} {SpfError permerror "zero SPF macro transformer"}
            # Clamp without converting arbitrarily long decimal strings.
            set count [string trimleft $count 0]
            if {[string length $count] > 3} {set count 999}
            if {$delimiters eq ""} {set delimiters .}
            lappend tokens [list macro $letter $count $reverse $delimiters]
            incr pos [string length $whole]
        } else {SpfError permerror "invalid SPF macro"}
    }
    if {$domainSpec && ![regexp -nocase {(\.[a-z0-9]*[a-z][a-z0-9]*\.?|\.[a-z0-9]+-[a-z0-9-]*[a-z0-9]\.?|%\{[^\}]+\}|%%|%_|%-)$} $text]} {
        SpfError permerror "invalid SPF domain-spec"
    }
    return $tokens
}

proc smtpd::SpfMacro {context text domain} {
    upvar 1 $context ctx
    set output ""
    foreach token [SpfMacroTokens $text] {
        lassign $token kind value count reverse delimiters
        if {$kind eq "literal"} {append output $value; continue}
        set letter $value
        switch -- [string tolower $letter] {
            s {set value [dict get $ctx sender]}
            l {set value [dict get $ctx local]}
            o {set value [dict get $ctx origin]}
            d {set value $domain}
            h {set value [dict get $ctx helo]}
            v {set value [expr {[dict get $ctx family] == 4 ? "in-addr" : "ip6"}]}
            i {
                set value [dict get $ctx ip]
                if {[dict get $ctx family] == 6} {set value [join [split [SpfIPv6Hex $value] ""] .]}
            }
            p {
                SpfTerm ctx
                set names [SpfValidatedNames ctx]
                set value [expr {$names eq "" ? "unknown" : [lindex $names 0]}]
                foreach name $names {
                    if {$name eq $domain} {set value $name; break}
                    if {[SpfWithin $name $domain]} {set value $name}
                }
            }
        }
        set parts [split $value $delimiters]
        if {$reverse ne ""} {set parts [lreverse $parts]}
        if {$count ne "" && $count < [llength $parts]} {set parts [lrange $parts end-[expr {$count-1}] end]}
        set value [join $parts .]
        if {[string is upper $letter]} {
            set escaped ""
            binary scan [encoding convertto utf-8 $value] cu* bytes
            foreach byte $bytes {
                set ch [format %c $byte]
                if {[regexp {^[a-zA-Z0-9._~-]$} $ch]} {append escaped $ch} else {append escaped [format %%%02X $byte]}
            }
            set value $escaped
        }
        append output $value
    }
    set output [SpfName $output]
    while {[string length $output] > 253 && [string first . $output] >= 0} {
        set output [string range $output [expr {[string first . $output]+1}] end]
    }
    if {![SpfDomainValid $output]} {SpfError permerror "invalid expanded SPF domain"}
    return $output
}

proc smtpd::SpfPrefix {value maximum} {
    if {![regexp {^(0|[1-9][0-9]{0,2})$} $value] || $value > $maximum} {SpfError permerror "invalid SPF prefix length"}
    return $value
}

proc smtpd::SpfParse {record} {
    set mechanisms {}; set modifiers {}
    foreach term [lrange [split $record " "] 1 end] {
        if {$term eq ""} {continue}
        if {[regexp {^([a-zA-Z][a-zA-Z0-9_.-]*)=(.*)$} $term -> name value]} {
            set name [string tolower $name]
            SpfMacroTokens $value [expr {$name in {redirect exp}}]
            if {$name in {redirect exp}} {
                if {[dict exists $modifiers $name]} {SpfError permerror "duplicate SPF modifier"}
                dict set modifiers $name $value
            }
            continue
        }
        if {![regexp {^([+?~-]?)([a-zA-Z0-9]+)(.*)$} $term -> qualifier name value]} {SpfError permerror "invalid SPF term"}
        if {$qualifier eq ""} {set qualifier +}
        set name [string tolower $name]
        set spec ""; set v4 32; set v6 128
        switch -- $name {
            all {if {$value ne ""} {SpfError permerror "invalid all mechanism"}}
            ip4 - ip6 {
                if {![regexp {^:([^/]+)(?:/([^/]+))?$} $value -> address prefix]} {SpfError permerror "invalid IP mechanism"}
                set family [string index $name end]
                if {![ns_ip valid $address] || [string first % $address] >= 0
                    || [dict get [ns_ip properties $address] type] ne "IPv$family"} {
                    SpfError permerror "invalid SPF address"
                }
                if {$prefix eq ""} {set prefix [expr {$family == 4 ? 32 : 128}]}
                SpfPrefix $prefix [expr {$family == 4 ? 32 : 128}]
                set spec $address/$prefix
            }
            a - mx {
                # Remove CIDR suffixes before parsing domain-spec (macro
                # delimiters themselves may contain slashes).
                if {[regexp {//([0-9]+)$} $value whole prefix]} {
                    set v6 [SpfPrefix $prefix 128]
                    set value [string range $value 0 end-[string length $whole]]
                }
                if {[regexp {/([0-9]+)$} $value whole prefix]} {
                    set v4 [SpfPrefix $prefix 32]
                    set value [string range $value 0 end-[string length $whole]]
                }
                if {$value ne ""} {
                    if {[string index $value 0] ne ":"} {SpfError permerror "invalid address mechanism"}
                    set spec [string range $value 1 end]
                    SpfMacroTokens $spec
                }
            }
            include - exists - ptr {
                if {$value eq "" && $name eq "ptr"} {
                    # The policy domain is the default.
                } elseif {[string index $value 0] eq ":"} {
                    set spec [string range $value 1 end]
                    SpfMacroTokens $spec
                } else {SpfError permerror "missing SPF domain-spec"}
            }
            default {SpfError permerror "unknown SPF mechanism"}
        }
        lappend mechanisms [list $name $qualifier $spec $v4 $v6]
    }
    return [list $mechanisms $modifiers]
}

proc smtpd::SpfWithin {name domain} {
    set suffix .$domain
    return [expr {$name eq $domain || [string range $name end-[expr {[string length $suffix]-1}] end] eq $suffix}]
}

proc smtpd::SpfValidatedNames {context} {
    upvar 1 $context ctx
    set ip [dict get $ctx ip]
    if {[dict get $ctx family] == 4} {
        set reverse [join [lreverse [split $ip .]] .].in-addr.arpa
        set type A
    } else {
        set reverse [join [lreverse [split [SpfIPv6Hex $ip] ""]] .].ip6.arpa
        set type AAAA
    }
    set names {}
    try {set records [SpfDns ctx $reverse PTR]} trap {NSSMTPD SPF RESULT temperror} {} {
        SpfRemaining [dict get $ctx deadline]
        return {}
    }
    foreach rr [lrange $records 0 9] {
        set name [SpfName [lindex $rr 2]]
        if {![SpfDomainValid $name]} {continue}
        try {set addresses [SpfDns ctx $name $type]} trap {NSSMTPD SPF RESULT temperror} {} {
            SpfRemaining [dict get $ctx deadline]
            continue
        }
        foreach address [lrange $addresses 0 9] {
            if {[ns_ip match [lindex $address 2] $ip]} {lappend names $name; break}
        }
    }
    return $names
}

proc smtpd::SpfEvaluate {context domain} {
    upvar 1 $context ctx
    SpfRemaining [dict get $ctx deadline]
    if {$domain in [dict get $ctx active]} {SpfError permerror "recursive SPF policy"}
    dict lappend ctx active $domain
    try {
        set policies {}
        foreach rr [SpfDns ctx $domain TXT] {
            set text [lindex $rr 2]
            if {[regexp -nocase {^v=spf1( |$)} $text]} {lappend policies $text}
        }
        if {$policies eq ""} {return none}
        if {[llength $policies] != 1} {SpfError permerror "multiple SPF records"}
        lassign [SpfParse [lindex $policies 0]] mechanisms modifiers
        foreach mechanism $mechanisms {
            SpfRemaining [dict get $ctx deadline]
            lassign $mechanism name qualifier spec v4 v6
            set match 0
            if {$name in {a mx include exists ptr}} {SpfTerm ctx}
            set target $domain
            if {$spec ne "" && $name ni {ip4 ip6}} {set target [SpfMacro ctx $spec $domain]}
            set type [expr {[dict get $ctx family] == 4 ? "A" : "AAAA"}]
            set prefix [expr {$type eq "A" ? $v4 : $v6}]
            switch -- $name {
                all {set match 1}
                ip4 - ip6 {
                    if {[string index $name end] == [dict get $ctx family]} {set match [ns_ip match $spec [dict get $ctx ip]]}
                }
                include {
                    set result [SpfEvaluate ctx $target]
                    if {$result eq "none"} {SpfError permerror "included domain has no SPF policy"}
                    set match [expr {$result eq "pass"}]
                }
                exists {set match [expr {[SpfDns ctx $target A] ne ""}]}
                ptr {
                    foreach validated [SpfValidatedNames ctx] {
                        if {[SpfWithin $validated $target]} {set match 1; break}
                    }
                }
                a - mx {
                    set hosts [list $target]
                    if {$name eq "mx"} {
                        set records [SpfDns ctx $target MX]
                        if {[llength $records] > 10} {SpfError permerror "SPF MX lookup limit exceeded"}
                        set hosts {}
                        foreach rr [lsort -integer -index 3 $records] {
                            set host [lindex $rr 2]
                            if {$host ne "."} {lappend hosts $host}
                        }
                    }
                    foreach host $hosts {
                        set addresses [SpfDns ctx $host $type]
                        if {$name eq "mx" && [llength $addresses] > 10} {SpfError permerror "SPF MX address limit exceeded"}
                        foreach rr $addresses {
                            if {[ns_ip match [lindex $rr 2]/$prefix [dict get $ctx ip]]} {set match 1; break}
                        }
                        if {$match} {break}
                    }
                }
            }
            if {$match} {return [dict get {+ pass - fail ~ softfail ? neutral} $qualifier]}
        }
        if {[dict exists $modifiers redirect]} {
            SpfTerm ctx
            set target [SpfMacro ctx [dict get $modifiers redirect] $domain]
            set result [SpfEvaluate ctx $target]
            if {$result eq "none"} {SpfError permerror "redirected domain has no SPF policy"}
            return $result
        }
        return neutral
    } finally {
        dict set ctx active [lrange [dict get $ctx active] 0 end-1]
    }
}

# -*- Tcl -*-
# Optional authentication diagnostics. These do not make delivery decisions.
namespace eval smtpd {}

proc smtpd::AuthDns {name timeout} {
    ns_dns lookup -details -jointxt -timeout $timeout $name TXT
}

proc smtpd::AuthTags {text} {
    set tags {}
    foreach part [split $text {;}] {
        set part [string trim $part]
        if {$part eq ""} {continue}
        if {![regexp {^([A-Za-z][A-Za-z0-9_]*)[ \t]*=(.*)$} $part -> key value]
            || [dict exists $tags $key]} {
            ::error "malformed or duplicate tag"
        }
        dict set tags $key [string trim $value]
    }
    return $tags
}

proc smtpd::AuthDkimDetails {signatures} {
    set details [dict create dkim-signatures [llength $signatures]]
    if {$signatures eq ""} {
        dict set details dkim-status unsigned
        return $details
    }
    # Bound DNS work for untrusted headers: eight signatures, five seconds
    # shared across all key lookups. Presence of a key is not verification.
    set deadline [ns_time incr [ns_time get] 5]
    set cache {}
    set index 0
    foreach signature [lrange $signatures 0 7] {
        incr index
        set prefix dkim-$index
        dict set details $prefix-verification not-performed
        try {
            if {[string length $signature] > 16384} {::error "oversized signature"}
            set tags [AuthTags $signature]
            set domain [dict get $tags d]
            set selector [dict get $tags s]
            set name "$selector._domainkey.$domain"
            foreach part [list $domain $selector] {
                if {![regexp {^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$} $part]} {
                    ::error "invalid domain or selector"
                }
                foreach label [split $part .] {
                    if {[string length $label] > 63} {::error "oversized DNS label"}
                }
            }
            if {[string length $name] > 253} {::error "oversized key name"}
        } on error {message} {
            dict set details $prefix-key invalid-signature-tags
            continue
        }
        dict set details $prefix-domain $domain
        dict set details $prefix-selector $selector
        if {[dict exists $cache $name]} {
            dict set details $prefix-key [dict get $cache $name]
            continue
        }
        set remaining [ns_time diff $deadline [ns_time get]]
        set status lookup-error
        if {[namespace which -command ::ns_dns] eq ""} {
            set status dns-unavailable
        } elseif {[ns_time format $remaining] <= 0} {
            set status lookup-timeout
        } else {
            try {
                set response [AuthDns $name $remaining]
                set rcode [dict get $response rcode]
                if {[dict get $response truncated]} {
                    set status truncated-response
                } elseif {$rcode == 3} {
                    set status no-key
                } elseif {$rcode == 0} {
                    set records {}
                    set cname false
                    foreach rr [dict get $response answer] {
                        if {[lindex $rr 1] eq "TXT"} {lappend records [lindex $rr 2]}
                        if {[lindex $rr 1] eq "CNAME"} {set cname true}
                    }
                    switch -- [llength $records] {
                        0 {set status [expr {$cname ? "unresolved-cname" : "no-key"}]}
                        1 {
                            try {
                                set key [AuthTags [lindex $records 0]]
                            } on error {} {
                                set key {}
                            }
                            if {![dict exists $key p]
                                || ([dict exists $key v] && [dict get $key v] ne "DKIM1")} {
                                set status invalid-key-record
                            } elseif {[string trim [dict get $key p]] eq ""} {
                                set status revoked-key
                            } else {
                                set status key-present-not-verified
                            }
                        }
                        default {set status multiple-key-records}
                    }
                } else {
                    set status dns-rcode-$rcode
                }
            } trap {NS_TIMEOUT} {} {
                set status lookup-timeout
            } on error {message options} {
                set status lookup-error
            }
        }
        dict set cache $name $status
        dict set details $prefix-key $status
    }
    if {[llength $signatures] > 8} {dict set details dkim-limit exceeded}
    return $details
}

# Collect key availability, not cryptographic DKIM verification. The aggregate
# no-key finding requires every provided signature to have an absent key.
proc smtpd::dkimkeypolicy {context findingsVar} {
    upvar 1 $findingsVar findings
    if {[dict get $context phase] ne "data"} {
        ::error "DKIM key policy requires the DATA phase"
    }
    set received [ns_smtpd headers [dict get $context id]]
    set signatures {}
    foreach {name value} [ns_set array $received] {
        if {[string equal -nocase $name DKIM-Signature]} {lappend signatures $value}
    }
    set details [AuthDkimDetails $signatures]
    set findings [dict merge $findings $details]
    set count [dict get $details dkim-signatures]
    set absent [expr {$count > 0 && $count <= 8}]
    for {set index 1} {$index <= min($count, 8)} {incr index} {
        if {[dict get $details dkim-$index-key] ne "no-key"} {set absent false}
    }
    dict unset findings dkim-no-key
    if {$absent} {dict set findings dkim-no-key true}
    return continue
}

# Extract hostnames only; never resolve, fetch, or log recipient-bearing URLs.
proc smtpd::AuthLinkHost {url} {
    try {
        set parts [ns_parseurl [string trim $url]]
        # A host without proto is a protocol-relative URL. Relative paths
        # have no host and are ignored along with non-HTTP schemes.
        if {[dict exists $parts proto]
            && [string tolower [dict get $parts proto]] ni {http https}} {return ""}
        set host [string trimright [string tolower [dict get $parts host]] .]
        if {![regexp {^[a-z0-9.-]+$} $host]} {return ""}
        return $host
    } on error {} {return ""}
}

proc smtpd::AuthHtmlLinks {html} {
    set findings {}
    set href ""
    set label ""
    set count 0
    foreach item [ns_parsehtml $html] {
        lassign $item type raw parsed
        if {$type eq "text" && $href ne ""} {append label $raw}
        if {$type ne "tag"} {continue}
        set tag [string tolower [lindex $parsed 0]]
        if {$tag eq "a"} {
            incr count
            if {$count > 100} {dict set findings link-limit exceeded; break}
            set href ""
            set label ""
            dict for {key value} [lindex $parsed 1] {
                if {[string equal -nocase $key href]} {set href [ns_unquotehtml $value]}
            }
            set host [AuthLinkHost $href]
            if {$host eq ""} {set href ""; continue}
            # Inspect URL-valued query parameters, independent of vendor names.
            # Decode each value once; this is not a redirect traversal.
            set queryStart [string first ? $href]
            if {$queryStart >= 0} {
                set query [lindex [split [string range $href $queryStart+1 end] #] 0]
                foreach field [lrange [split $query &] 0 31] {
                    set equals [string first = $field]
                    if {$equals < 0} {continue}
                    try {
                        set target [AuthLinkHost [ns_urldecode [string range $field $equals+1 end]]]
                        if {$target ne "" && $target ne $host} {
                            dict set findings link-embedded-redirect [list $host $target]
                        }
                    } on error {} {continue}
                }
            }
        } elseif {$tag eq "/a" && $href ne ""} {
            set label [string trim [ns_unquotehtml $label]]
            set shown [AuthLinkHost $label]
            if {$shown eq "" && [regexp -nocase {^[a-z0-9-]+(?:\.[a-z0-9-]+)+\.?$} $label]} {
                set shown [string trimright [string tolower $label] .]
            }
            if {$shown ne "" && $shown ne $host} {
                dict set findings link-host-mismatch [list $shown $host]
            }
            set href ""
        }
    }
    return $findings
}

# Tcllib handles MIME transfer encodings and multipart boundaries. Keep this
# optional, like the DNS diagnostics, and explicitly report missing support.
proc smtpd::AuthLinkDetails {message} {
    if {[string length $message] > 262144} {return {link-status message-size-limit}}
    foreach command {ns_parsehtml ns_parseurl ns_unquotehtml ns_urldecode} {
        if {[namespace which -command ::$command] eq ""} {return {link-status parser-unavailable}}
    }
    try {package require mime} on error {} {return {link-status mime-unavailable}}
    set token ""
    set details {link-status no-html}
    try {
        # Tcllib's string input expects LF header separators. Normalize only
        # this inspection copy, never the original message sent to the relay.
        set token [mime::initialize -string [string map {\r\n \n} $message]]
        set pending [list $token]
        set count 0
        while {[llength $pending]} {
            incr count
            if {$count > 64} {dict set details link-status part-limit; break}
            set part [lindex $pending 0]
            set pending [lrange $pending 1 end]
            set properties [mime::getproperty $part]
            if {[dict exists $properties parts]} {
                lappend pending {*}[dict get $properties parts]
            } elseif {[string equal -nocase [dict get $properties content] text/html]} {
                dict set details link-status inspected
                set details [dict merge $details [AuthHtmlLinks [mime::getbody $part]]]
            }
        }
    } on error {} {
        dict set details link-status parse-error
    } finally {
        if {$token ne ""} {mime::finalize $token -subordinates all}
    }
    return $details
}

# Generate only new, unsigned fields. Never remove or replace received fields.
# Conservatively omit every proposed field mentioned in any signature's h=,
# including oversigned (not yet present) fields. Malformed signatures suppress
# all additions rather than guessing what they protect.
proc smtpd::AuthLinkHeaders {details received} {
    set protected [ns_set copy $received]
    set headers [ns_set create -nocase diagnostics]
    try {
        foreach {name signature} [ns_set array $received] {
            switch -nocase -- $name {
                DKIM-Signature -
                ARC-Message-Signature {}
                default {continue}
            }
            try {
                set tags [AuthTags $signature]
                foreach name [split [dict get $tags h] :] {
                    ns_set put $protected [string trim $name] {}
                }
            } on error {} {return $headers}
        }
        set findings {}
        foreach {key name reason} {
            link-host-mismatch Nssmtpd-Link-Host-Mismatch host-mismatch
            link-embedded-redirect Nssmtpd-Link-Embedded-Redirect embedded-redirect
        } {
            if {[dict exists $details $key]} {
                lappend findings $reason
                if {[ns_set find $protected $name] < 0} {
                    ns_set put $headers $name [join [dict get $details $key] { -> }]
                }
            }
        }
        if {$findings ne "" && [ns_set find $protected Nssmtpd-Link-Findings] < 0} {
            ns_set put $headers Nssmtpd-Link-Findings [join $findings {, }]
        }
        return $headers
    } on error {message options} {
        ns_set free $headers
        return -options $options $message
    } finally {
        ns_set free $protected
    }
}

# authdetailsproc callback: inspect the actual socket peer, never Received
# headers supplied by a sender. Replayed mail therefore describes the relay.
proc smtpd::authdetails {id} {
    set section ns/server/[ns_info server]/module/nssmtpd
    set addheaders [ns_config -bool $section authdetailheaders false]
    if {!$addheaders && ![ns_config -bool $section eventlogging false]} {return {}}
    set details [dict create action observed reason authentication-diagnostics \
                     spf-peer [ns_conn peeraddr] spf-helo [ns_smtpd gethelo $id]]
    if {[ns_smtpd getflag $id -1] & [ns_smtpd flag LOCAL]} {
        dict set details spf-result not-checked-local
        dict set details dkim-status not-checked-local
    } else {
        try {
            dict set details spf-result [smtpd::checkspf -ip [ns_conn peeraddr] \
                -sender [ns_smtpd getfrom $id] -helo [ns_smtpd gethelo $id]]
        } trap {NSSMTPD SPF DISABLED} {} {
            dict set details spf-result disabled
        } trap {NSSMTPD SPF DEPENDENCY} {} {
            dict set details spf-result unavailable
        } on error {message options} {
            dict set details spf-result evaluation-error
            dict set details spf-errorcode [dict get $options -errorcode]
        }
        set details [dict merge $details [AuthDkimDetails [ns_smtpd gethdrs $id DKIM-Signature]]]
    }
    set details [dict merge $details [AuthLinkDetails [lindex [ns_smtpd getbody $id] 0]]]
    smtpd::logevent $id authentication $details
    if {$addheaders} {
        return [AuthLinkHeaders $details [ns_smtpd headers $id]]
    }
    return {}
}

# Local variables:
#    mode: tcl
#    tcl-indent-level: 4
#    indent-tabs-mode: nil
# End:

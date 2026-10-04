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
    set deadline [expr {[clock milliseconds] + 5000}]
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
        set status lookup-error
        if {[namespace which -command ::ns_dns] eq ""} {
            set status dns-unavailable
        } elseif {[clock milliseconds] >= $deadline} {
            set status lookup-timeout
        } else {
            try {
                set response [AuthDns $name [expr {($deadline - [clock milliseconds]) / 1000.0}]]
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

# authdetailsproc callback: inspect the actual socket peer, never Received
# headers supplied by a sender. Replayed mail therefore describes the relay.
proc smtpd::authdetails {id} {
    if {![ns_config -bool ns/server/[ns_info server]/module/nssmtpd eventlogging false]} {return}
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
    smtpd::logevent $id authentication $details
}

# Local variables:
#    mode: tcl
#    tcl-indent-level: 4
#    indent-tabs-mode: nil
# End:

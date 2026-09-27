# Author: Vlad Seryakov vlad@crystalballinc.com
# Gustaf Neumann
#
# March 2006

namespace eval smtpd {
    variable version "Smtpd version 2.7"
}

# Shared by SMTP reception, ns_smtpd send, and ns_smtpd resolve.
# The resolver is a command prefix returning FINAL envelope recipients.
# Backend access and recursive alias policy belong to the configured proc.
proc smtpd::resolvealiases {resolver recipients maxrcpt} {
    set resolved {}
    set seen [dict create]
    foreach recipient $recipients {
        set targets [uplevel #0 [list {*}$resolver $recipient]]
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
proc smtpd::filealiases {format filename domains recipient} {
    if {$format ni {aliases virtual}} {
        ::error "alias file format must be aliases or virtual"
    }
    set domains [lmap domain $domains {string tolower $domain}]
    set domain [string tolower [lindex [split $recipient @] end]]
    if {$domain ni $domains} {return [list $recipient]}
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
    set budget 10000
    return [smtpd::ExpandFileAlias $format $map $domains $recipient {} budget]
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
    set key [expr {$format eq "aliases" ? $local : $address}]
    if {![dict exists $map $key] && $format eq "virtual"} {set key @$domain}
    if {![dict exists $map $key]} {return [list $recipient]}
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

proc smtpd::rcpt { id } {

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

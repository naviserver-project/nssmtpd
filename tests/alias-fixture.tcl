# Test-only callbacks. Loaded into every interpreter of the isolated server.
source [file join [ns_config alias-test source] nssmtpd-procs.tcl]
source [file join [ns_config alias-test source] tests alias-sink.tcl]

proc io_log_filter {severity timestamp message} {
    if {[string match {nssmtpd:*} $message]} {
        nsv_lappend io-test logs [list $severity $message]
    }
}

rename ::smtpd::ReadAliasFile ::smtpd::test_ReadAliasFile
proc ::smtpd::ReadAliasFile {format filename} {
    nsv_incr alias-test reads
    return [smtpd::test_ReadAliasFile $format $filename]
}

# Exercise the C boundary when a replacement Tcl helper breaks its contract.
rename ::smtpd::resolvealiases ::smtpd::test_resolvealiases
proc ::smtpd::resolvealiases {resolver recipients maxrcpt passthrough} {
    switch -- $recipients {
        helper-empty@example.test {return {}}
        helper-malformed@example.test {return "\{"}
    }
    return [::smtpd::test_resolvealiases $resolver $recipients $maxrcpt $passthrough]
}

proc alias_test_resolver {tag args} {
    if {$tag ne {prefix argument}} {error {command prefix was not preserved}}
    ns_parseargs {-recipient -rejectunknown} $args
    if {![info exists rejectunknown]} {
        set rejectunknown [ns_config ns/server/[ns_info server]/module/nssmtpd rejectunknownrecipients false]
    }
    if {$recipient eq "unknown@example.test" && $rejectunknown} {
        return -code error -errorcode {NSSMTPD ALIAS UNKNOWN} {unknown recipient}
    }
    nsv_incr alias-test calls
    switch -- $recipient {
        webmaster@example.test {return {one@remote.test two@remote.test one@remote.test}}
        mixed@example.test {return {one@remote.test two@other.test}}
        grow@example.test {return {one@remote.test two@remote.test}}
        missing@example.test {return {}}
        broken@example.test {error {backend unavailable}}
        invalid@example.test {return [list "bad@remote.test\r\nRCPT TO:<victim@remote.test>"]}
        empty@example.test {return [list {}]}
        malformed@example.test {return "\{"}
        many@example.test {return {a@remote.test b@remote.test c@remote.test d@remote.test}}
        default {return [list $recipient]}
    }
}

proc alias_test_rcpt {id} {
    set recipient [lindex [ns_smtpd getrcpt $id 0] 0]
    nsv_lappend alias-test policy $recipient
    switch -- $recipient {
        denied@example.test {
            ns_smtpd delrcpt $id 0
            ns_smtpd setreply $id "550 Policy rejected\r\n"
        }
        deleted@example.test {
            ns_smtpd delrcpt $id 0
        }
        mutate@example.test {
            ns_smtpd addrcpt $id added@remote.test [ns_smtpd flag VERIFIED]
            ns_smtpd delrcpt $id $recipient
        }
        grow@example.test {
            ns_smtpd addrcpt $id added1@remote.test [ns_smtpd flag VERIFIED]
            ns_smtpd addrcpt $id added2@remote.test [ns_smtpd flag VERIFIED]
            ns_smtpd setflag $id $recipient VERIFIED
        }
        default {
            ns_smtpd setflag $id 0 VERIFIED
            ns_smtpd setrcptdata $id 0 original-policy
        }
    }
}

proc alias_test_data {id} {
    set recipients {}
    foreach recipient [ns_smtpd getrcpt $id] {
        lappend recipients [lindex $recipient 0]
    }
    nsv_set alias-test body [lindex [ns_smtpd getbody $id] 0]
    nsv_set alias-test from [ns_smtpd getfrom $id]
    nsv_set alias-test recipients [ns_smtpd getrcpt $id]
    ns_smtpd setreply $id "250 [list $recipients]\r\n"
}

proc grey_test_policy {tag context} {
    if {$tag ne {prefix argument}} {error {policy prefix lost}}
    nsv_incr grey-test calls
    nsv_set grey-test context $context
    if {[nsv_get grey-test override result]} {
        if {$result eq "error"} {error {backend unavailable}}
        return $result
    }
    return [smtpd::greylist $context]
}

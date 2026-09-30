# Isolated configuration: no external relay, database, or fixed ports.
set root $::env(ALIAS_TEST_ROOT)
set nsroot $::env(ALIAS_TEST_NSROOT)
ns_section ns/parameters {
    ns_param home $::env(ALIAS_TEST_HOME)
    ns_param tcllibrary [file join $nsroot tcl]
    ns_param pidfile [file join $::env(ALIAS_TEST_HOME) nsd.pid]
}
# Both locations support older and newer ns_sendmail implementations.
foreach section {ns/parameters ns/sendmail} {
    ns_section $section {
        ns_param smtphost 127.0.0.1
        ns_param smtpport $::env(ALIAS_TEST_PORT)
        ns_param smtptimeout 3
        ns_param smtpauthmode ""
        ns_param smtpusestarttls false
        ns_param smtpencodingmode false
    }
}
ns_section ns/servers {
    ns_param test {Alias tests}
    if {$::env(ALIAS_TEST_MODE) eq "proxy"} {ns_param sink {STARTTLS test sink}}
}
ns_section ns/server/test {
    ns_param minthreads 2
    ns_param maxthreads 4
}
ns_section ns/server/test/tcl {
    ns_param initfile [file join $nsroot bin init.tcl]
    ns_param initcmds [list source [file join $root tests alias-fixture.tcl]]
}
ns_section ns/server/test/modules {
    ns_param nssmtpd [file join $root nssmtpd.so]
    ns_param nssock [file join $nsroot bin nssock.so]
}
ns_section ns/server/test/module/nssock {
    ns_param address 127.0.0.1
    ns_param port 0
}
ns_section ns/server/test/module/nssmtpd {
    if {$::env(ALIAS_TEST_MODE) in {events eventsoff}} {
        ns_param eventlogfile [file join $::env(ALIAS_TEST_HOME) events.log]
        if {$::env(ALIAS_TEST_MODE) eq "events"} {ns_param eventlogging true}
        ns_param eventlogroll false
        ns_param eventlogrollonsignal true
        ns_param greylistdelay 1
        ns_param greylistretrywindow 60
        ns_param greylistlifetime 120
        ns_param recipientpolicyproc smtpd::greylist
        ns_param rejectunknownrecipients true
    }
    if {$::env(ALIAS_TEST_MODE) eq "io"} {
        ns_param certificate [file join $::env(ALIAS_TEST_HOME) cert.pem]
        ns_param key [file join $::env(ALIAS_TEST_HOME) key.pem]
        ns_param eventlogging true
        ns_param eventlogfile [file join $::env(ALIAS_TEST_HOME) events.log]
        ns_param eventlogroll false
    }
    ns_param address 127.0.0.1
    ns_param port $::env(ALIAS_TEST_PORT)
    ns_param readtimeout 3
    ns_param writetimeout 3
    ns_param maxrcpt 3
    ns_param relaydomains example.test
    ns_param localdomains [expr {$::env(ALIAS_TEST_MODE) in {events eventsoff io untrusted policyexternal policyoff policyempty greyexternal greyoff greyempty} ? "" : "127.0.0.1"}]
    ns_param rcptproc [expr {$::env(ALIAS_TEST_MODE) in {events eventsoff} ? "event_test_rcpt" : ([string match policy* $::env(ALIAS_TEST_MODE)] || [string match grey* $::env(ALIAS_TEST_MODE)]) ? "smtpd::rcpt" : "alias_test_rcpt"}]
    ns_param dataproc alias_test_data
    if {$::env(ALIAS_TEST_MODE) in {events eventsoff enabled untrusted proxy greyexternal greytrusted greyoff greyempty}} {
        ns_param aliasproc {alias_test_resolver {prefix argument}}
    } elseif {$::env(ALIAS_TEST_MODE) in {files filevirtual policyexternal policytrusted policyoff policyempty}} {
        set format [expr {$::env(ALIAS_TEST_MODE) eq "files" ? "aliases" : "virtual"}]
        if {$::env(ALIAS_TEST_MODE) in {files policyexternal}} {
            ns_param aliasformat $format
            ns_param aliasfile [file join $::env(ALIAS_TEST_HOME) aliases]
            ns_param aliasdomains {example.test}
            ns_param aliasproc smtpd::resolvefilealiases
        } else {
            ns_param aliasproc [list smtpd::resolvefilealiases -format $format -file \
                                   [file join $::env(ALIAS_TEST_HOME) aliases] -domains {example.test}]
        }
    } elseif {$::env(ALIAS_TEST_MODE) eq "empty"} {
        ns_param aliasproc ""
    }
    if {$::env(ALIAS_TEST_MODE) in {policyexternal policytrusted}} {
        ns_param rejectunknownrecipients true
    } elseif {$::env(ALIAS_TEST_MODE) eq "policyempty"} {
        ns_param rejectunknownrecipients false
    }
    if {[string match grey* $::env(ALIAS_TEST_MODE)]} {
        ns_param rejectunknownrecipients true
        if {$::env(ALIAS_TEST_MODE) in {greyexternal greytrusted}} {
            ns_param recipientpolicyproc {grey_test_policy {prefix argument}}
        } elseif {$::env(ALIAS_TEST_MODE) eq "greyempty"} {
            ns_param recipientpolicyproc ""
        }
    }
    if {$::env(ALIAS_TEST_MODE) eq "proxy"} {
        ns_param relay plain://127.0.0.1:$::env(ALIAS_TEST_RELAY)
        ns_param eventlogging true
        ns_param eventlogfile [file join $::env(ALIAS_TEST_HOME) events.log]
        ns_param eventlogroll false
    }
}
ns_section alias-test {
    ns_param source $root
}

if {$::env(ALIAS_TEST_MODE) eq "proxy"} {
    ns_section ns/server/sink/tcl {
        ns_param initfile [file join $nsroot bin init.tcl]
        ns_param initcmds [list source [file join $root tests alias-fixture.tcl]]
    }
    ns_section ns/server/sink/modules {
        ns_param nssmtpd [file join $root nssmtpd.so]
    }
    ns_section ns/server/sink/module/nssmtpd {
        ns_param eventlogging true
        ns_param eventlogfile [file join $::env(ALIAS_TEST_HOME) sink-events.log]
        ns_param eventlogroll false
        ns_param address 127.0.0.1
        ns_param port $::env(ALIAS_TEST_RELAY)
        ns_param localdomains 127.0.0.1
        ns_param certificate [file join $::env(ALIAS_TEST_HOME) cert.pem]
        ns_param key [file join $::env(ALIAS_TEST_HOME) key.pem]
        ns_param rcptproc alias_sink_rcpt
        ns_param dataproc alias_sink_data
    }
}

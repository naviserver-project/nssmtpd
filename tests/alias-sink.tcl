# -*- Tcl -*-
# Test-only SMTP sink. Connchan callbacks run in other interpreters, so all
# connection state is shared through nsv.
proc alias_sink_accept {channel {stall false}} {
    nsv_set alias-sink $channel [dict create input "" recipients {} body "" data 0 stall $stall]
    ns_connchan write $channel "220 alias-test SMTP\r\n"
    ns_connchan callback -timeout 5s $channel [list alias_sink_read $channel] rx
    return 1
}
proc alias_sink_read {channel reason} {
    if {$reason ne "r"} {
        nsv_unset -nocomplain alias-sink $channel
        return 0
    }
    try {
        set bytes [ns_connchan read $channel]
        if {$bytes eq ""} {
            nsv_unset -nocomplain alias-sink $channel
            return 0
        }
        set state [nsv_get alias-sink $channel]
        dict append state input $bytes
        while {[set end [string first "\r\n" [dict get $state input]]] >= 0} {
            set line [string range [dict get $state input] 0 $end-1]
            dict set state input [string range [dict get $state input] $end+2 end]
            if {[dict get $state data]} {
                if {$line eq "."} {
                    nsv_lappend alias-sink messages [list [dict get $state recipients] [dict get $state body]]
                    dict set state data 0
                    ns_connchan write $channel "250 OK\r\n"
                } else {dict append state body $line "\r\n"}
                continue
            }
            switch -glob -- [string toupper $line] {
                {RCPT TO:*} {
                    dict lappend state recipients [string trim [string range $line 8 end] { <>}]
                    ns_connchan write $channel "250 OK\r\n"
                }
                DATA* {
                    dict set state data 1
                    ns_connchan write $channel "354 Send data\r\n"
                    if {[dict get $state stall]} {
                        nsv_set alias-sink $channel $state
                        return 2
                    }
                }
                QUIT* {
                    ns_connchan write $channel "221 Bye\r\n"
                    nsv_unset alias-sink $channel
                    return 0
                }
                default {ns_connchan write $channel "250 OK\r\n"}
            }
        }
        nsv_set alias-sink $channel $state
        return 1
    } on error {message options} {
        nsv_set alias-sink error [dict get $options -errorinfo]
        nsv_unset -nocomplain alias-sink $channel
        return 0
    }
}

# Native nssmtpd supplies STARTTLS, which connchan cannot upgrade in place.
# Record messages in a file shared with the main test virtual server.
proc alias_sink_rcpt {id} {ns_smtpd setflag $id 0 VERIFIED}
proc alias_sink_data {id} {
    set recipients {}
    foreach recipient [ns_smtpd getrcpt $id] {lappend recipients [lindex $recipient 0]}
    set channel [open [file join $::env(ALIAS_TEST_HOME) sink-messages.list] a]
    fconfigure $channel -translation lf -encoding utf-8
    try {
        puts $channel [list [list $recipients [lindex [ns_smtpd getbody $id] 0]]]
    } finally {close $channel}
}

# Receive-error fixtures, running inside NaviServer rather than an external server.
proc io_sink_accept {mode channel} {
    nsv_set io-test accepted $channel
    if {$mode eq "eof"} {
        ns_connchan close $channel
    } elseif {$mode eq "silent"} {
        # The test closes this channel after the client's bounded timeout.
    } elseif {$mode eq "partial"} {
        ns_connchan write $channel "220 incomplete"
        ns_connchan close $channel
    } elseif {$mode eq "long"} {
        ns_connchan write $channel "220 [string repeat X 4096]\r\n"
    } elseif {$mode eq "write-timeout"} {
        alias_sink_accept $channel true
    } elseif {$mode eq "helo-eof"} {
        ns_connchan write $channel "220 test SMTP\r\n"
        ns_connchan callback -timeout 5s $channel [list io_sink_close $channel] rx
    } elseif {$mode eq "delayed"} {
        ns_after 1 [list alias_sink_accept $channel]
    }
    return 1
}
proc io_sink_close {channel reason} {
    if {$reason eq "r"} {ns_connchan read $channel}
    return 0
}

# Local variables:
#    mode: tcl
#    tcl-indent-level: 4
#    indent-tabs-mode: nil
# End:

#!/usr/bin/env tclsh
# -*- Tcl -*-
# SMTP sinks run inside NaviServer: ns_connchan or native nssmtpd STARTTLS.
package require Tcl 8.6
namespace eval alias_runner {variable output ""; variable done ""}
namespace eval alias_runner {
    variable totals {Total 0 Passed 0 Skipped 0 Failed 0}
    variable summaries 0
    variable skippedBecause {}
}

proc alias_runner::readOutput {pipe} {
    variable output
    variable done
    append output [read $pipe]
    if {[eof $pipe]} {
        fileevent $pipe readable {}
        set done eof
    }
}
proc alias_runner::timeout {pipe} {
    variable done
    foreach child [pid $pipe] {catch {exec kill -KILL $child}}
    set done timeout
}
proc alias_runner::run {nsroot root mode} {
    variable output
    variable done
    variable testArgs
    variable totals
    variable summaries
    variable skippedBecause
    set output ""
    set done ""
    set placeholder [file tempfile temporary]
    close $placeholder
    set home ${temporary}.d
    file mkdir $home
    file delete $temporary
    set pipe ""
    set timer ""
    set savedDirectory [pwd]
    try {
        # Reserve distinct ephemeral module ports, then release for nsd.
        # The plain SMTP sink allocates its own port with ns_connchan.
        set probes {}
        foreach name {PORT RELAY} {
            set probe [socket -server {apply {{channel args} {close $channel}}} -myaddr 127.0.0.1 0]
            lappend probes $probe
            set ::env(ALIAS_TEST_$name) [lindex [fconfigure $probe -sockname] 2]
        }
        foreach probe $probes {close $probe}
        if {$mode in {proxy io headers}} {
            exec openssl req -x509 -newkey rsa:2048 -nodes \
                -keyout [file join $home key.pem] -out [file join $home cert.pem] \
                -days 1 -subj /CN=localhost >[file join $home openssl.log] 2>@1
        }
        foreach {key value} [list ROOT $root NSROOT $nsroot HOME $home MODE $mode] {
            set ::env(ALIAS_TEST_$key) $value
        }
        set testfile [dict get {headers headers.test events events.test eventsoff events.test greyexternal greylisting.test greytrusted greylisting.test greyoff greylisting.test greyempty greylisting.test policyexternal recipient-policy.test policytrusted recipient-policy.test policyoff recipient-policy.test policyempty recipient-policy.test io io-errors.test basic basic.test files aliases-files.test filevirtual aliases-files.test proxy aliases-proxy.test disabled aliases.test empty aliases.test enabled aliases.test untrusted aliases.test} $mode]
        set command [list [file join $nsroot bin nsd] -c -d -t \
                         [file join $root tests alias-config.tcl] [file join $root tests $testfile] {*}$testArgs]
        cd $home
        set pipe [open [list | {*}$command 2>@1] r]
        cd $savedDirectory
        fconfigure $pipe -blocking 0
        fileevent $pipe readable [list alias_runner::readOutput $pipe]
        set timer [after 45000 [list alias_runner::timeout $pipe]]
        vwait ::alias_runner::done
        after cancel $timer
        if {$done ne "eof"} {error "NaviServer timed out:\n$output"}
        fconfigure $pipe -blocking 1
        set status [catch {close $pipe} detail]
        set pipe ""
        puts "$mode:"
        set skipSummary false
        foreach line [split $output \n] {
            # Preserve tcltest's constraint summary and accumulate its counts.
            if {$line eq "Number of tests skipped for each constraint:"} {
                set skipSummary true
                puts $line
                continue
            }
            if {$skipSummary} {
                if {[regexp {^\t([0-9]+)\t(.+)$} $line -> count constraint]} {
                    dict incr skippedBecause $constraint $count
                    puts $line
                    continue
                }
                set skipSummary false
            }
            if {[string match *Total* $line] || [string match ALIAS_TEST_FAILURES=* $line]} {puts $line}
            if {[regexp {^(\S+):\s+Total\s+(\d+)\s+Passed\s+(\d+)\s+Skipped\s+(\d+)\s+Failed\s+(\d+)\s*$} $line -> file total passed skipped failed]
                && $file eq $testfile} {
                foreach key {Total Passed Skipped Failed} value [list $total $passed $skipped $failed] {
                    dict incr totals $key $value
                }
                incr summaries
            }
        }
        if {$mode eq "greyexternal" && $status == 0} {
            # The startup fixture must have been atomically replaced by the
            # real ns_atshutdown callback before the server process exits.
            set f [open [file join $home logs greylist.state] r]
            try {set snapshot [read $f]} finally {close $f}
            if {[dict get $snapshot version] != 1 || [dict exists $snapshot startupfixture]} {
                error "Greylist shutdown callback did not replace the startup snapshot:\n$output"
            }
        }
        if {$status != 0 || [string first ALIAS_TEST_FAILURES=0 $output] < 0} {
            error "NaviServer tests failed: $detail\n$output"
        }
    } finally {
        cd $savedDirectory
        if {$timer ne ""} {after cancel $timer}
        if {$pipe ne ""} {
            foreach child [pid $pipe] {catch {exec kill -KILL $child}}
            catch {close $pipe}
        }
        file delete -force $home
    }
}
set nsroot /usr/local/ns
if {[llength $argv] >= 2 && [lindex $argv 0] eq "--naviserver"} {
    set nsroot [lindex $argv 1]
    set argv [lrange $argv 2 end]
} elseif {[lindex $argv 0] eq "--naviserver"} {
    puts stderr "Usage: tclsh [file tail [info script]] ?--naviserver /usr/local/ns? ?tcltest options?"
    exit 2
}
set alias_runner::testArgs $argv
set root [file dirname [file dirname [file normalize [info script]]]]
set modes {headers events eventsoff basic disabled empty enabled untrusted proxy files filevirtual io policyexternal policytrusted policyoff policyempty greyexternal greytrusted greyoff greyempty}
try {
    foreach mode $modes {
        alias_runner::run [file normalize $nsroot] $root $mode
    }
} finally {
    puts "Aggregate ($alias_runner::summaries/[llength $modes] configuration summaries):"
    puts [format "Total\t%d\tPassed\t%d\tSkipped\t%d\tFailed\t%d" \
              {*}[dict values $alias_runner::totals]]
    if {[dict size $alias_runner::skippedBecause] > 0} {
        puts "Number of tests skipped for each constraint:"
        foreach constraint [lsort [dict keys $alias_runner::skippedBecause]] {
            puts "\t[dict get $alias_runner::skippedBecause $constraint]\t$constraint"
        }
    }
}
puts "All basic mail, alias and outgoing SMTP envelope tests passed."

# Local variables:
#    mode: tcl
#    tcl-indent-level: 4
#    indent-tabs-mode: nil
# End:

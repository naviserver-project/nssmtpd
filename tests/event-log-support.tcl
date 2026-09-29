# Test reader for the fixed access-log fields; no Tcl evaluation of log data.
proc event_parse_line {line} {
    lassign [split $line " "] date zone thread code event peer session transaction server sender recipient action reason targets
    foreach name {server sender recipient action reason targets} {
        if {[set $name] eq "-"} {set $name ""}
    }
    set targets [expr {$targets eq "" ? {} : [split $targets ,]}]
    return [dict create server $server session $session transaction $transaction event $event \
        sender $sender peer [string range $peer 1 end-1] details \
        [dict create action $action reason $reason recipient $recipient targets $targets code $code]]
}

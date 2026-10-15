smtpd::quarantineinit
set metadata [smtpd::quarantine show [lindex $argv 0]]
if {[dict get $metadata state] ne "held" || [dict get $metadata decision findings spf-fail] ne "true"
    || [string first "Subject:" [smtpd::quarantine message [lindex $argv 0]]] < 0} {error "quarantine did not survive restart"}
puts QUARANTINE_RESTART_OK
ns_shutdown
vwait forever

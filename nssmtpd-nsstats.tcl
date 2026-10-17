# Publish the reusable admin views independently of nsstats initialization.
# No nsstats code is loaded until an authorized page request includes the ADP.
namespace eval ::smtpd {}

proc ::smtpd::registerStatsPages {} {
    variable statsPageDirectory
    set directory $statsPageDirectory
    set pages {}
    foreach {id label title file} {
        log.smtpsent {SMTP sent log} {SMTP Sent Logfile Analysis} nsstats-sent.adp
        log.smtpevents {SMTP events} {SMTP Event Logfile Analysis} nsstats-events.adp
    } {
        dict set pages $id [dict create label $label title $title group logs scope source \
            requires ::ns_smtpd adp [file join $directory $file]]
    }
    nsv_set nsstats:plugins nssmtpd $pages
}
set ::smtpd::statsPageDirectory [file join [file dirname [info script]] lib]
::smtpd::registerStatsPages

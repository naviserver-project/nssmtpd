# Persistent DATA-policy quarantine. Metadata is a Tcl dictionary, never code.
namespace eval ::smtpd {}

# Initialize the private spool and one server-local lock before worker threads.
# Custom initproc callbacks must call this when quarantine is enabled.
proc smtpd::quarantineinit {} {
    if {![nsv_exists smtpd-quarantine mutex]} {
        nsv_set smtpd-quarantine mutex [ns_mutex create smtpd-quarantine]
    }
    set section ns/server/[ns_info server]/module/nssmtpd
    if {![ns_config -bool $section quarantinePolicyRejects false]} {return}
    set config [smtpd::QuarantineConfig]
    set directory [dict get $config directory]
    if {![file exists $directory]} {
        set missing {}
        set ancestor $directory
        while {![file exists $ancestor]} {
            lappend missing $ancestor
            set ancestor [file dirname $ancestor]
        }
        foreach path [lreverse $missing] {
            file mkdir $path
            file attributes $path -permissions 0700
            ns_smtpd filesync $path
            ns_smtpd filesync [file dirname $path]
        }
    }
    if {[file type $directory] ne "directory"
        || ([file attributes $directory -permissions] & 0077) != 0} {
        ::error "quarantineDirectory '$directory' must be a private directory (0700)"
    }
    ns_smtpd filesync $directory
    if {![nsv_exists smtpd-quarantine scheduler]} {
        nsv_set smtpd-quarantine scheduler [ns_schedule_proc 3600 smtpd::QuarantineCleanupScheduled]
    }
}

proc smtpd::QuarantineConfig {} {
    set section ns/server/[ns_info server]/module/nssmtpd
    set directory [ns_config $section quarantineDirectory {}]
    if {[file pathtype $directory] ne "absolute"} {
        ::error "quarantineDirectory must name an absolute persistent directory"
    }
    set retention [ns_baseunit -time [ns_config $section quarantineRetention 7d]]
    set maxBytes [ns_baseunit -size [ns_config $section quarantineMaxBytes 1GiB]]
    set maxMessages [ns_config -int -min 1 $section quarantineMaxMessages 10000]
    if {$retention <= 0 || $maxBytes <= 0} {::error "quarantine limits must be positive"}
    return [dict create directory $directory retention $retention maxBytes $maxBytes maxMessages $maxMessages]
}

proc smtpd::QuarantinePath {id} {
    if {![regexp {^[0-9a-f]{32}$} $id]} {::error "invalid quarantine id"}
    set path [file join [dict get [smtpd::QuarantineConfig] directory] $id]
    if {[file type $path] ne "directory"} {::error "invalid quarantine directory '$path'"}
    return $path
}

# Write, close and sync a temporary file before atomic replacement. Sync the
# directory as well; a successful return is the durability boundary for SMTP.
proc smtpd::QuarantineWrite {path data binary} {
    set channel [file tempfile temporary ${path}.tmp-]
    try {
        file attributes $temporary -permissions 0600
        if {$binary} {
            fconfigure $channel -translation binary -encoding binary
        } else {
            fconfigure $channel -translation lf -encoding utf-8
        }
        puts -nonewline $channel $data
        close $channel
        set channel ""
        ns_smtpd filesync $temporary
        file rename -force $temporary $path
        ns_smtpd filesync [file dirname $path]
    } finally {
        if {$channel ne ""} {catch {close $channel}}
        if {[file exists $temporary]} {file delete $temporary}
    }
}

proc smtpd::QuarantineRead {id} {
    set path [file join [smtpd::QuarantinePath $id] metadata.tcl]
    if {[file type $path] ne "file" || [file size $path] > 1048576} {::error "invalid quarantine metadata '$path'"}
    set channel [open $path r]
    try {
        fconfigure $channel -encoding utf-8 -translation lf
        set metadata [read $channel]
    } finally {close $channel}
    if {[dict get $metadata schemaVersion] != 1 || [dict get $metadata id] ne $id
        || [dict get $metadata server] ne [ns_info server]} {::error "quarantine metadata identity mismatch"}
    return $metadata
}

proc smtpd::QuarantineSave {metadata action} {
    dict set metadata updatedAt [clock seconds]
    dict lappend metadata audit [dict create at [clock seconds] action $action thread [ns_thread name]]
    if {[string bytelength $metadata] > 1048576} {::error "quarantine metadata exceeds 1MiB"}
    smtpd::QuarantineWrite [file join [smtpd::QuarantinePath [dict get $metadata id]] metadata.tcl] $metadata false
    ns_log Notice "nssmtpd quarantine: $action id=[dict get $metadata id] state=[dict get $metadata state]"
    return $metadata
}

proc smtpd::QuarantineIds {} {
    set directory [dict get [smtpd::QuarantineConfig] directory]
    set ids {}
    foreach path [glob -nocomplain -directory $directory *] {
        if {[regexp {^[0-9a-f]{32}$} [file tail $path]] && [file type $path] eq "directory"} {
            lappend ids [file tail $path]
        }
    }
    return [lsort $ids]
}

# Caller holds the lock. Never expire deliveries with unresolved outcomes.
proc smtpd::QuarantineCleanup {} {
    set cutoff [expr {[clock seconds] - [dict get [smtpd::QuarantineConfig] retention]}]
    set removed {}
    foreach id [smtpd::QuarantineIds] {
        set metadata [smtpd::QuarantineRead $id]
        if {[dict get $metadata createdAt] < $cutoff && [dict get $metadata state] in {held released}} {
            smtpd::QuarantineDelete $id expired
            lappend removed $id
        }
    }
    return $removed
}

proc smtpd::QuarantineCleanupScheduled {} {
    if {[catch {smtpd::quarantine cleanup} message]} {
        ns_log Warning "nssmtpd quarantine cleanup failed: $message"
    }
}

proc smtpd::QuarantineDelete {id action} {
    set path [smtpd::QuarantinePath $id]
    file delete -force $path
    ns_smtpd filesync [file dirname $path]
    ns_log Notice "nssmtpd quarantine: $action id=$id"
}

# Save the unstuffed binary RFC message and original policy context. Publish the
# complete directory with one rename, then sync its parent before returning 250.
proc smtpd::QuarantineStore {session context decision} {
    if {![nsv_exists smtpd-quarantine mutex]} {::error "quarantine has not been initialized"}
    ns_mutex eval [nsv_get smtpd-quarantine mutex] {
        set config [smtpd::QuarantineConfig]
        set directory [dict get $config directory]
        smtpd::QuarantineCleanup
        set ids [smtpd::QuarantineIds]
        set message [ns_smtpd getmessage $session]
        set id [ns_crypto::randombytes -encoding hex 16]
        set now [clock seconds]
        set progress {}
        foreach recipient [dict get $context recipients] {
            dict set progress $recipient pending
        }
        if {[dict size $progress] == 0} {::error "quarantine requires recipients"}
        set metadata [dict create schemaVersion 1 id $id server [ns_info server] \
            createdAt $now updatedAt $now process [list [pid] [ns_info boottime]] state held bytes [string length $message] \
            context $context decision $decision recipients $progress audit {}]
        set metadataBytes [string bytelength $metadata]
        if {$metadataBytes > 1048576} {::error "quarantine metadata exceeds 1MiB"}
        set used 0
        foreach existing $ids {
            foreach file [glob -nocomplain -directory [smtpd::QuarantinePath $existing] *] {
                incr used [file size $file]
            }
        }
        # Reserve space for metadata updates during release as well.
        if {[llength $ids] >= [dict get $config maxMessages]
            || $used + [string length $message] + 2*$metadataBytes + 4096 > [dict get $config maxBytes]} {
            ::error "quarantine capacity exceeded in '$directory'"
        }
        set pending [file join $directory .pending-$id]
        set published [file join $directory $id]
        file mkdir $pending
        file attributes $pending -permissions 0700
        try {
            smtpd::QuarantineWrite [file join $pending message.eml] $message true
            smtpd::QuarantineWrite [file join $pending metadata.tcl] $metadata false
            file rename $pending $published
            ns_smtpd filesync $directory
        } on error {message options} {
            # A published entry is kept if the final directory sync fails:
            # acceptance is not acknowledged, but evidence must not be lost.
            if {[file exists $pending]} {file delete -force $pending}
            return -options $options $message
        }
        ns_log Notice "nssmtpd quarantine: stored id=$id session=$session"
        return $id
    }
}

# Administrative interface for nscp. All IDs are opaque; no user-supplied paths
# or scripts are evaluated. SMTP release is deliberately outside the spool lock.
proc smtpd::quarantine {command args} {
    if {![nsv_exists smtpd-quarantine mutex]} {::error "quarantine has not been initialized"}
    if {$command eq "release"} {
        if {[llength $args] != 1} {::error "usage: smtpd::quarantine release id"}
        return [smtpd::QuarantineRelease [lindex $args 0]]
    }
    ns_mutex eval [nsv_get smtpd-quarantine mutex] {
        switch -- $command {
            status {
                if {[llength $args]} {::error "usage: smtpd::quarantine status"}
                set config [smtpd::QuarantineConfig]
                set bytes 0
                set counts {}
                foreach id [smtpd::QuarantineIds] {
                    set metadata [smtpd::QuarantineRead $id]
                    dict incr counts [dict get $metadata state]
                    foreach path [glob -directory [smtpd::QuarantinePath $id] *] {incr bytes [file size $path]}
                }
                return [dict merge $config [dict create enabled [ns_config -bool ns/server/[ns_info server]/module/nssmtpd quarantinePolicyRejects false] messages [llength [smtpd::QuarantineIds]] bytes $bytes states $counts]]
            }
            list {
                ns_parseargs {{-offset 0} {-limit 50}} $args
                if {![string is integer -strict $offset] || ![string is integer -strict $limit] || $offset < 0 || $limit < 1 || $limit > 1000} {::error "invalid quarantine page limits"}
                # Sort before slicing pages. IDs are random; updatedAt changes
                # on release and must not replace the original receipt time.
                set ordered {}
                foreach id [smtpd::QuarantineIds] {
                    set metadata [smtpd::QuarantineRead $id]
                    lappend ordered [list [dict get $metadata createdAt] $id $metadata]
                }
                # QuarantineIds supplies a stable ID order for equal times.
                set ordered [lsort -integer -decreasing -index 0 $ordered]
                set entries {}
                foreach item [lrange $ordered $offset [expr {$offset+$limit-1}]] {
                    lassign $item createdAt id metadata
                    lappend entries [dict create id $id createdAt [dict get $metadata createdAt] \
                        state [dict get $metadata state] bytes [dict get $metadata bytes] \
                        sender [dict get $metadata context sender] \
                        recipients [dict get $metadata recipients] decision [dict get $metadata decision]]
                }
                return [dict create entries $entries total [llength $ordered] nextOffset [expr {$offset+[llength $entries]}] \
                    more [expr {$offset+[llength $entries] < [llength $ordered]}]]
            }
            show - message {
                if {[llength $args] != 1} {::error "usage: smtpd::quarantine $command id"}
                set id [lindex $args 0]
                if {$command eq "show"} {
                    return [dict merge [smtpd::QuarantineRead $id] \
                        [dict create messagePath [file join [smtpd::QuarantinePath $id] message.eml]]]
                }
                set path [file join [smtpd::QuarantinePath $id] message.eml]
                if {[file type $path] ne "file"} {::error "invalid quarantine message '$path'"}
                set channel [open $path rb]
                try {return [read $channel]} finally {close $channel}
            }
            delete - recover {
                if {[llength $args] != 1} {::error "usage: smtpd::quarantine $command id"}
                set id [lindex $args 0]
                set metadata [smtpd::QuarantineRead $id]
                if {$command eq "delete"} {
                    if {[dict get $metadata state] eq "releasing"} {::error "delivery is active or interrupted; inspect and recover first"}
                    smtpd::QuarantineDelete $id deleted
                    return
                }
                if {[dict get $metadata state] ne "releasing"} {::error "only interrupted releases need recovery"}
                # Recover only across process lifetimes. Never unlock a live send.
                if {[dict get $metadata releaseInstance] eq [list [pid] [ns_info boottime]]} {
                    ::error "release belongs to the current process; wait for it to finish"
                }
                dict for {recipient state} [dict get $metadata recipients] {
                    if {$state eq "sending"} {dict set metadata recipients $recipient uncertain}
                }
                dict set metadata state uncertain
                return [smtpd::QuarantineSave $metadata recovered]
            }
            retry {
                if {[llength $args] != 3 || [lindex $args 2] ne "-confirm"} {
                    ::error "usage: smtpd::quarantine retry id recipient -confirm (may duplicate delivery)"
                }
                lassign $args id recipient
                set metadata [smtpd::QuarantineRead $id]
                if {[dict get $metadata state] eq "releasing" || [dict get $metadata recipients $recipient] ne "uncertain"} {
                    ::error "only an uncertain, inactive recipient may be retried"
                }
                dict set metadata recipients $recipient pending
                dict set metadata state [expr {"uncertain" in [dict values [dict get $metadata recipients]] ? "uncertain" : "held"}]
                return [smtpd::QuarantineSave $metadata retry-confirmed]
            }
            cleanup {
                if {[llength $args]} {::error "usage: smtpd::quarantine cleanup"}
                return [smtpd::QuarantineCleanup]
            }
            default {::error "unknown quarantine command: use status, list, show, message, release, recover, retry, delete or cleanup"}
        }
    }
}

# Claim durably, then send one saved recipient at a time. A persisted 'sending'
# marker is never retried automatically: SMTP acceptance and local persistence
# cannot form one transaction, so interrupted delivery may have succeeded.
proc smtpd::QuarantineRelease {id} {
    set mutex [nsv_get smtpd-quarantine mutex]
    ns_mutex eval $mutex {
        set metadata [smtpd::QuarantineRead $id]
        if {[dict get $metadata state] ni {held uncertain}} {::error "quarantine entry is not available for release"}
        set path [file join [smtpd::QuarantinePath $id] message.eml]
        if {[file type $path] ne "file"} {::error "invalid quarantine message '$path'"}
        set channel [open $path rb]
        try {set message [read $channel]} finally {close $channel}
        dict set metadata state releasing
        dict set metadata releaseInstance [list [pid] [ns_info boottime]]
        set metadata [smtpd::QuarantineSave $metadata release-started]
    }
    try {
        dict for {recipient state} [dict get $metadata recipients] {
            if {$state ne "pending"} {continue}
            ns_mutex eval $mutex {
                dict set metadata recipients $recipient sending
                set metadata [smtpd::QuarantineSave $metadata delivery-started]
            }
            set sender [dict get $metadata context sender]
            if {$sender eq "<>"} {set sender ""}
            if {[catch {ns_smtpd sendresolved $sender [list $recipient] message} detail]} {
                dict set metadata recipients $recipient uncertain
                dict set metadata deliveryErrors $recipient $detail
            } else {
                dict set metadata recipients $recipient delivered
            }
            ns_mutex eval $mutex {set metadata [smtpd::QuarantineSave $metadata delivery-finished]}
        }
        dict set metadata state [expr {"uncertain" in [dict values [dict get $metadata recipients]] ? "uncertain" : "released"}]
        ns_mutex eval $mutex {set metadata [smtpd::QuarantineSave $metadata release-finished]}
        return $metadata
    } on error {message options} {
        # Leave the durable releasing/sending markers intact for inspection.
        ns_log Error "nssmtpd quarantine: interrupted release id=$id: $message"
        return -options $options $message
    }
}

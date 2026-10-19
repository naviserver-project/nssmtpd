namespace eval ::smtpd::mcp {}

# Read-only, bounded SMTP log inspection. Paths come from the current server's
# loaded nssmtpd module configuration; callers never supply filesystem paths.
if {![nsf::object::exists ::smtpd::mcp::SmtpLogTool]} {
nx::Class create ::smtpd::mcp::SmtpLogTool -superclass ::nsmcp::Tool {
    :property {name smtp_logs}
    :property {adminSummary {Inspect recent SMTP send results and session events.}}
    :property {adminExample {Use smtp_logs with log event for the last 15 minutes. Show SMTP deferrals, rejections, TLS failures and transaction outcomes; include coverage.}}
    :property {permission diagnostics.logs.read}
    :property authorizer:required
    :property redactor:required
    :property peerRedactor:required
    :property {maxReadBytes:integer 1048576}
    :property {maxLineBytes:integer 16384}
    :property {description
        {
            Read recent nssmtpd sendlog or eventlog records from the
            current server's configured SMTP module. Defaults to eventlog,
            the last 60 minutes, and at most 20 newest matching
            records. Reads at most 1 MiB from the current file; does not
            scan rotated files or certify full-window coverage when
            earlier bytes remain unread. Reports malformed, oversized and
            unfinished lines separately. Filters use exact
            event/session/status matches; contains is a literal substring
            in the redacted record. Returns SMTP envelope addresses and
            diagnostic metadata, never message bodies. Peer addresses are
            masked unless includePeerAddresses is true and
            diagnostics.logs.peers.read is granted. Event records
            belonging to another virtual server are excluded; sendlog has
            no per-record server field, so its scope is the configured
            source. Does not send mail or change SMTP settings.
        }
    }

    :property {inputSchema {
        {
            "type": "object",
            "properties": {
                "log": {
                    "type": "string",
                    "enum": ["event", "send"],
                    "default": "event"
                },
                "module": {
                    "type": "string",
                    "default": "nssmtpd",
                    "description": "Configured nssmtpd module name in the current virtual server."
                },
                "lastMinutes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1440,
                    "default": 60
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "default": 20
                },
                "session": {
                    "type": "string",
                    "description": "Exact eventlog session identifier; not available in sendlog."
                },
                "event": {
                    "type": "string",
                    "description": "Exact eventlog event name."
                },
                "status": {
                    "type": "string",
                    "description": "Exact SMTP status code, for example 451 or 550."
                },
                "contains": {
                    "type": "string",
                    "description": "Literal substring in the redacted record."
                },
                "includePeerAddresses": {
                    "type": "boolean",
                    "default": false
                }
            },
            "additionalProperties": false
        }
    }}

    :method init {} {
        next
        if {${:maxReadBytes} < 1 || ${:maxReadBytes} > 16777216 || ${:maxLineBytes} < 1} {
            error "SMTP log read budget must be 1..16 MiB and line budget positive"
        }
    }

    :method options {
        {-log event}
        {-module nssmtpd}
        {-lastMinutes:integer 60}
        {-limit:integer 20}
        -session
        -event
        -status
        -contains
        {-includePeerAddresses:boolean false}
    } {
        if {$log ni {event send}} {error "log must be event or send"}
        if {![regexp {^[A-Za-z0-9_.-]+$} $module]} {error "Invalid SMTP module name"}
        if {$lastMinutes < 1 || $lastMinutes > 1440} {error "lastMinutes must be between 1 and 1440"}
        if {$limit < 1 || $limit > 100} {error "limit must be between 1 and 100"}
        set options [dict create log $log module $module lastMinutes $lastMinutes limit $limit \
            includePeerAddresses $includePeerAddresses]
        foreach key {session event status contains} {
            if {[info exists $key]} {
                set value [set $key]
                if {[string length $value] > 256 || [regexp {[\x00\r\n]} $value]} {error "Invalid $key filter"}
                dict set options $key $value
            }
        }
        if {$log eq "send" && ([info exists event] || [info exists session])} {
            error "event and session filters require eventlog"
        }
        return $options
    }
    :public method validate {arguments} {
        if {[catch {:options {*}[:jsonArguments $arguments]} message]} {
            return -code error -errorcode {NSMCP RPC -32602} $message
        }
    }

    :method path {server module kind} {
        set modules [ns_server -server $server modules]
        set smtpModule false
        if {[dict exists $modules $module]} {
            set info [dict get $modules $module]
            set smtpModule [expr {([dict exists $info name] && [dict get $info name] eq "nssmtpd")
                || ([dict exists $info file] && [file rootname [file tail [dict get $info file]]] eq "nssmtpd")}]
        }
        if {!$smtpModule} {
            return -code error -errorcode {NSMCP RPC -32602} "The selected nssmtpd module is not loaded for this server"
        }
        set section ns/server/$server/module/$module
        set parameter [expr {$kind eq "event" ? "eventlogfile" : "logfile"}]
        set enabled [ns_config -bool $section [expr {$kind eq "event" ? "eventlogging" : "logging"}] false]
        set path [ns_config $section $parameter {}]
        if {$path ne "" && [file pathtype $path] ne "absolute"} {
            set path [file join [ns_server -server $server logdir] $path]
        }
        return [dict create path $path enabled $enabled]
    }

    :method decode {value} {
        # EventField escapes every original backslash. Substitution is one-pass:
        # decoded backslashes are not processed again; log data is never Tcl code.
        return [subst -nocommands -novariables $value]
    }

    :method parse {kind line} {
        if {![regexp {^\[([^]]+)\] (\S+) (.*)$} $line -> timestamp thread rest]} {error "Invalid SMTP timestamp"}
        set at [clock scan $timestamp -format {%d/%b/%Y:%H:%M:%S %z}]
        set record [dict create timestamp $timestamp timestampSeconds $at thread $thread]
        if {$kind eq "send"} {
            set source unknown
            set separator [string last "\t" $rest]
            if {$separator >= 0} {
                set attribute [string range $rest $separator+1 end]
                if {![regexp {^source=(send|relay)$} $attribute -> source]} {
                    error "Invalid SMTP send source"
                }
                set rest [string range $rest 0 $separator-1]
            }
            if {![regexp {^(\S+) (\S+) \[([^]]+)\]:([0-9]+) ([0-9]+(?:\.[0-9]+)?) ([0-9]+) (.*?) RCPT: (.*)$} $rest \
                -> status result host port elapsed bytes sender recipients]} {error "Invalid SMTP send record"}
            return [dict merge $record [dict create status $status result $result destinationHost $host \
                destinationPort $port elapsedSeconds $elapsed sentBytes $bytes sender $sender recipients $recipients source $source]]
        }
        set fields [split $rest " "]
        lassign $fields code event peer session transaction server sender recipient action reason targets
        if {[llength $fields] < 11 || ![regexp {^(-|[1-5][0-9]{2})$} $code]
            || ![regexp {^[a-z0-9_-]+$} $event] || ![string is integer -strict $transaction]
            || [string index $peer 0] ne "\[" || [string index $peer end] ne "\]"} {error "Invalid SMTP event record"}
        foreach field {code sender recipient action reason targets} {
            if {[set $field] eq "-"} {set $field ""}
        }
        foreach field {server sender recipient action reason session} {
            set $field [:decode [set $field]]
        }
        set metadata {}
        set omitted 0
        foreach field [lrange $fields 11 end] {
            if {[regexp {^([a-z0-9-]+)=(.*)$} $field -> key value]} {
                # Expose diagnostic fields, not arbitrary custom event payloads.
                if {$key in {last-command message-bytes relay-accepted relay-reply recipients findings policy-rule
                    greylist-early-retries greylist-elapsed-seconds spf-fail dkim-no-key
                    link-status link-limit link-host-mismatch link-embedded-redirect link-destination-hosts link-destination-limit
                    dkim-obsolete-algorithm spf-result spf-peer spf-helo spf-errorcode dkim-signatures dkim-status dkim-limit}
                    || [regexp {^dkim-[1-8]-(domain|selector|key|verification|algorithm|algorithm-status)$} $key]} {
                    dict set metadata $key [:decode $value]
                } else {
                    incr omitted
                }
            }
        }
        return [dict merge $record [dict create status $code event $event peerAddress [string range $peer 1 end-1] \
            session $session transaction $transaction recordedServer $server sender $sender recipient $recipient \
            action $action reason $reason targets [expr {$targets eq "" ? {} : [split $targets ,]}] metadata $metadata metadataFieldsOmitted $omitted]]
    }

    :method redact {record peers} {
        set original $record
        set redactor [expr {$peers ? ${:peerRedactor} : ${:redactor}}]
        # Redact credential-like headers and URL parameters in free text too.
        foreach field {sender recipient recipients action reason result} {
            if {[dict exists $record $field]} {dict set record $field [$redactor message [dict get $record $field]]}
        }
        if {[dict exists $record metadata]} {
            set metadata {}
            dict for {key value} [dict get $record metadata] {
                if {!$peers && [dict exists $record peerAddress] && [dict get $record peerAddress] ne ""} {
                    set value [string map [list [dict get $record peerAddress] {[REDACTED]}] $value]
                }
                set value [$redactor message "$key: $value"]
                dict set metadata $key [string range $value [expr {[string length $key]+2}] end]
            }
            dict set record metadata $metadata
        }
        set record [$redactor record $record]
        dict set record redacted [expr {[dict remove $record redacted] ne $original}]
        return $record
    }

    :method recordTriples {record} {
        set triples {}
        dict for {key value} $record {
            if {$key in {timestampSeconds offset endOffset transaction destinationPort elapsedSeconds sentBytes metadataFieldsOmitted}} {
                lappend triples $key number $value
            } elseif {$key eq "redacted"} {
                lappend triples $key boolean $value
            } elseif {$key eq "targets"} {
                set array {}
                set index 0
                foreach target $value {
                    lappend array $index string $target
                    incr index
                }
                lappend triples $key array $array
            } elseif {$key eq "metadata"} {
                set fields {}
                dict for {name item} $value {lappend fields $name string $item}
                lappend triples $key object $fields
            } else {lappend triples $key string $value}
        }
        return $triples
    }

    :public method execute {context arguments} {
        set options [:options {*}[:jsonArguments $arguments]]
        set peers [dict get $options includePeerAddresses]
        if {$peers} {${:authorizer} require $context diagnostics.logs.peers.read}
        set server [$context server]
        set kind [dict get $options log]
        set module [dict get $options module]
        set source [:path $server $module $kind]
        set path [dict get $source path]
        set fields [list server string $server module string $module log string $kind \
            loggingEnabled boolean [dict get $source enabled] sourcePath string $path]
        if {$path eq "" || ![file isfile $path] || ![file readable $path]} {
            lappend fields available boolean false reason string {Configured SMTP log is missing or unreadable.}
            return [list {} object $fields]
        }
        set now [clock seconds]
        set from [expr {$now-60*[dict get $options lastMinutes]}]
        file stat $path before
        set end $before(size)
        set start [expr {max(0,$end-${:maxReadBytes})}]
        set channel [open $path rb]
        try {
            seek $channel $start
            set bytes [read $channel [expr {$end-$start}]]
        } finally {close $channel}
        set readBytes [string length $bytes]
        set discarded 0
        if {$start > 0} {
            # Discard the first fragment, even if it happens to be a full line.
            set first [string first \n $bytes]
            if {$first < 0} {set discarded $readBytes; set bytes ""} else {
                set discarded [expr {$first+1}]
                set bytes [string range $bytes $discarded end]
            }
        }
        set position [expr {$start+$discarded}]
        set pending [expr {$bytes ne "" && [string index $bytes end] ne "\n"}]
        set lines [split $bytes \n]
        set lines [lrange $lines 0 end-1]
        set malformed 0
        set oversized 0
        set otherServers 0
        set matches 0
        set records {}
        foreach line $lines {
            set offset $position
            incr position [expr {[string length $line]+1}]
            if {[string length $line] > ${:maxLineBytes}} {incr oversized; continue}
            if {$line eq ""} continue
            if {[catch {:parse $kind [encoding convertfrom utf-8 [string trimright $line \r]]} record]} {
                incr malformed
                continue
            }
            if {$kind eq "event" && [dict get $record recordedServer] ne $server} {incr otherServers; continue}
            set at [dict get $record timestampSeconds]
            if {$at < $from || $at > $now} continue
            set match true
            foreach key {session event status} {
                if {[dict exists $options $key] && [dict get $options $key] ne [dict get $record $key]} {set match false}
            }
            if {!$match} continue
            set record [:redact $record $peers]
            if {[dict exists $options contains] && [string first [dict get $options contains] $record] < 0} continue
            incr matches
            dict set record offset $offset
            dict set record endOffset $position
            lappend records $record
            set records [lrange $records end-[expr {[dict get $options limit]-1}] end]
        }
        set changed [catch {file stat $path after}]
        if {!$changed} {
            set changed [expr {[list $before(dev) $before(ino)] ne [list $after(dev) $after(ino)] || $after(size) < $end}]
        }
        if {$changed} {set records {}; set matches 0}
        set array {}
        set index 0
        foreach record [lreverse $records] {
            lappend array $index object [:recordTriples $record]
            incr index
        }
        set complete [expr {$start == 0 && !$pending && !$changed && !$malformed && !$oversized}]
        lappend fields available boolean true from number $from to number $now order string newest-first \
            records array $array matchesInTail number $matches omittedMatches number [expr {$matches-$index}] \
            coverage object [list sourceBytes number $end readBytes number $readBytes \
                initialOffset number $start examinedFromOffset number [expr {$start+$discarded}] \
                historyUnreadBytes number $start tailOnly boolean [expr {$start > 0}] \
                pending boolean $pending malformed number $malformed oversized number $oversized \
                otherServerRecords number $otherServers sourceChanged boolean $changed fileScanComplete boolean $complete rotatedFilesExamined boolean false]
        return [list {} object $fields]
    }
}

}

# Each registry receives independent objects; credentials remain in nsmcp.
proc ::smtpd::mcp::createTools {context} {
    set readBytes [ns_baseunit -size [::nsmcp::ToolRegistry providerConfig $context logReadBytes 1MiB]]
    set redactor [::nsmcp::LogRedactor new]
    set peerRedactor [::nsmcp::LogRedactor new -maskPeerAddresses false]
    return [list [::smtpd::mcp::SmtpLogTool new \
        -authorizer [dict get $context authorizer] \
        -redactor $redactor -peerRedactor $peerRedactor \
        -maxReadBytes $readBytes]]
}

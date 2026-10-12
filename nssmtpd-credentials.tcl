# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
# Separate SMTP credentials; the file is a Tcl dictionary, never evaluated.
namespace eval smtpd {}

# Administrative helper. The password argument is text, encoded as UTF-8.
proc smtpd::authcredential {password} {
    set salt [binary decode hex [ns_crypto::randombytes 16]]
    set digest [ns_crypto::pbkdf2_hmac -binary -digest sha256 -iterations 600000 \
                    -dklen 32 -salt $salt -secret [encoding convertto utf-8 $password]]
    return [dict create salt [binary encode hex $salt] digest $digest]
}

# authproc: smtpd::authfile; authfile supplies the filename by default.
# Callback passwords are raw UTF-8 bytes received from the client.
proc smtpd::authfile {args} {
    ns_parseargs {{-file ""} -- id username password} $args
    set filename [smtpd::AuthFilePath $file]
    set data [smtpd::AuthFileRead $filename]
    set users [dict get $data users]
    set found [dict exists $users $username]
    # Unknown users also incur the password derivation cost.
    set record [dict create salt [string repeat 0 32] digest [string repeat 0 64]]
    if {$found} {set record [dict get $users $username]}
    set salt [dict get $record salt]
    set expected [dict get $record digest]
    if {![regexp {^[0-9a-f]{32}$} $salt] || ![regexp {^[0-9a-f]{64}$} $expected]} {
        ::error "invalid SMTP credential record"
    }
    set actual [ns_crypto::pbkdf2_hmac -binary -digest sha256 -iterations 600000 \
                    -dklen 32 -salt [binary decode hex $salt] -secret $password]
    # Compare every byte, without early termination on a differing prefix.
    binary scan [binary decode hex $actual] cu* actualBytes
    binary scan [binary decode hex $expected] cu* expectedBytes
    set difference 0
    foreach a $actualBytes b $expectedBytes {set difference [expr {$difference | ($a ^ $b)}]}
    return [expr {$found && $difference == 0}]
}

# Shared parser for readers and administrative updates. Never evaluate the file.
proc smtpd::AuthFileRead {filename} {
    set f [open $filename r]
    try {set data [read $f 65537]} finally {close $f}
    if {[string length $data] > 65536 || [dict get $data version] ne "1"} {
        ::error "invalid SMTP credential file"
    }
    foreach {username record} [dict get $data users] {
        if {![regexp {^[!-~]+$} $username]
            || ![regexp {^[0-9a-f]{32}$} [dict get $record salt]]
            || ![regexp {^[0-9a-f]{64}$} [dict get $record digest]]} {
            ::error "invalid SMTP credential record"
        }
    }
    dict size [dict get $data users]
    return $data
}

# Same-directory tempfile: atomic replacement and initial mode 0600.
proc smtpd::AuthFileWrite {filename data} {
    if {[string length $data] > 65536} {::error "SMTP credential file exceeds 65536 characters"}
    set temporary ""
    try {
        set f [file tempfile temporary ${filename}.tmp]
        try {puts -nonewline $f $data} finally {close $f}
        file rename -force $temporary $filename
        set temporary ""
    } finally {
        if {$temporary ne ""} {file delete -force $temporary}
    }
}

# Add a user or replace that user's password; return the login name.
# Serialize updates within this process. Separate administrative processes must
# coordinate their updates externally.
proc smtpd::authfileadduser {args} {
    ns_parseargs {{-file ""} -- username password} $args
    set filename [smtpd::AuthFilePath $file]
    if {![regexp {^[!-~]+$} $username]} {::error "SMTP login must be nonempty printable ASCII without spaces"}
    if {$password eq ""} {::error "SMTP password must not be empty"}
    set credential [smtpd::authcredential $password]
    ns_runonce {nsv_set smtpd-authfile mutex [ns_mutex create]}
    ns_mutex eval [nsv_get smtpd-authfile mutex] {
        if {[file exists $filename]} {
            set data [smtpd::AuthFileRead $filename]
        } else {
            set data [dict create version 1 users {}]
        }
        dict set data users $username $credential
        smtpd::AuthFileWrite $filename $data
    }
    return $username
}

# Return 1 if removed, or 0 when absent (including a missing file).
proc smtpd::authfileremoveuser {args} {
    ns_parseargs {{-file ""} -- username} $args
    set filename [smtpd::AuthFilePath $file]
    set removed 0
    ns_runonce {nsv_set smtpd-authfile mutex [ns_mutex create]}
    ns_mutex eval [nsv_get smtpd-authfile mutex] {
        if {[file exists $filename]} {
            set data [smtpd::AuthFileRead $filename]
            if {[dict exists $data users $username]} {
                dict unset data users $username
                smtpd::AuthFileWrite $filename $data
                set removed 1
            }
        }
    }
    return $removed
}

# Resolve per-server configuration; explicit paths remain available for administration.
proc smtpd::AuthFilePath {{filename ""}} {
    if {$filename eq ""} {
        set filename [ns_config ns/server/[ns_info server]/module/nssmtpd authfile ""]
        if {$filename eq ""} {::error "nssmtpd authfile parameter is not configured"}
    }
    return $filename
}

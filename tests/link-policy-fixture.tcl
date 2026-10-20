# Read the shipped startup example without changing the test server configuration.
proc link_policy_example_rules {} {
    set child [interp create]
    try {
        interp alias $child ns_info {} ns_info
        $child eval {
            set server test
            set settings {}
            proc ns_section {section script} {uplevel 1 $script}
            proc ns_param {key value} {dict set ::settings $key $value}
        }
        $child eval [list source [file join $::env(ALIAS_TEST_ROOT) examples datapolicy-config.tcl]]
        return [lindex [$child eval {dict get $settings datapolicyproc}] 1]
    } finally {
        interp delete $child
    }
}
proc link_policy_message {host} {
    return "From: sender@example.test\r\nTo: one@example.test\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<a href=\"https://$host/document\">Document</a>\r\n"
}

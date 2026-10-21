# Exact hosts observed in operator-confirmed spam, not a general reputation list.
# Source during server configuration, replacing an existing datapolicyproc.
# smtpd::init validates standardpolicy options before normal SMTP processing.
ns_section ns/server/$server/module/nssmtpd {
    ns_param quarantinePolicyRejects true
    ns_param quarantineDirectory [file join [ns_info home] data smtp-quarantine $server]
    ns_param datapolicyproc {
        smtpd::standardpolicy
        -rejectSpfFailWithoutDkimKey true
        -maxGreylistEarlyRetries 10
        -blockedLinkHosts {
            accuse-de-reception-de-courrier-recommande-3.jimdosite.com
            voir-mon-doc-1.jimdosite.com
        }
    }
}

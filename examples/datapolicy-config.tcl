# Destinations observed in operator-confirmed spam, not a reputation service.
# Host entries match exactly; domain entries include every subdomain.
# Source during server configuration, replacing an existing datapolicyproc.
# smtpd::init validates standardpolicy options before normal SMTP processing.
ns_section ns/server/$server/module/nssmtpd {
    ns_param quarantinePolicyRejects true
    ns_param quarantineDirectory [file join [ns_info home] data smtp-quarantine $server]
    ns_param datapolicyproc {
        smtpd::standardpolicy
        -rejectSpfFailWithoutDkimKey true
        -localDkimDomains {openacs.org}
        -maxGreylistEarlyRetries 10
        -blockedLinkHosts {
            accuse-de-reception-de-courrier-recommande-3.jimdosite.com
            voir-mon-doc-1.jimdosite.com
            mofferbg.eu
            top-mixx.com
        }
        -blockedLinkDomains {
            renewplean.sbs
        }
    }
}

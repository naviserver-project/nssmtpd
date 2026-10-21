# DATA policy example: retain existing authentication/retry checks, then inspect
# exact link hosts observed in operator-confirmed spam. Review/update this list
# for your own site; it is not a general reputation list for the hosting domain.
# Source once during server configuration, replacing an existing datapolicyproc.
ns_section ns/server/$server/module/nssmtpd {
    ns_param quarantinePolicyRejects true
    ns_param quarantineDirectory [file join [ns_info home] data smtp-quarantine $server]
    ns_param datapolicyproc {
        smtpd::policychain {
            {smtpd::collectfindings $context findings}
            {
                if {[dict exists $findings spf-fail]
                    && [dict exists $findings dkim-no-key]} {
                    return {
                        action reject
                        reason spf-fail-and-dkim-no-key
                    }
                }
                continue
            }
            {
                if {[dict exists $findings greylist-early-retries]
                    && [dict get $findings greylist-early-retries] >= 10} {
                    return {
                        action reject
                        reason excessive-greylist-early-retries
                    }
                }
                continue
            }
            {
                if {[dict exists $findings link-destination-hosts]} {
                    foreach host [dict get $findings link-destination-hosts] {
                        if {$host in {
                            accuse-de-reception-de-courrier-recommande-3.jimdosite.com
                            voir-mon-doc-1.jimdosite.com
                        }} {
                            dict set findings blocked-link-host $host
                            return {
                                action reject
                                reason known-spam-link-host
                            }
                        }
                    }
                }
                continue
            }
        }
    }
}

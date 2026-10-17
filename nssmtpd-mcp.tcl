# Publish trusted tools without loading NX/nsmcp or requiring startup ordering.
nsv_set nsmcp:providers nssmtpd [dict create \
    file [file join [file dirname [info script]] mcp smtp-tools.tcl] \
    factory ::smtpd::mcp::createTools requires ::ns_smtpd \
    section ns/server/[ns_info server]/module/nssmtpd/mcp \
    enabledParameter enabled \
    fallbackParameters {enabled enableSmtpTools logReadBytes smtpLogReadBytes}]

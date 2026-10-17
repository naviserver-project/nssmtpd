# MCP diagnostics are separate from SMTP listener and delivery configuration.
ns_section ns/server/$server/module/nssmtpd/mcp {
    ns_param enabled true
    ns_param logReadBytes 1MiB
}
# MCP endpoint and credential settings remain in nsmcp.

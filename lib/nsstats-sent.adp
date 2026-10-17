<% uplevel #0 [list source [file join [file dirname [lindex [ns_adp_info] 0]] nsstats.tcl]]
set html [::_ns_stats.log.smtpsent]
if {$html ne ""} {ns_adp_append {<style>
.ns-smtp-views {display:flex;gap:12px;flex-wrap:wrap;margin:0 0 16px;}
.ns-smtp-views a {display:inline-block;padding:8px 12px;border:1px solid var(--color-border,#ccc);border-radius:4px;}
.ns-smtp-views a[aria-current] {font-weight:bold;background:var(--color-secondary-bg,#eee);}
.ns-quarantine-scroll {max-width:100%;overflow-x:auto;}
.ns-quarantine-table {width:100%;table-layout:auto;}
.ns-quarantine-table th:first-child,.ns-quarantine-table td:first-child {width:auto;}
.ns-quarantine-table td {vertical-align:top;overflow-wrap:anywhere;}
.ns-quarantine-preview {max-height:32em;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;}
.ns-quarantine-release {margin:16px 0;padding:12px;border:1px solid var(--color-border,#ccc);}
.ns-quarantine-release button {padding:8px 12px;}
</style>} $html} %>
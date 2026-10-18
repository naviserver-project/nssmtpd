# Shared nsstats log API fixture for standalone SMTP page tests.
proc ::_ns_stats.log.mkchart {section param title {renderer ::_ns_stats.log.chart}} {
    set ::extraHeadEntries {
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN" crossorigin="anonymous">
        <script src="https://code.highcharts.com/highcharts.js"></script>
        <script src="https://code.highcharts.com/modules/exporting.js"></script>
        <script src="https://code.highcharts.com/modules/export-data.js"></script>
        <script src="https://code.highcharts.com/highcharts-more.js"></script>
        <script src="https://code.highcharts.com/modules/dumbbell.js"></script>
        <script src="https://code.highcharts.com/modules/lollipop.js"></script>
    }

    set configured_logfile [ns_config ns/server/[ns_info server]/$section $param ""]
    if {$configured_logfile eq ""} {
        set HTML "<p>No $section $param logfiles configured</p>"
    } else {
        set files [::_ns_stats.log.logfiles $section $param]
        set selected_logfile [ns_queryget logfile ""]
        if {$selected_logfile eq ""} {
            set logfile $configured_logfile
            if {$logfile ni $files} {set logfile [lindex $files 0]}
        } else {
            set logfile $selected_logfile
            if {[file tail $selected_logfile] eq $selected_logfile} {
                set logfile [file join [file dirname $configured_logfile] $selected_logfile]
            }
        }
        # Restrict all renderers to configured log files and discovered rotations.
        if {$logfile eq "" || $logfile ni $files} {
            set HTML {<p>No matching log file available.</p>}
        } else {
            try {
                set HTML [{*}$renderer $logfile $section $param $title]
            } on error {message options} {
                ns_log error "nsstats: cannot render $section $param log $logfile: [dict get $options -errorinfo]"
                set HTML "<p>Cannot read log: [ns_quotehtml $message]</p>"
            }
        }
    }
    append html \
        [::_ns_stats.header $title] \
        $HTML \
        [::_ns_stats.footer]
    return $html
}

proc ::_ns_stats.log.fileform {files selected page {filters {}}} {
    set options {}
    foreach path $files {
        set attribute [expr {$path eq $selected ? "selected" : ""}]
        append options "<option value=\"[ns_quotehtml $path]\" $attribute>[ns_quotehtml $path]</option>"
    }
    set html "<form action=\"nsstats.tcl\" class=\"row g-1\">\
        <input type=\"hidden\" name=\"@page\" value=\"[ns_quotehtml $page]\">\
        <div class=\"col\"><label>Log <select class=\"form-select\" name=\"logfile\">$options</select></label></div>"
    dict for {name value} $filters {
        append html "<div class=\"col\"><label>[ns_quotehtml [string totitle $name]] \
            <input class=\"form-control\" name=\"[ns_quotehtml $name]\" value=\"[ns_quotehtml $value]\"></label></div>"
    }
    append html {<div class="col"><button type="submit" class="btn btn-outline-secondary">Show</button></div></form>}
    return $html
}

proc ::_ns_stats.log.httpclient {} {
    return [::_ns_stats.log.mkchart httpclient logfile "HTTP Client Log"]
}

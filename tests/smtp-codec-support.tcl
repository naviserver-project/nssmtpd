# Reference EventField's token encoding for nonempty, NUL-free Tcl strings.
# Empty fields use a sentinel handled by the record parser, not by the decoder.
proc smtp_encode_field {value} {
    set map [list \\ {\x5c} [format %c 127] {\x7f}]
    for {set i 1} {$i<=32} {incr i} {
        lappend map [format %c $i] [format {\x%02x} $i]
    }
    return [string map $map $value]
}
proc smtp_decode_values {} {
    set controls {}
    for {set i 1} {$i<=32} {incr i} {append controls [format %c $i]}
    return [list {plain text} "line\nnext\tcolumn\rend" $controls [format %c 127] \
        {literal \n \r \t \x20 \u0041 \123 \\} \
        {$::smtpDecodeProbe [set ::smtpDecodeProbe changed] [error unexpected]} \
        {Grüße 日本語}]
}

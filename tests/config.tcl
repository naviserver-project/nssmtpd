#
# nsssl configuration test.
#
set port 8080
set address "0.0.0.0"

if {[ns_info ipv6]} {
    #
    # The version of NaviServer supports IPv6. Probe if we can reverse
    # lookup the loopback interface and bind to the IPv6 loopback
    # address with the port specified above.
    #
    if {
        ![catch {ns_hostbyaddr ::1}]
        && ![catch {close [ns_socklisten ::1 $port]}]
    } {
        #
        # Yes we can. So use the IPv6 any address
        #
        set address ::
    }
}

set homedir [pwd]/tests
set bindir  [file dirname [ns_info nsd]]

ns_section "ns/parameters"
ns_param   home           $homedir
ns_param   tcllibrary     $bindir/../tcl
ns_param   logdebug       false

# configure SMTP module
ns_param        smtphost            $address
ns_param        smtpport            2525
ns_param        smtptimeout         10    ;# 10 seconds
ns_param        smtplogmode         true
ns_param        smtpmsgid           false
ns_param        smtpmsgidhostname   ""
ns_param        smtpencodingmode    false
ns_param        smtpencoding        "utf-8"
ns_param        smtpauthmode        ""
ns_param        smtpauthuser        ""
ns_param        smtpauthpassword    ""

ns_section "ns/servers"
ns_param   test            "Test Server"

ns_section "ns/server/test/tcl"
ns_param   initfile        $bindir/init.tcl
ns_param   library         $homedir/modules

ns_section "ns/server/test/module/nssmtpd"
    ns_param port 2525
    ns_param address $address
    ns_param relay localhost:25
    ns_param spamd localhost
    ns_param initproc smtpd::init
    ns_param heloproc smtpd::helo
    ns_param heloproc smtpd::mail
    ns_param rcptproc smtpd::rcpt
    ns_param dataproc smtpd::data
    ns_param errorproc smtpd::error
    ns_param relaydomains "localhost"
    ns_param localdomains "localhost"

ns_section "ns/server/test/module/nssock"
ns_param   port            $port
ns_param   hostname        $address

# ns_section "ns/server/test/module/nsssl"
# ns_param   port            8443
# ns_param   hostname        localhost
# ns_param   address         [expr {[ns_info ipv6] ? "::1" : "127.0.0.1"}]
# ns_param   ciphers         "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305"
# ns_param   protocols	   "!SSLv2"
# ns_param   certificate	   $homedir/etc/server.pem
# ns_param   verify     	   0
# ns_param   writerthreads   2
# ns_param   writersize	   2048

ns_section test
ns_param listenport [ns_config "ns/server/test/module/nssock" port]
ns_param listenurl http://\[[ns_config "ns/server/test/module/nssock" address]\]:[ns_config "ns/server/test/module/nssock" port]

#	set host [ns_config "test" loopback]
#	set port [ns_config "ns/module/nssock" port]


ns_section "ns/server/test/modules"
#ns_param   nsssl           $bindir/nsssl.so
ns_param   nssock           $bindir/nssock.so
ns_param   nssmtpd          [pwd]/nssmtpd.so

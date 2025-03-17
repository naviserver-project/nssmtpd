Below is an improved version of the README converted to Markdown:

---

# SMTPD Server/Proxy for NaviServer

**Release:** 2.3  
**Author:** Vlad Seryakov (<vlad@crystalballinc.com>) Gustaf Neumann (<neumann@wu-wien.ac.at>)

---

## Overview

This NaviServer module implements the SMTP protocol and functions as an SMTP proxy/server with built-in anti-spam and anti-virus capabilities. The sender can use the nssmptd API to directly send mails. A common configuration is to specify as the target relay a local installation of Postfix responsible for further delivery.

```
    A NaviServer (Sender) → B (nssmptd, 127.0.0.1:smtpdport) → C (relay, localhost:25)
```

- **Compatibility:** Compiles with Tcl versions 8.5, 8.6, and 9.0.
- **Note:** By default, anti-spam and anti-virus support are deactivated. They may require additional configuration or updates to work with current libraries.

---

## Requirements

### Anti-SPAM Support

Install one of the following to enable anti-spam features:

- **SpamAssassin:** [http://www.spamassassin.org/](http://www.spamassassin.org/)
- **DSPAM:** [http://www.nuclearelephant.com/projects/dspam/](http://www.nuclearelephant.com/projects/dspam/)  
  Patched version: [Download DSPAM 3.1.0 (Vlad)](http://www.crystalballinc.com/vlad/dspam-3.1.0-vlad-src.tar.gz)

### Anti-Virus Support

Install one of the following to enable anti-virus features:

- **ClamAV:** [http://www.clamav.net/](http://www.clamav.net/)
- **Sophos SAVI:** [http://sophos.com](http://sophos.com)

---

## Configuration

To enable the SMTPD module, add the following configuration directives to your `nsd.tcl` file. The `modules` section should already exist—just add the `nssmtpd` line:

```tcl
ns_section ns/server/${server}/modules {
  ns_param nssmtpd ${home}/bin/nssmtpd.so
}

ns_section ns/server/${server}/module/nssmtpd {
  ns_param port         2525
  ns_param address      127.0.0.1
  ns_param relay        localhost:25
  ns_param spamd        localhost
  ns_param initproc     smtpd::init
  ns_param rcptproc     smtpd::rcpt
  ns_param dataproc     smtpd::data
  ns_param errorproc    smtpd::error
  ns_param relaydomains "localhost domain.com"
  ns_param localdomains "localhost domain.com"

  # For STARTTLS functionality
  ns_param certificate "pathToYourCertificateChainFile.pem"
  ns_param cafile      ""
  ns_param capath      ""
  ns_param ciphers     "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305"

  # For logging "ns_smtpd send ..." operations
  ns_param logging    on           ;# default: off
  # ns_param logfile ${logroot}/smtpsend.log
  ns_param logrollfmt %Y-%m-%d     ;# format appended to log filename
  # ns_param logmaxbackup 100       ;# max number of backup log files
  # ns_param logroll true           ;# enable automatic log rolling
  # ns_param logrollonsignal true   ;# roll logs on SIGHUP
  # ns_param logrollhour 0          ;# specify the hour to roll logs
}
```

Once enabled, the SMTPD module will act as an SMTP server, forwarding all messages to the real SMTP server specified in the `relay` parameter. For each SMTP command, it calls a corresponding Tcl handler that performs the actual processing. The package can also be used via the `ns_nsmp` command.

---

## Usage

The module is controlled by a single Tcl command: `ns_smtpd`. Below is a summary of its usage:

```
ns_smtpd flag /name/
ns_smtpd send /sender_email/ /rcpt_email/ /data_varname/ ?server? ?port?
ns_smtpd relay add /domain/
ns_smtpd relay check /address/
ns_smtpd relay clear
ns_smtpd relay del /domain/
ns_smtpd relay get
ns_smtpd relay set /relay/ ?relay? ...
ns_smtpd local add /domain|ipaddr|
ns_smtpd local check /ipaddr|
ns_smtpd local clear
ns_smtpd local del /domain|ipaddr|
ns_smtpd local get
ns_smtpd local set /ipaddr/ ?ipaddr? ...
ns_smtpd encode /base64|hex|qprint/ /text/
ns_smtpd decode /base64|hex|qprint/ /text/
ns_smtpd checkemail /email/           ;# Parses email and returns in the form name@domain if valid
ns_smtpd checkdomain /domain/
ns_smtpd virusversion                ;# Returns version of anti-virus tool used
ns_smtpd spamversion                 ;# Returns version of anti-spam tool used
ns_smtpd checkspam /message/ ?email?
ns_smtpd trainspam 1|0 /email/ /message/ ?signature? ?mode? ?source?
ns_smtpd checkvirus /data/
ns_smtpd sessions
ns_smtpd gethdr /name/
ns_smtpd gethdrs ?name?
ns_smtpd getbody
ns_smtpd getfrom
ns_smtpd getfromdata
ns_smtpd setfrom /address/
ns_smtpd setfromdata /data/
ns_smtpd getrcpt ?address|index?
ns_smtpd getrcptdata ?address|index?
ns_smtpd addrcpt /address/ ?flags? ?data?
ns_smtpd setrcptdata /address|index/ /data/
ns_smtpd delrcpt /address|index/
ns_smtpd setflag /address|index/ /flag/
ns_smtpd unsetflag /address|index/ /flag/
ns_smtpd getflag ?address|index?
ns_smtpd setreply /reply/
ns_smtpd getline
ns_smtpd dump /filename/
```

---

## Licensing

This project is licensed under the Mozilla Public License.

---

## Authors

- **Vlad Seryakov** – <vlad@crystalballinc.com>
- **Gustaf Neumann** – <neumann@wu-wien.ac.at>

---
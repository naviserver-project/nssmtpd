
# SMTPD Server/Proxy for NaviServer

**Release:** 2.4  
**Author:** Vlad Seryakov (<vlad@crystalballinc.com>) Gustaf Neumann (<neumann@wu-wien.ac.at>)

---

# NaviServer SMTPD Module

The NaviServer SMTPD module implements the SMTP protocol and functions
as both an SMTP proxy and server. It provides an API for interacting
with the server directly via Tcl for e.g. sending mails and
interacting with the server. A typical setup uses a local Postfix
installation as the relay for further message delivery. The module
features built-in anti-spam and anti-virus capabilities which require
work to interact with newer releases of the external packages.


```
    A NaviServer (Sender) → B (nssmptd, 127.0.0.1:smtpdport) → C (relay, localhost:25)
```

- **Compatibility:** Compiles with Tcl versions 8.5, 8.6, and 9.0.
- **Note:** By default, anti-spam and anti-virus support are deactivated. They may require additional configuration or updates to work with current libraries.

---


## Table of Contents

- [Overview](#overview)
- [Requirements](#requirements)
  - [Anti-Spam Support](#anti-spam-support)
  - [Anti-Virus Support](#anti-virus-support)
- [Configuration](#configuration)
  - [Basic Setup](#basic-setup)
  - [Enabling Logging](#enabling-logging)
- [Relay Authentication](#relay-authentication)
- [API Overview](#api-overview)
- [Usage Example](#usage-example)
- [License](#license)

--- 

## Overview

This module acts as an intermediary SMTP server. It accepts messages
via NaviServer or directly through its API and then forwards them to a
designated SMTP relay. This design enables integration with anti-spam
and anti-virus tools, providing an additional layer of email security.

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

### Basic Setup

To enable the SMTPD module, add the following directives to your
NaviServer configuration file (e.g., `nsd.tcl`) Load the `nssmtpd.so`
module within your server’s `modules` section and configure its
settings in a dedicated section:


```tcl
ns_section ns/server/${server}/modules {
  ns_param nssmtpd ${home}/bin/nssmtpd.so
}

ns_section ns/server/${server}/module/nssmtpd {
  #
  # Networking settings
  #
  ns_param port         2525
  ns_param address      127.0.0.1
  ns_param relay        localhost:25
  ns_param relaydomains "localhost domain.com"
  ns_param localdomains "localhost domain.com"
  ns_param spamd        localhost
  
  #
  # Tcl callback definitions
  #
  ns_param initproc     smtpd::init
  ns_param rcptproc     smtpd::rcpt
  ns_param dataproc     smtpd::data
  ns_param errorproc    smtpd::error

  # For STARTTLS functionality
  ns_param certificate "pathToYourCertificateChainFile.pem"
  ns_param cafile      ""
  ns_param capath      ""
  ns_param ciphers     "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305"
}
```

### Enabling Logging

For secure communication via STARTTLS and to enable logging, add these
parameters to the `nssmtpd` section.
  
```tcl
  # For logging "ns_smtpd send ..." operations
  ns_param logging    on           ;# default: off
  # ns_param logfile ${logroot}/smtpsend.log
  ns_param logrollfmt %Y-%m-%d     ;# format appended to log filename
  # ns_param logmaxbackup 100       ;# max number of backup log files
  # ns_param logroll true           ;# enable automatic log rolling
  # ns_param logrollonsignal true   ;# roll logs on SIGHUP
  # ns_param logrollhour 0          ;# specify the hour to roll logs
```


### Relay Authentication

The `relay` parameter specifies the SMTP server used for message
delivery. When using port `25`, the relay server is expected to accept
messages without further authentication. However, if you configure the
relay to use port `587`, the module supports PLAIN password
authentication. In this case, ensure that:

- The relay server supports STARTTLS.
- NaviServer (and this module= is compiled with OpenSSL support.

The URL format is designed to allow for future authentication
methods. For example (the uppercase letters are placeholders):

```tcl
ns_section ns/server/${server}/module/nssmtpd {
  # ...
  ns_param relay plain://USER:PWD@MAILHOST:587
  # ...
}
```

## API Overview

The module is managed via a single Tcl command, `ns_smtpd`, which
provides an extensive set of operations for interacting with the SMTP
server. Below is a summary of available commands:

- **General Commands:**
  - `ns_smtpd flag /name/`
  - `ns_smtpd send /sender_email/ /rcpt_email/ /data_varname/ ?server? ?port?`
- **Relay Management:**
  - `ns_smtpd relay add /domain/`
  - `ns_smtpd relay check /address/`
  - `ns_smtpd relay clear`
  - `ns_smtpd relay del /domain/`
  - `ns_smtpd relay get`
  - `ns_smtpd relay set /relay/ ?relay? ...`
- **Local Domains/IPs:**
  - `ns_smtpd local add /domain|ipaddr|`
  - `ns_smtpd local check /ipaddr|`
  - `ns_smtpd local clear`
  - `ns_smtpd local del /domain|ipaddr|`
  - `ns_smtpd local get`
  - `ns_smtpd local set /ipaddr/ ?ipaddr? ...`
- **Data Encoding/Decoding:**
  - `ns_smtpd encode /base64|hex|qprint/ /text/`
  - `ns_smtpd decode /base64|hex|qprint/ /text/`
- **Validation and Versioning:**
  - `ns_smtpd checkemail /email/` &nbsp;&nbsp;&nbsp; *(Returns a valid email in the form name@domain)*
  - `ns_smtpd checkdomain /domain/`
  - `ns_smtpd virusversion` &nbsp;&nbsp;&nbsp; *(Returns anti-virus tool version)*
  - `ns_smtpd spamversion` &nbsp;&nbsp;&nbsp; *(Returns anti-spam tool version)*
- **Spam and Virus Checks:**
  - `ns_smtpd checkspam /message/ ?email?`
  - `ns_smtpd trainspam 1|0 /email/ /message/ ?signature? ?mode? ?source?`
  - `ns_smtpd checkvirus /data/`
- **Session and Message Handling:**
  - `ns_smtpd sessions`
  - `ns_smtpd gethdr /name/`
  - `ns_smtpd gethdrs ?name?`
  - `ns_smtpd getbody`
  - `ns_smtpd getfrom`
  - `ns_smtpd getfromdata`
  - `ns_smtpd setfrom /address/`
  - `ns_smtpd setfromdata /data/`
  - `ns_smtpd getrcpt ?address|index?`
  - `ns_smtpd getrcptdata ?address|index?`
  - `ns_smtpd addrcpt /address/ ?flags? ?data?`
  - `ns_smtpd setrcptdata /address|index/ /data/`
  - `ns_smtpd delrcpt /address|index/`
  - `ns_smtpd setflag /address|index/ /flag/`
  - `ns_smtpd unsetflag /address|index/ /flag/`
  - `ns_smtpd getflag ?address|index?`
  - `ns_smtpd setreply /reply/`
  - `ns_smtpd getline`
  - `ns_smtpd dump /filename/`

The provided source code of the Tcl files  provide more details about
using the API.


## Usage Example

Once configured, the SMTPD module will act as an SMTP server, forwarding messages to the relay specified by the `relay` parameter. Additionally, you can interact with it via the `ns_smtpd` command to perform actions such as sending mail, checking spam/virus status, and managing session data.

For example, to send an email using the API:

```tcl
set message "From: sender@example.com
To: recipient@example.com
Date: [ns_httptime [clock seconds]]
Subject: Testmail
 
This is a test mail!
"

ns_smtpd send sender@example.com recipient@example.com message localhost 25
```

This command will deliver the message to the configured SMTP relay,
applying potentially anti-spam or anti-virus checks along the way.

---

## Licensing

This project is licensed under the Mozilla Public License.

---

## Authors

- **Vlad Seryakov** – <vlad@crystalballinc.com>
- **Gustaf Neumann** – <neumann@wu-wien.ac.at>


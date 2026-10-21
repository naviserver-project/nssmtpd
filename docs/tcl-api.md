# Send mail and extend SMTP handling from Tcl

[Administration guide](../README.md)

This is the developer/operator reference for application sending, callback
integration and session inspection. For listener configuration and operational
checks, use [deployment](deployment.md) and [monitoring](monitoring.md).

## Send a message from an application

Once configured, the SMTPD module will act as an SMTP server, forwarding messages to the relay specified by the `relay` parameter. Additionally, you can interact with it via the `ns_smtpd` command to perform actions such as sending mail and managing session data.

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

This example supplies an explicit SMTP host and port. Omitting them uses
the configured relay defaults. Successful sending means acceptance by the
upstream SMTP server, not final mailbox delivery. Do not rely on the legacy
scanner integrations for current spam or virus filtering.

---

## Parse and validate a mailbox

```tcl
ns_smtpd parseemail {Example User <"john smith"@example.org>}
# localpart {john smith} domain example.org address {"john smith"@example.org} name {Example User}

ns_smtpd parseemail -syntax smtp {<"john smith"@example.org>}
# localpart {john smith} domain example.org address {"john smith"@example.org}
```

The default `header` syntax parses one complete mailbox, optionally with a
display name and angle brackets. Header comments and folding whitespace are
allowed between constituents; quoted local parts are decoded into `localpart`.
The `address` field retains the quoting/escaping needed for a valid mailbox.
`name` is present only for a display name. Groups, address lists, trailing
unparsed text, malformed domain labels/literals and unquoted spaces inside a
local part are rejected. Existing long local parts (including
OpenACS bounce addresses) remain supported; parsing does not add a
new SMTP mailbox-size restriction. Domains are DNS-style labels or IPv4/IPv6 address
literals. Syntax validation performs no DNS lookup and grants no relay permission.

`-syntax smtp` parses a bare mailbox or angle path with SMTP quoting rules,
without header display names, comments or whitespace around `@`. It also accepts
`<>` as the null reverse path (empty `localpart` and `domain`), and validates and
ignores obsolete SMTP source routes. MAIL and RCPT use this syntax before any
normalization; a null RCPT is rejected. SIZE and BODY parameters of MAIL are
handled separately. Existing command-level handling of null senders remains.

Like `ns_parseurl`, a parse failure raises an ordinary Tcl error with a message
`Could not parse email "...": reason`, without a custom error code or partial
result. `ns_smtpd checkemail` uses the header parser and retains its string
contract: a valid serialized address or an empty string, without mutating its
Tcl input. It now rejects malformed addresses that the former phrase extractor
accepted. Header whitespace around `@` is legal; the corresponding SMTP path
is rejected. Valid local parts containing spaces remain quoted in the output.

## Inspect parsed header sets

`ns_smtpd headers $id` returns a detached, case-insensitive `ns_set` in parsing
order, retaining duplicate fields and empty values. NaviServer reclaims this
temporary set when the SMTP connection ends (which may span multiple mail
transactions). Changes to this copy do not affect the SMTP transaction.
The parsed view retains the existing address normalization; it is not a raw
representation suitable for signature verification or reserializing received mail.

`gethdr` and `gethdrs` keep their existing reverse parsing order and filtering of
empty values in named lookups. Forwarding uses the original wire data, not a
serialization of the parsed set. NaviServer 4.99 remains a compilation target;
the new case-insensitive Tcl interface and diagnostic features target 5+.

## Find session and relay commands

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
  - `ns_smtpd getauthuser /session/`
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
  - `ns_smtpd parseemail ?-syntax header|smtp? ?--? /email/` *(Returns parsed address constituents as a dictionary)*
  - `ns_smtpd checkemail /email/` *(Returns the parsed address, or an empty string on invalid input)*
  - `ns_smtpd checkdomain /domain/`
- **Session and Message Handling:**
  - `ns_smtpd sessions`
  - `ns_smtpd gethdr /name/`
  - `ns_smtpd gethdrs ?name?`
  - `ns_smtpd getbody`
  - `ns_smtpd getfrom`
  - `ns_smtpd getfromdata`
  - `ns_smtpd setfrom /address/`
  - `ns_smtpd setfromdata /data/`
  - `ns_smtpd getrcptfindings /session/` *(Accepted original recipient findings, current callback only)*
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

## Use low-level quarantine operations

Low-level administrative support: `ns_smtpd getmessage SESSION` returns unstuffed
message bytes; `ns_smtpd sendresolved SENDER RECIPIENT_LIST DATA_VARIABLE` sends
binary RFC data to exactly one saved recipient without alias expansion;
`ns_smtpd filesync PATH` syncs a closed file or directory. Normal application
sending should continue to use `ns_smtpd send`.

For alias callback contracts, see [recipient routing](recipient-routing.md#implement-application-specific-alias-routing).
For custom decisions and transaction findings, see [policy callbacks](policy-reference.md).
For credential-file operations, see [client submission](client-submission.md).

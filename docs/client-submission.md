# Let mail clients submit authenticated mail

[Administration guide](../README.md)

Use this guide when a mail client should submit mail through nssmtpd using
STARTTLS and a separate SMTP login. This is independent of the credentials used
by nssmtpd to authenticate to its upstream relay.

## Enable client login over STARTTLS

Incoming `AUTH PLAIN` is opt-in and independent of outgoing relay credentials
and `authdetailsproc`. It is advertised only after STARTTLS and accepted only
following the client's post-TLS EHLO. This allows mail clients to submit through
the existing port 25 listener while unauthenticated incoming mail continues to
use the existing relay-domain and alias rules. LOGIN and other SASL mechanisms
are not supported.

Configure a Tcl command prefix to verify separate SMTP credentials:

```tcl
ns_section ns/server/${server}/module/nssmtpd {
    ns_param authproc smtpd::authfile
    ns_param authfile /run/secrets/smtp-users
    # Existing certificate, key, relay, aliasproc, and port settings remain.
}
```

The module calls `authproc` with three appended arguments: session ID, login
name, and password bytes. Return a Tcl boolean: true authorizes relay submission
for this connection, false rejects the login. Errors or nonboolean results fail
closed with a temporary authentication error. Command-prefix arguments are
preserved; credentials are passed as Tcl objects, never evaluated as script.
Login names are case-sensitive printable ASCII; passwords are received as raw
UTF-8 bytes. A PLAIN authorization identity must be empty or match the login.
The verifier must not log passwords or retain them. Module protocol logging
redacts both the AUTH command payload and challenge responses; verifier errors
are logged without their Tcl result or stack, which might contain credentials.

`ns_smtpd getauthuser $id` returns the authenticated login, or an empty string.
Identity survives RSET and completed messages but never survives connection
closure. Reauthentication and AUTH during a MAIL transaction are rejected;
three failed credential checks close the connection. Existing IP-based LOCAL
trust is unchanged. Authenticated submission allows alias passthrough and skips
the built-in recipient/DATA policy wrappers as LOCAL submissions do. Custom
`mailproc` and `rcptproc` callbacks still run and can use the authenticated
identity to enforce sender restrictions.

## Add, change or remove SMTP users

The provided `nssmtpd-credentials.tcl` includes `smtpd::authcredential`,
`smtpd::authfile`, `smtpd::authfileadduser`, `smtpd::authfilechangepassword`, and
`smtpd::authfileremoveuser`.
Records use a random 16-byte salt and PBKDF2-HMAC-SHA256 with
600,000 iterations. The file is a Tcl dictionary read as data, never sourced.
It is read for each login so replacing it updates credentials without a restart.
Unknown users incur the same password derivation work; digest comparison visits
every byte. Malformed or unreadable files fail closed.

An existing **nscp control-port session** is one option for populating and
maintaining the password file. Connect to the nscp instance for the intended
virtual server and check `ns_info server` before running the commands below.
They execute as the NaviServer account, so the configured credential directory
must be writable by that account. In Docker, the directory mount must be writable
when managing users through nscp; a read-only mount supports verification only.

Manage users in that administrative NaviServer interpreter with a password
supplied separately in `$smtpPassword`:

```tcl
smtpd::authfileadduser my-smtp-login $smtpPassword
# To change only an existing account:
smtpd::authfilechangepassword my-smtp-login $smtpPassword
unset smtpPassword
smtpd::authfileremoveuser my-smtp-login
```

`authfileadduser ?-file filename? ?--? username password` creates the file if missing, adds
the user, or replaces that user's password; it returns the login name.
`authfilechangepassword ?-file filename? ?--? username password` replaces only an
existing user's password and returns the login name; an unknown user is an error.
`authfileremoveuser ?-file filename? ?--? username` returns 1 when removed, or 0 when absent.
Both preserve other users. By default these procedures and `smtpd::authfile`
use the `authfile` parameter in the current server's nssmtpd module section.
There is no implicit filename: a missing or empty parameter produces an error.
The `-file filename` option overrides configuration for any of these procedures.
Use `--` before positional arguments when a login name starts with a dash.
Use an absolute configured path, and run management commands in an interpreter
for the intended server. Setting `authfile` alone does not enable AUTH; configure
`authproc smtpd::authfile` as well.

Updates use a process-local mutex and atomically
replace the file using a same-directory mode-0600 temporary file, with
`${filename}.tmp` as its template. This requires write permission on the parent
directory, even when the existing password file is writable. Serialize
administration across separate processes; the mutex does not coordinate different
NaviServer instances. Malformed existing files are not overwritten. The parent
directory must already exist and be writable by the administrative account.

Run the procedures as the account that will own the credential file, normally
the NaviServer account. For Docker, persist it outside the container and mount
its containing directory read-only for the SMTP server, for example at
`/run/secrets`; directory mounts expose atomic file replacements to the reader.
Adding SMTP users does not create OpenACS accounts or mailboxes.

**Password-file helper requirements:** Tcl 8.6 or newer, NaviServer 4.99.23 or
newer with working `ns_crypto::pbkdf2_hmac` and `ns_crypto::randombytes` commands,
and a core built with OpenSSL 1.1.1 or newer with SHA-256 enabled. OpenSSL 1.1.1
provides the required
[`PKCS5_PBKDF2_HMAC`](https://docs.openssl.org/1.1.1/man3/PKCS5_PBKDF2_HMAC/)
function; OpenSSL 3 is not required. PBKDF2 needs no external executable or
additional password database library. The requirement concerns NaviServer's core
crypto support, not merely an installed `openssl` executable. Custom `authproc`
callbacks can use other credential backends instead.

In Apple Mail, set the outgoing server to `smtp.openacs.org`, port 25, TLS
(STARTTLS), and Password authentication with this separate login/password.
The certificate must cover that hostname. AUTH is disabled if `authproc` is
unset or empty; enabling it does not make unauthenticated clients relayable.

## Verify login and policy scope

Use the configured certificate hostname in the mail client, require STARTTLS,
and use the separate SMTP credentials. Verify a successful login and a failed
login, and confirm unauthenticated clients still cannot relay to arbitrary
external domains. Authenticated/local submissions bypass the built-in incoming
recipient and DATA policy wrappers; they are not a way to test external-mail
filtering. See [mail policy](mail-policy.md) for those tests.

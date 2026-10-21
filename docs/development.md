# Test changes and maintain module documentation

[Administration guide](../README.md)

Use this guide when building a release, changing callbacks/readers, or
updating generated reference documentation. Routine server administration is
covered by the task guides linked from the [README](../README.md).

## Run isolated SMTP regression tests

To run the isolated tests (Tcl 8.6+, OpenSSL CLI and an installed
NaviServer with OpenSSL support needed):

```sh
make test
# Optional: select an installation or filter test cases.
make test NAVISERVER=/usr/local/ns TCLTESTARGS='-match nssmtpd-*'
```

These tests use ephemeral loopback ports and a local SMTP sink. They exercise
basic `ns_sendmail` and `ns_smtpd send` submission as well as
unset/empty hooks, incoming and outgoing expansion, rejection and temporary
failures, recipient limits, callback compatibility and relay authorization.
The plain SMTP sink uses NaviServer's `ns_connchan` listener and callbacks.
Forwarding through STARTTLS uses a second nssmtpd instance within the test
server, since `ns_connchan` does not provide a STARTTLS-upgrade operation.
They do not contact external mail servers or require a database.
`make test` builds the module and runs the Tcl harness; it needs neither a
local Postfix service nor the `nsadmin` account. Failed tests cause a nonzero
make exit status. Aggregate envelope checks are skipped when filtering cases.

## Test the administration pages

Run the standalone rendering, permissions and registry tests with
`make test-admin`. No SMTP listener or nsstats checkout is needed. The native ADP inclusion
and empty direct-response checks in `tests/admin/adp.test` run inside NaviServer.

## Test the MCP provider

Run the native regression suite using a NaviServer installation containing the
updated nsmcp (`NSMCP_MODULE_LIBRARY` can override its Tcl library directory):

```sh
make test-mcp NAVISERVER=/usr/local/ns
```

It checks event/send parsing, authorization, peer masking, scope, bounded reads,
provider metadata and rejection of release/path arguments. No SMTP listener,
model backend or external checkout is required.

## Regenerate parameter and module references

This repository owns `doc/tcl/config-parameters.tcl`; its committed generated
reference is `doc/src/include/parameters.man`. The complete module manual is
`doc/src/nssmtpd.man`. With the updated NaviServer development tools:

```sh
make regen-config-parameters-includes
make check-doc
make build-doc
```

HTML is written to `doc/html`, nroff to `doc/man`. Ordinary builds and installation
use the committed fragment without running the documentation generator.
`DOC_TOOLS=/path/to/naviserver/doc/tools` selects source-checkout tools.
For combined documentation, run NaviServer's `make build-doc` with
`EXTERNAL_MODULE_DOCS` listing the selected local module repository directories.

## Update the mail-path diagram

The editable [D2 source](smtp-paths.d2) is included alongside the rendered
SVG. Regenerate it from the module directory with:

```sh
d2 --layout dagre docs/smtp-paths.d2 docs/smtp-paths.svg
```

## Maintain historical scanner integrations

The source retains integrations for **SpamAssassin/spamd**, **DSPAM**,
**ClamAV**, and **Sophos SAVI**. These are historical interfaces, not working
scanner integrations for current installations: external APIs have changed
or the referenced libraries/services are unavailable. They are disabled by
default and require maintenance and verification before use. Installing a
current scanner alone does not restore these integrations.

The associated legacy API includes:

- `ns_smtpd spamversion` and `ns_smtpd virusversion`
- `ns_smtpd checkspam /message/ ?email?`
- `ns_smtpd trainspam 1|0 /email/ /message/ ?signature? ?mode? ?source?`
- `ns_smtpd checkvirus /data/`

The `spamd` parameter and optional DSPAM/ClamAV/SAVI build settings belong to
these integrations. They are not part of the [basic SMTP deployment](deployment.md).
Current Tcl policy callbacks can integrate separately maintained services
without depending on these historical interfaces.

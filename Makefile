ifndef NAVISERVER
    NAVISERVER  = /usr/local/ns
endif

#
# Module name
#
MODNAME  = nssmtpd
MOD      = nssmtpd.so

#
# Objects to build.
#
MODOBJS     = nssmtpd.o

# Optional SPF evaluator; no new dependency in the default build.
# Override SPF2_CFLAGS/SPF2_LIBS for a nonstandard installation.
ifeq ($(WITH_SPF2),1)
SPF2_LIBS ?= -lspf2
CFLAGS += -DUSE_SPF2 $(SPF2_CFLAGS)
MODLIBS += $(SPF2_LIBS)
endif

# Use DSPAM

#CFLAGS   += -I/usr/local/include -DUSE_DSPAM -DSIGNATURE_LIFE=14 -DDSPAM_HOME=/usr/local/aolserver/modules/dspam
#MODLIBS  += -ldspam

# Use SpamAssassin
#CFLAGS   += -DUSE_SPAMASSASSIN

# SAVI interface
#CFLAGS   += -DUSE_SAVI -I/usr/local/include/sav_if
#MODLIBS  += -L/usr/local/lib -lsavi

# ClamAv interface
#
# The current CLAMAV interface uses the removed ClamAvLimits
# structures. These have to be replaced by the cl_engine_set_xxx methods
# see e.g. https://github.com/paulbeesley3/ClamAV-Sharp/commit/76a5d42b66904fb9227c7235ab23197fc7db4ccc
#
#CFLAGS   += -DUSE_CLAMAV
#MODLIBS  += -lclamav

TCL       = nssmtpd-mcp.tcl nssmtpd-nsstats.tcl nssmtpd-quarantine.tcl nssmtpd-procs.tcl nssmtpd-spf.tcl nssmtpd-auth.tcl nssmtpd-credentials.tcl

INSTALL += install-admin-pages install-mcp-tools install-mcp-example

include  $(NAVISERVER)/include/Makefile.module

.PHONY: install-admin-pages test-admin
install-admin-pages:
	$(MKDIR) "$(DESTDIR)$(INSTTCL)/$(MODNAME)/lib"
	$(INSTALL_DATA) lib/nsstats-sent.adp lib/nsstats-events.adp lib/nsstats.tcl "$(DESTDIR)$(INSTTCL)/$(MODNAME)/lib/"

test-admin:
	$(NS_TCLSH) tests/admin/data-findings.test
	$(NS_TCLSH) tests/admin/smtp-events.test
	$(NS_TCLSH) tests/admin/smtp-quarantine.test
	$(NS_TCLSH) tests/admin/registry.test

NS_LD_LIBRARY_PATH = LD_LIBRARY_PATH="./:$$LD_LIBRARY_PATH"
NSD                = $(NAVISERVER)/bin/nsd
NS_TCLSH           ?= $(NAVISERVER)/bin/tclsh
NS_TEST_CFG        = -c -d -t tests/config.tcl -u nsadmin
NS_TEST_ALL        = all.tcl $(TCLTESTARGS)
PEM_FILE           = tests/etc/server.pem

$(PEM_FILE):
	openssl genrsa 1024 > host.key
	openssl req -new -config tests/etc/nssmtpd.cnf -x509 -nodes -sha1 -days 365 -key host.key > host.cert
	cat host.cert host.key > server.pem
	rm -rf host.cert host.key
	openssl dhparam 1024 >> server.pem
	mv server.pem $(PEM_FILE)

.PHONY: test
test: all
	set -f; $(NS_TCLSH) tests/run-alias-tests.tcl --naviserver "$(NAVISERVER)" $(TCLTESTARGS)
lldbtest: all $(PEM_FILE)
	$(NS_LD_LIBRARY_PATH) lldb -- $(NSD) $(NS_TEST_CFG) $(NS_TEST_ALL)

tidy:
	clang-tidy-mp-16 *.c -- $(CFLAGS)

.PHONY: install-mcp-tools
install-mcp-tools:
	$(MKDIR) "$(DESTDIR)$(INSTTCL)/$(MODNAME)/mcp"
	$(INSTALL_DATA) mcp/smtp-tools.tcl "$(DESTDIR)$(INSTTCL)/$(MODNAME)/mcp/"

.PHONY: test-mcp
test-mcp:
	NSMCP_NAVISERVER="$(NAVISERVER)" $(NSD) -c -d $(NSDARGS) -t "$(CURDIR)/tests/mcp/config.tcl" "$(CURDIR)/tests/mcp/run.tcl"

.PHONY: install-mcp-example
install-mcp-example:
	$(MKDIR) "$(DESTDIR)$(INSTTCL)/$(MODNAME)/examples"
	$(INSTALL_DATA) examples/mcp-config.tcl "$(DESTDIR)$(INSTTCL)/$(MODNAME)/examples/"

# The MCP subsection is documented independently from the SMTP module settings.
.PHONY: mcp-parameters-include regen-mcp-parameters-include check-mcp-parameters
config-parameters-includes: mcp-parameters-include
mcp-parameters-include:
	@test -r doc/src/include/mcp-parameters.man || { echo "run make regen-config-parameters-includes"; exit 1; }
regen-config-parameters-includes: regen-mcp-parameters-include
regen-mcp-parameters-include:
	$(TCLSH_PROG) "$(DOC_TOOLS)/gen-config-parameters.tcl" --config "$(MODULE_CONFIG_PARAMETERS)" --section 'ns/server/*/module/nssmtpd/mcp' --output doc/src/include/mcp-parameters.man
check-config-parameters build-doc: check-mcp-parameters
check-mcp-parameters:
	$(TCLSH_PROG) "$(DOC_TOOLS)/gen-config-parameters.tcl" --config "$(MODULE_CONFIG_PARAMETERS)" --section 'ns/server/*/module/nssmtpd/mcp' --output doc/src/include/mcp-parameters.man --check

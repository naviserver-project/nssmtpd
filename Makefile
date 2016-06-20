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

TCL       = nssmtpd-procs.tcl
MODLIBS  += -lnssock


include  $(NAVISERVER)/include/Makefile.module

NS_LD_LIBRARY_PATH = LD_LIBRARY_PATH="./:$$LD_LIBRARY_PATH"
NSD                = $(NAVISERVER)/bin/nsd
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

test: all $(PEM_FILE)
	export $(NS_LD_LIBRARY_PATH); $(NSD) $(NS_TEST_CFG) $(NS_TEST_ALL)

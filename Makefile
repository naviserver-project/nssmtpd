ifndef NAVISERVER
    NAVISERVER  = /usr/local/ns
endif

#
# Module name
#
MOD      =  nssmtpd.so

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

include  $(NAVISERVER)/include/Makefile.module

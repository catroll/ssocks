# General settings

# Avoid install of this lib need to be static
#lib_LTLIBRARIES = libsocks.la
noinst_LTLIBRARIES = libsocks.la

libsocks_la_LDFLAGS = -version-info 1:0:0
libsocks_la_SOURCES = bor-util.c Makefile.am net-util.h output-util.h \
socks5-client.h socks5-server.h socks-common.h ssl-util.h \
bor-util.h net-util.c output-util.c socks5-client.c  \
socks5-server.c socks-common.c client.c log-util.c log-util.h \ 
client.c client.h

if WITH_SSL
libsocks_la_SOURCES += ssl-util.h ssl-util.c
endif

# Name of the static library
LDADDBASE = libsocks.la


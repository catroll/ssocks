AM_CFLAGS=-Wall 
bin_PROGRAMS = ssocksd nsocks ssocks

ssocks_SOURCES =  auth-util.c  bor-util.c  client.c  configd-util.c  \
log-util.c  net-util.c  output-util.c  socks5-client.c  socks5-server.c \
socks-common.c ssocks.c 

nsocks_SOURCES =  auth-util.c  bor-util.c  client.c  configd-util.c  \
log-util.c  net-util.c  output-util.c  socks5-client.c  socks5-server.c \
socks-common.c nsocks.c 

ssocksd_SOURCES =  auth-util.c  bor-util.c  client.c  configd-util.c  \
log-util.c  net-util.c  output-util.c  socks5-client.c  socks5-server.c \
socks-common.c ssocksd.c \
\
auth-util.h  bor-util.h  client.h  configd-util.h  log-util.h  net-util.h \
output-util.h  socks5-client.h  socks5-server.h  socks-common.h 


if WITH_SSL
ssocksd_SOURCES += ssl-util.h ssl-util.c
nsocks_SOURCES += ssl-util.h ssl-util.c
ssocks_SOURCES += ssl-util.h ssl-util.c
endif

# sysconf_DATA = ssocksd.conf ssocksd.auth

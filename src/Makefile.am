AM_CFLAGS=-Wall -std=gnu99 -O2 -Wextra
bin_PROGRAMS = nsocks ssocks ssocksd

ssocks_SOURCES = bor-timer.c bor-util.c client.c net-util.c \
socks5-client.c socks5-server.c ssocks.c output-util.c auth-util.c log-util.c socks5-common.c

nsocks_SOURCES = bor-timer.c bor-util.c client.c net-util.c \
nsocks.c socks5-client.c socks5-server.c output-util.c auth-util.c \
ssl-util.c log-util.c socks5-common.c

ssocksd_SOURCES = bor-timer.c bor-util.c client.c net-util.c \
socks5-client.c socks5-server.c ssocksd.c output-util.c auth-util.c  \
log-util.c configd-util.c socks5-common.c auth-util.h bor-timer.h bor-util.h \
client.h configd-util.h log-util.h net-util.h output-util.h \
ssl-util.h ssl-util.c \
socks5-client.h socks5-server.h socks5-common.h ssocksd.conf ssocksd.auth  

sysconf_DATA = ssocksd.conf ssocksd.auth

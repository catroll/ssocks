/*
 *      socks5-common.h
 *
 *      Created on: 2011-03-31
 *      Author:     Hugo Caron
 *      Email:      <h.caron@codsec.com>
 *
 * Copyright (C) 2011 by Hugo Caron
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#ifndef SOCKS5_COMMON__H
#define SOCKS5_COMMON__H

#include "client.h"

#include <config.h>
#include <stdint.h>

#define SOCKS5_V 0x05
#define SOCKS5_SSL_V 0x06

/* Client state */
enum {
	E_R_VER,		/* Read version */
	E_W_VER,		/* Write version */
	E_R_VER_ACK,	/* Read version ACK */
	E_W_VER_ACK,	/* Write version ACK */

	E_R_AUTH,		/* Read authentication */
	E_W_AUTH,		/* Write authentication ACK */
	E_R_AUTH_ACK,	/* Read authentication */
	E_W_AUTH_ACK,	/* Write authentication ACK */

	E_R_REQ,		/* Read authentication */
	E_W_REQ,		/* Write authentication */
	E_R_REQ_ACK,	/* Read authentication ACK */
	E_W_REQ_ACK,	/* Write authentication ACK */

	E_REPLY,		/* Read on a socket, write a another */

	E_WAIT			/* Nothing to do just wait */
};



 /* Socks5 version packet */
typedef struct {
	char ver;
	char nmethods;
	char methods[5];
} Socks5Version;

/* Socks5 version packet ACK */
typedef struct {
	char ver;
	char method;
} Socks5VersionACK;

/* Socks5 authentication packet */
typedef struct {
	char ver;
	char ulen;
	char uname[256];
	char plen;
	char passwd[256];
} Socks5Auth;

/* Socks5 authentication packet ACK */
typedef struct {
	char ver;
	char status;
} Socks5AuthACK;

/* Socks5 request packet */
typedef struct {
	char ver;
	char cmd;
	char rsv;
	char atyp;
	/*char dstadr;
	unsigned short dstport;*/
} Socks5Req;

/* Socks5 request packet ACK
 * Need to change alignment 4 -> 2  else sizeof 12 instead of 10 */
#pragma pack(push, 2) /* Change alignment 4 -> 2 */
typedef struct {
	char ver;
	char rep;
	char rsv;
	char atyp;
	struct in_addr bndaddr; /* uint32_t */
	uint16_t  bndport;
} Socks5ReqACK;
#pragma pack(pop) /* End of change alignment */

/* Configuration dynamic for ssocks */
typedef struct {
	char *host;	/* Socks you want to be connected */
	int port;	/* Its port */
	char *uname; /* Username for authentication can be NULL */
	char *passwd; /* Password for authentication can be NULL */
} ConfigDynamic;


void read_server (Client *c);
void write_server (Client *c);

void read_client (Client *c);
void write_client (Client *c);


#endif /* SOCKS5_COMMON__H */

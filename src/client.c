/*
 *      client.c
 *      
 *      Created on: 2011-03-30
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
#include "socks5-common.h" /* load client.h */
#include "output-util.h"
#include "log-util.h"
#include "net-util.h"

#include <stdarg.h>
#include <limits.h>

/* Init the client structure
 *  - id in tc table
 *  - mode = M_SERVER, M_CLIENT define in client.h
 *  - config can be NULL
 */
void init_client (Client *c, int id, int mode, int ver, void *config)
{
	/* Position in tc table */
    c->id = id;

    /* Default value for sockets -1 */
    c->soc = c->soc_stream = c->soc_bind = -1;

    c->req[0] = 0;
    c->req_a = c->req_b = c->req_pos = 0;
    
    /* Start with no authentication set */
    c->auth = 0x00;
    c->ver = ver;

    /* First state in server mode */
    c->state = E_R_VER;

    /* First state in client mode */
    c->stateC = E_W_VER;

    c->mode =  mode;
	
	/* Don't need to set buf_stream[0] and buf_client[0]
	 * at zero, only binary data */
	c->buf_stream_a = c->buf_stream_b =  c->buf_stream_w = 0;
	c->buf_client_a = c->buf_client_b =  c->buf_client_w = 0;

	c->config = config;

	/* We need to start a '\0' beceause we append string in */
	c->buf_log[0] = 0;
	
#ifdef HAVE_LIBSSL
	c->ctx = NULL;
	c->ssl = NULL;
#endif
}

/* Disconnection */
void disconnection(Client *c) {

	if ( c->mode == M_CLIENT || c->mode == M_CLIENT_BIND ){
		TRACE(L_VERBOSE, "client: disconnected server ...");
		if ( c->soc_stream != -1 ) { close(c->soc_stream); c->soc_stream = -1; }
		if ( c->ver == SOCKS5_SSL_V ) { ssl_close(c->ssl); c->ssl = NULL; }
	}else{
		writeLog(c->buf_log);
		TRACE(L_VERBOSE, "server [%d]: disconnected client ...", c->id);
		raz_client (c);
	}
}

/* Append log in the client log buffer, written in connection end.
 * TODO: Look if overflow possible here
 */
void append_log_client(Client *c, char *template, ...){
	va_list ap;
	va_start(ap, template);
	int len = strlen(c->buf_log);
	len += vsnprintf(c->buf_log + len, sizeof(c->buf_log) - len , template, ap);
	snprintf(c->buf_log + len, sizeof(c->buf_log) - len, " | ");
	va_end(ap);	
}

/* Reset client structure
 */
void raz_client (Client *c){
    if ( c->soc  != -1) close (c->soc);
	if ( c->soc_stream != -1 ) close(c->soc_stream);
	if ( c->soc_bind != -1 ) close(c->soc_bind);
	if ( c->ver == SOCKS5_SSL_V ) { ssl_close(c->ssl); }
    /* bor_timer_remove(tc[nc].handle); */
    init_client (c, c->id, c->mode, c->ver, c->config);
}

/* Used in ssocks a experimental tool ...
 */
void init_select_dynamic (int soc_ec, Client *tc, int *maxfd,
		fd_set *set_read, fd_set *set_write)
{
    int nc;
    
    FD_ZERO (set_read);
    FD_ZERO (set_write);
    FD_SET (soc_ec, set_read);

    *maxfd = soc_ec;
    for (nc = 0; nc < MAXCLI; nc++){
        if (tc[nc].soc != -1) {
        	if (tc[nc].state == E_R_VER
				|| tc[nc].state == E_R_REQ
				|| tc[nc].state == E_R_AUTH){
        		FD_SET (tc[nc].soc, set_read);
        	/* Write flag on add in set_write */
        	}else if (tc[nc].buf_client_w == 1
        			|| (tc[nc].req_b - tc[nc].req_a) > 0){
				FD_SET (tc[nc].soc, set_write);
			/* if we don't write we can read if we have space */
			}else if (tc[nc].state == E_WAIT){

			}else if (tc[nc].buf_stream_b <
					(int)(sizeof(tc[nc].buf_stream) - 1)){
				FD_SET (tc[nc].soc, set_read);
			}
			
            if (tc[nc].soc > *maxfd) *maxfd = tc[nc].soc;
        }
        if (tc[nc].soc_stream != -1) {
			FD_SET (tc[nc].soc_stream, set_read);
			if (tc[nc].soc_stream > *maxfd) *maxfd = tc[nc].soc_stream;
			
			if ( tc[nc].stateC == E_W_VER
					|| tc[nc].stateC == E_W_AUTH
					|| tc[nc].stateC == E_W_REQ
					|| (tc[nc].stateC == E_REPLY && tc[nc].buf_stream_w == 1) ){
				FD_SET (tc[nc].soc_stream, set_write);
				if (tc[nc].soc_stream > *maxfd) *maxfd = tc[nc].soc_stream;
			}
        }
	}
}

/* Build fd_set for select
 */
void init_select (int soc_ec, Client *tc, int *maxfd,
		fd_set *set_read, fd_set *set_write)
{
    int nc;
    
    FD_ZERO (set_read);
    FD_ZERO (set_write);
    FD_SET (soc_ec, set_read);

    *maxfd = soc_ec;
    for (nc = 0; nc < MAXCLI; nc++){
    	/* TODO: Fix init_select, do this more proper is the key of select.
    	 * Many bugs can come from here.
    	 * For now seen to be good,one doubt on
    	 * state E_WAIT in set_read
    	 * ( remember: I do this to block on select
    	 * and wake up with signal USR1) */
        if (tc[nc].soc != -1) { /* Ugly code! */

        	if (tc[nc].state == E_R_VER
				|| tc[nc].state == E_R_REQ
				|| tc[nc].state == E_R_AUTH
				|| tc[nc].state == E_WAIT){
        		FD_SET (tc[nc].soc, set_read);
        	/* Write flag on add in set_write */
        	}else if (tc[nc].buf_client_w == 1
        			|| (tc[nc].req_b - tc[nc].req_a) > 0){
				FD_SET (tc[nc].soc, set_write);
			/* if we don't write we can read if we have space */
			}else if (tc[nc].buf_stream_b <
					(int)(sizeof(tc[nc].buf_stream) - 1)){
				FD_SET (tc[nc].soc, set_read);
			}
            if (tc[nc].soc > *maxfd) *maxfd = tc[nc].soc;
        }

        /* Stream wanted by the client */
        if (tc[nc].soc_stream != -1) {
        	/* Write flag on add in set_write */
			if (tc[nc].buf_stream_w == 1)
				FD_SET (tc[nc].soc_stream, set_write);
			/* if we don't write we can read if we have space */
			else if (tc[nc].buf_client_b <
					(int)(sizeof(tc[nc].buf_client) - 1))
				FD_SET (tc[nc].soc_stream, set_read);

            if (tc[nc].soc_stream > *maxfd) *maxfd = tc[nc].soc_stream;
        }

        /* Socket in server mode (binding connection)
         * in set_read to wait new connection */
        if (tc[nc].soc_bind != -1) {
			FD_SET (tc[nc].soc_bind, set_read);
            if (tc[nc].soc_bind > *maxfd) *maxfd = tc[nc].soc_bind;
        }
	}
}

/* Deal with a new client
 * Accept connection
 * Search a eligible space in tc[], assign the new client
 * to this space and set socket in non blocking
 * If no more space close socket.
 */
int new_connection (int soc_ec, Client *tc){
    int nc, soc_tmp;
    struct sockaddr_in adrC_tmp;
    
    TRACE(L_DEBUG, "server: connection in progress ...");
    soc_tmp = bor_accept_in (soc_ec, &adrC_tmp);
    if (soc_tmp < 0) { return -1; }
    
    /* Search free space in tc[].soc */
    for (nc = 0; nc < MAXCLI; nc++) 
        if (tc[nc].soc == -1) break;
    if (nc < MAXCLI) {
        tc[nc].soc = soc_tmp;
        memcpy (&tc[nc].addr, &adrC_tmp, sizeof(struct sockaddr_in));
        TRACE(L_VERBOSE, "server [%d]: established connection with %s", 
            nc, bor_adrtoa_in(&adrC_tmp));
        
        append_log_client(&tc[nc], "%s", bor_adrtoa_in(&adrC_tmp));
		//set_non_blocking(tc[nc].soc);
    } else {
        close (soc_tmp);
        ERROR (L_NOTICE, "server: %s connection refused : too many clients!", 
            bor_adrtoa_in(&adrC_tmp));
    }

    return 0;
}

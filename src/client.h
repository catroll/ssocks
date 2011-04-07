/*
 *      client.h
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
#ifndef CLIENT__H
#define CLIENT__H

#include "bor-timer.h"
#include "bor-util.h"

#define MAXCLI 128
#define BUFFER_SIZE 4096

/* Operating mode
 */
enum{
	M_SERVER, /* Server mode used by ssocksd */

	M_CLIENT, /* Client mode used by nsocks and ssocks */

	M_CLIENT_BIND, /* Client mode with bind request,
				    * used by nsocks and ssocks */

	M_DYNAMIC, /* Run a server and listen, when it receive data
				* it transmit it to a another socks server,
				* used by ssocks */
};

/* TODO: Do some cleaning on client struct
 * Need to remove buffer req I thinks
 *
 * This structure is used in client/server mode for this
 * it've a mode flag that define rules to follow
 */
typedef struct {
    struct sockaddr_in addr,  		/* Client address */
					   addr_stream,  /* Stream address */
					   addr_dest;    /* Dest address */

    int soc;                 		/* Client socket, default -1 */
	int soc_stream; 				/* Stream socket, default -1  */
	int soc_bind; 					/* Bind socket, default -1, in binding
									*  mode is a server sockets */

    int id;							/* ID in tc table */

    char auth;				/* Auth method define during the version check */
    int state;				/* Server state, define in socks5-common.h ...*/
    int stateC;				/* Client state, define in socks5-common.h */
    int mode;				/* Operating mode: M_SERVER, M_CLIENT, M_DYNAMIC */
	
    char req[BUFFER_SIZE];
    int req_a, req_b, req_pos;

    /* Buffer used when it relay data from stream to client.
     * buf_client_w is write flag 1 when data in buffer */
	char buf_client[BUFFER_SIZE];
	int buf_client_a, buf_client_b, buf_client_w;

	/* Buffer used when it relay data from client to stream.
	 * buf_stream_w is write flag 1 when data in buffer*/
	char buf_stream[BUFFER_SIZE];
	int buf_stream_a, buf_stream_b, buf_stream_w;

	char buf_log[1024]; 	/* Buffer for log file */

	void *config; 			/* Configuration data pointer
							 * used in client mode (nsocks and ssocks) */
} Client;

void append_log_client(Client *c, char *template, ...);

void init_client (Client *tc, int nc, int mode, void *config);
void raz_client (Client *c);
void disconnection(Client *c) ;
int new_connection (int soc_ec, Client *tc);

void init_select (int soc_ec, Client *tc, int *maxfd,
		fd_set *set_read, fd_set *set_write);

void init_select_dynamic (int soc_ec, Client *tc, int *maxfd,
		fd_set *set_read, fd_set *set_write);



#endif /* CLIENT__H */

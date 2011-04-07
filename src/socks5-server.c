/*
 *      socks5-server.c
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
#include "socks5-server.h"
#include "socks5-common.h"

#include "net-util.h"
#include "output-util.h"
#include "auth-util.h"
#include "log-util.h"
#include "configd-util.h"

#include <config.h> /* HAVE_LIBPTHREAD */

#ifdef HAVE_LIBPTHREAD
	#include <pthread.h>
#endif

void dispatch_server (Client *c){
	switch(c->state){
		case E_R_VER: read_version(c); break;
		case E_W_VER_ACK: write_version_ack(c); break;
		case E_R_AUTH: read_auth(c); break;
		case E_W_AUTH_ACK: write_auth_ack(c); break;
		case E_R_REQ:
			if ( c->mode == M_DYNAMIC) /* Used by ssocks */
				read_request_dynamic(c);
			else
				read_request(c);
			break;
		case E_W_REQ_ACK: write_request_ack(c); break;
		case E_REPLY :
			(c->buf_client_w == 1) ? write_server(c) : read_server(c);
			break;
		default : break;
	}

}


/* Read the client version and build the ack in buffer req
 *
 * Version packet:
 *	+----+----------+----------+
 *	|VER | NMETHODS | METHODS  |
 *	+----+----------+----------+
 *	| 1  |    1     | 1 to 255 |
 *	+----+----------+----------+
 *
 * Version ack packet:
 *	+----+--------+
 *	|VER | METHOD |
 *	+----+--------+
 *	| 1  |   1    |
 *	+----+--------+
 *
 */
void read_version (Client *c){
    int k, i, ok = 0;

    /* Warm if the buffer is full, the third parameter read goes to 0,
     * so read return 0 as a disconnection */
    TRACE(L_DEBUG, "server [%d]: read version ...", c->id);
    k = read (c->soc,
              c->req+c->req_pos,
              sizeof(c->req)-c->req_pos-1);
	if (k < 0) { perror ("read version"); disconnection (c); return; }
	if (k == 0) { 
		ERROR(L_VERBOSE, "server: maybe buffer is full"); 
		disconnection (c);
		return; 
	}
	TRACE(L_DEBUG, "server [%d]: read %d bytes", c->id, k);
    
    c->req_pos += k;

    /* Maybe dangerous if lot of methods */
    if ( (unsigned int)c->req_pos >= 3 ){
		TRACE(L_DEBUG, "server [%d]: testing version ...", c->id);
		
		Socks5Version req;
		Socks5VersionACK res;

		/* Version packet:
		 *	+----+----------+----------+
		 *	|VER | NMETHODS | METHODS  |
		 *	+----+----------+----------+
		 *	| 1  |    1     | 1 to 255 |
		 *	+----+----------+----------+
		 */
		memcpy(&req, c->req, sizeof(Socks5Version));
		TRACE(L_DEBUG, "server [%d]: v0x%x, nmethod 0x%02X", c->id, req.ver,
				req.nmethods);

		/* If too much method we truncate */
		if (sizeof(req.methods) < (unsigned int)req.nmethods){
			ERROR(L_VERBOSE, "server [%d]: truncate methods", c->id);
			req.nmethods = sizeof(req.methods);
		}
		
		/* Show only in debug mode */
		if ( L_DEBUG <= verbosity ){
			printf("server [%d]: ", c->id);
		}

		/* Copy in methods the methods in the packet
		 * memcpy can do the trick too */
		for (i=0; i <  req.nmethods; ++i){
			req.methods[i] = *(c->req + 2 + i );
			/* Show only in debug mode */
			if ( L_DEBUG <= verbosity ){
				printf("0x%02X,",req.methods[i]);
			}
		}

		/* Show only in debug mode */
		if ( L_DEBUG <= verbosity ){
			printf("\n");
		}
		
		/* Testing version */
		if(req.ver == SOCKS5_V){
#ifdef HAVE_LIBSSL
		}else if (globalArgsServer.ssl == 1 && req.ver == SOCKS5_SSL_V){
#endif
		}else{
			ERROR(L_NOTICE, "server [%d]: wrong socks5 version", c->id);
			disconnection (c);
			return;
		}

		c->ver = req.ver;
		
		/* Searching valid methods:
		 * Methods 0x00, no authentication
		 *         0x01, GSSAPI no supported
		 *         0x02, username/password RFC1929
		 *
		 * if method == no authentication
		 * 		if guest available
		 * 			set it
		 * 			stop searching
		 * if method == username password
		 * 		set it
		 * 		stop searching
		 * */
		for (i=0; i <  req.nmethods; ++i){
			if ( req.methods[i] == 0x00){
				/* In ssocks ( DYNAMIC_MODE no globalArgsServer */
				if ( c->mode == M_DYNAMIC || globalArgsServer.guest != 0 ){
					ok = 1;
					c->auth = req.methods[i];
					break;
				}
			}
			if ( req.methods[i] == 0x02 ){
				ok = 1;
				c->auth = req.methods[i];
				break;
			}
		}
		
		/* No valid method find */
		if ( !ok ){
			ERROR(L_NOTICE, "server [%d]: no method supported", c->id);
			disconnection (c);
			return;
		}


		/*
		 * Version ack packet:
		 *	+----+--------+
		 *	|VER | METHOD |
		 *	+----+--------+
		 *	| 1  |   1    |
		 *	+----+--------+
		 *
		 *  Build ack */
		res.ver = c->ver;
		res.method = c->auth;
		
		/* Copy in buffer for send */
		memcpy(c->req, &res, sizeof(Socks5VersionACK));
		
		/* Reset counter and fix b flag */
		c->req_pos = 0;
		c->req_a = 0;
		c->req_b = sizeof(Socks5VersionACK);

		/* Next state write version ack */
		c->state = E_W_VER_ACK;
	}
    return;
}

/* Write the version ack build by read_version
 */
void write_version_ack (Client *c){
	int k = 0;
	
	TRACE(L_DEBUG, "server [%d]: write version ack ...", c->id);
    if (c->req_b-c->req_a > 0) {
        k = write (c->soc, c->req+c->req_a, c->req_b-c->req_a);
        if (k < 0) { perror ("write socket"); disconnection (c); return; }
        TRACE(L_DEBUG, "server [%d]: wrote %d bytes", c->id, k);
        c->req_a += k;
    }

    if (c->req_b-c->req_a <= 0) {

#ifdef HAVE_LIBSSL
		/* Init SSL here
		 */
		if ( c->ver == SOCKS5_SSL_V){
			//set_blocking(c->soc);
			TRACE(L_DEBUG, "server [%d]: socks5 ssl enable ...", c->id);
			c->ssl = ssl_neogiciate_server(c->soc);
			if ( c->ssl == NULL ){
				ERROR(L_VERBOSE, "server [%d]: ssl error", c->id);
				disconnection (c);
				return;
			}
		}
#endif

		if ( c->auth == 0x02 ) /* Username/Password authentication */
			/* Next state read authentication */
			c->state = E_R_AUTH;
		else{
			/* Next state read request */
			c->state = E_R_REQ;
			append_log_client(c, "anonymous");
		}
    }
}

/* Read authentication packet and check username/password
 * and build the ack in buffer req
 *
 * RFC 1929
 *
 * Authentication packet:
 *	+----+------+----------+------+----------+
 *	|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
 *	+----+------+----------+------+----------+
 *	| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
 *	+----+------+----------+------+----------+
 *
 * Authentication ack packet:
 *	+----+--------+
 *	|VER | STATUS |
 *	+----+--------+
 *	| 1  |   1    |
 *	+----+--------+
 */
void read_auth (Client *c){
    int k = 0, ok = 0;

    TRACE(L_DEBUG, "server [%d]: read authentication uname/passwd ...", c->id);
	if ( c->ver == SOCKS5_SSL_V){
#ifdef HAVE_LIBSSL
	    k = SSL_read (c->ssl,
	              c->req+c->req_pos,
	              sizeof(c->req)-c->req_pos-1);
#endif
	}else{
	    k = read (c->soc,
	              c->req+c->req_pos,
	              sizeof(c->req)-c->req_pos-1);
	}
	if (k < 0) { perror ("read socket"); disconnection (c); return; }
	if (k == 0) { 
		ERROR(L_VERBOSE, "server: maybe buffer is full"); 
		disconnection (c);
		return; 
	}
	TRACE(L_DEBUG, "server [%d]: read %d bytes", c->id, k);
    

    c->req_pos += k;
    if ( (unsigned int)c->req_pos >= 4 ){
		TRACE(L_DEBUG, "server [%d]: testing authentication ...", c->id);
		
		Socks5Auth req;
		Socks5AuthACK res;

		/* Rebuild the packet in Socks5Auth struct
		 *  +----+------+----------+------+----------+
		 *	|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
		 *	+----+------+----------+------+----------+
		 *	| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
		 *	+----+------+----------+------+----------+
		 */
		memcpy(&req, c->req, 2);
		memcpy(&req.plen, c->req + 2 + (int)req.ulen , 2);

		/* Check username and password length truncate if too long
		 * RFC tell us max length 255 */
		if ( (unsigned int)req.ulen > sizeof(req.uname)-1){
			ERROR(L_NOTICE, "server [%d]: username too long", c->id);
			req.ulen = sizeof(req.uname)-1;
		}
		if ( (unsigned int)req.plen > sizeof(req.passwd)-1){
			ERROR(L_NOTICE, "server [%d]: password  too long", c->id);
			req.plen = sizeof(req.passwd)-1;
		}

		/* Extract username and fix NULL byte */
		strncpy(req.uname, c->req + 2, req.ulen);
		*(req.uname + req.ulen) = '\0';

		/* Extract passwd and fix NULL byte */
		strncpy(req.passwd, c->req + 2 + (int)req.ulen + 1, req.plen);
		*(req.passwd + req.plen) = '\0';
		
		TRACE(L_VERBOSE, "server [%d]: authentication attempt v0x%02X (%d,%d) %s:%s", 
			c->id, req.ver, req.ulen, req.plen, req.uname, req.passwd);
		
		/* Test version need 0x01 RFC */
		if ( req.ver != 0x01 ){
			ERROR(L_NOTICE, "server [%d]: wrong version need to be 0x01", c->id);
			disconnection (c);
			return;
		}
		
		/* Check username and password in authentication file */
		if ( check_auth(req.uname, req.passwd) == 1 ){
			TRACE(L_VERBOSE, "server [%d]: authentication OK!", c->id);
			append_log_client(c, "%s OK", req.uname);
			ok = 1;
		}else{
			ERROR(L_VERBOSE, "server [%d]: authentication NOK!", c->id);
			append_log_client(c, "%s NOK", req.uname);
		}
		
		/* Build ack
		 *  +----+--------+
		 *	|VER | STATUS |
		 *	+----+--------+
		 *	| 1  |   1    |
		 *	+----+--------+
		 */
		res.ver = 0x01;
		res.status = (ok) ? 0x00 : 0xFF; /* 0x00 == win! */
		
		/* Copy in buffer for send */
		memcpy(c->req, &res, sizeof(Socks5AuthACK));
		
		/* Reset counter and fix b flag */
		c->req_pos = 0;
		c->req_a = 0;
		c->req_b = sizeof(Socks5AuthACK);

		/* Next state write auth ack */
		c->state = E_W_AUTH_ACK;
	}
    return;	
}
/* Write the authentication ack build by read_auth
 */
void write_auth_ack (Client *c){
	int k = 0;
	
	TRACE(L_DEBUG, "server [%d]: write version ack ...", c->id);
    if (c->req_b-c->req_a > 0) {
		if ( c->ver == SOCKS5_SSL_V){
#ifdef HAVE_LIBSSL
			k = SSL_write(c->ssl, c->req+c->req_a, c->req_b-c->req_a);
#endif
		}else{
			k = write (c->soc_stream, c->req+c->req_a, c->req_b-c->req_a);
		}
        if (k < 0) { perror ("write socket"); disconnection (c); return; }
        TRACE(L_DEBUG, "server [%d]: wrote %d bytes", c->id, k);
        c->req_a += k;
    }

    if (c->req_b-c->req_a <= 0){
    	c->buf_client_w = 0;
    	/* Next state read request */
		c->state = E_R_REQ;
	}
}

void *thr_process_request( void *client ){
		Client *c = (Client *)client;


		TRACE(L_DEBUG, "server [%d]: testing client request ...", c->id);

		int ok = 0;
		char domain[256];
		int port = 0;

		unsigned char chAddr[4];
		unsigned int l;
		int *p;

		Socks5Req req;
		Socks5ReqACK res;

		/* Rebuild the packet but don't extract
		 * DST.ADDR and DST.PORT in Socks5Req struct
		 *	+----+-----+-------+------+----------+----------+
		 *	|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
		 *	+----+-----+-------+------+----------+----------+
		 *	| 1  |  1  | X'00' |  1   | Variable |    2     |
		 *	+----+-----+-------+------+----------+----------+
		 *
		 */
		memcpy(&req, c->req, sizeof(Socks5Req));
		TRACE(L_DEBUG, "server [%d]: v0x%x, cmd 0x%x, rsv 0x%x, atyp 0x%x", c->id, req.ver,
			req.cmd, req.rsv, req.atyp);
		
		/* Check ATYP
		 * ATYP address type of following address
         *    -  IP V4 address: X'01'
         *    -  DOMAINNAME: X'03'
         *    -  IP V6 address: X'04'
		 *
		 */
		switch ( req.atyp ){
			case 0x03: /* Domain name */
				/* First byte is the domain len */
				l = *(c->req + sizeof(Socks5Req)) ;

				/* Copy the domain name and blank at end
				 * little cheat to avoid overflow (dangerous here) */
				strncpy(domain, c->req + sizeof(Socks5Req) + 1,
						( l < sizeof(domain) ) ? l : sizeof(domain)-1 );
				domain[(int)l] = 0;
				
				/* After domain we have the port
				 * big endian on 2 bytes*/
				p = (int*)(c->req + sizeof(Socks5Req) + l  + 1) ;
				port = ntohs(*p);
				
				/*printf("Server [%d]: asking for %s:%d\n", c->id, domain, port);*/
				break;

			case 0x01: /* IP address */
				memcpy(&chAddr, (c->req + sizeof(Socks5Req)), sizeof(chAddr));
				sprintf(domain, "%d.%d.%d.%d", chAddr[0],
					chAddr[1], chAddr[2], chAddr[3]);
					
				/* After domain we have the port
				 * big endian on 2 bytes*/
				p = (int*)(c->req + sizeof(Socks5Req) + 4  ) ;
				port = ntohs(*p);
				break;

			/* TODO: ipv6 support */
			default:
				ERROR(L_NOTICE, "server [%d]: support domain name and ipv4 only", c->id);
				disconnection (c);

#ifdef HAVE_LIBPTHREAD
				pthread_exit(NULL);
#else
				return NULL;
#endif

		}

		append_log_client(c, "v%d %s:%d", c->ver, domain, port);

		/* Request ack packet:
		 *	+----+-----+-------+------+----------+----------+
		 *	|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
		 *	+----+-----+-------+------+----------+----------+
		 *	| 1  |  1  | X'00' |  1   | Variable |    2     |
		 *	+----+-----+-------+------+----------+----------+
		 *  Build ack */
		res.ver = SOCKS5_V;/*c->ver*/;
		res.rsv = 0;
		res.atyp = 0x01;

		/* CMD:
         *  - CONNECT X'01'
         *  - BIND X'02'
         *  - UDP ASSOCIATE X'03'
		 *
		 * Open or bind connection here
		 */
		switch(req.cmd){
			case 0x01: /* TCP/IP Stream connection */

				c->soc_stream = new_client_socket(domain, port, &c->addr_stream, &c->addr_dest);
				if ( c->soc_stream >= 0 ){
					append_log_client(c, "CONNECT");
					ok = 1;
					/* In the reply to a CONNECT, BND.PORT contains the port number that the
					 * server assigned to connect to the target host, while BND.ADDR
					 * contains the associated IP address.
					 */
					TRACE(L_DEBUG, "client: assigned addr %s", bor_adrtoa_in(&c->addr_stream));
					memcpy(&res.bndaddr, &c->addr_stream.sin_addr.s_addr,
							sizeof(c->addr_stream.sin_addr.s_addr));
					memcpy(&res.bndport, &c->addr_stream.sin_port,
							sizeof(c->addr_stream.sin_port));

					/*DUMP(&c->adr_stream.sin_addr.s_addr, sizeof(c->adr_stream.sin_addr.s_addr));
					DUMP(&c->adr_stream.sin_port, sizeof(c->adr_bind.sin_port));
					DUMP(&c->adr_bind.sin_addr.s_addr, sizeof(c->adr_bind.sin_addr.s_addr));
					DUMP(&c->adr_bind.sin_port, sizeof(c->adr_bind.sin_port));*/
				}
				break;
			case 0x02: /* TCP/IP port binding */
				c->soc_bind = new_listen_socket(port, 10);
				if ( c->soc_bind >= 0 ){
					append_log_client(c, "BIND");
					ok = 1;
					/* TODO: Need to set bndaddr and bndport in port binding see RFC
					 * The BND.PORT field contains the port number that the
				     * SOCKS server assigned to listen for an incoming connection.  The
				     * BND.ADDR field contains the associated IP address.
				     */


				}

				break;
			/* TODO: udp support */
			default :
				append_log_client(c, "ERROR request cmd");
				ERROR(L_NOTICE, "server [%d]: don't support udp", c->id);
				disconnection (c);
#ifdef HAVE_LIBPTHREAD
				pthread_exit(NULL);
#else
				return NULL;
#endif
		}

		/* 0x00 succeeded, 0x01 general SOCKS failure ... */
		res.rep = (ok == 1) ? 0x00 : 0x01;
		
		/* Copy in buffer for send */
		memcpy(c->req, &res, sizeof(Socks5ReqACK));

		/* Reset counter and fix b flag */
		c->req_pos = 0;
		c->req_a = 0;
		c->req_b = sizeof(Socks5ReqACK);

		/* Next state write request ack */
		c->state = E_W_REQ_ACK;

		/* TODO: need to find a better way to exit select
		 * Send signal SIGUSER1 to the parent thread to unblock select */
		if ( kill(getpid(), SIGUSR1) != 0 )
			perror("kill");

#ifdef HAVE_LIBPTHREAD
				pthread_exit(NULL);
#else
				return NULL;
#endif
}

/* Read request packet and test it, create connection
 * and build the ack in buffer req
 *
 * Request packet:
 *	+----+-----+-------+------+----------+----------+
 *	|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
 *	+----+-----+-------+------+----------+----------+
 *	| 1  |  1  | X'00' |  1   | Variable |    2     |
 *	+----+-----+-------+------+----------+----------+
 *
 * Request ack packet:
 *	+----+-----+-------+------+----------+----------+
 *	|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
 *	+----+-----+-------+------+----------+----------+
 *	| 1  |  1  | X'00' |  1   | Variable |    2     |
 *	+----+-----+-------+------+----------+----------+
 *
 * See RFC 1928 / 4.  Requests for full information
 */
void read_request (Client *c){
	int k = 0;

    TRACE(L_DEBUG, "server [%d]: read client request ...", c->id);
	if ( c->ver == SOCKS5_SSL_V){
#ifdef HAVE_LIBSSL
	    k = SSL_read (c->ssl,
	              c->req+c->req_pos,
	              sizeof(c->req)-c->req_pos-1);
#endif
	}else{
	    k = read (c->soc,
	              c->req+c->req_pos,
	              sizeof(c->req)-c->req_pos-1);
	}
	if (k < 0) { perror ("read socket"); disconnection (c); return; }
	if (k == 0) {
		ERROR(L_VERBOSE,  "server: maybe buffer is full");
		disconnection (c);
		return;
	}
	TRACE(L_DEBUG, "server [%d]: read %d bytes", c->id, k);

    c->req_pos += k;
    if ( c->req_pos >= (int)(sizeof(Socks5Req)  + 4) ){

#ifdef HAVE_LIBPTHREAD
    	/* This avoid to block all socks client when we do a connection */
    	pthread_t thr;
    	pthread_create( &thr, NULL, thr_process_request, (void*) c);

    	/* We never join this thread, to notify the end
    	 * it send a signal SIGUSR1 */
    	pthread_detach(thr);

    	/* Next state wait end of thr_process_request */
		c->state = E_WAIT;
#else
		thr_process_request((void*) c);
#endif

	}
}

/* Used by ssocks not in the server
 */
void read_request_dynamic (Client *c){
	int k = 0;

	TRACE(L_DEBUG, "server [%d]: read dynamic client request ...", c->id);
	k = read (c->soc, 
			  c->buf_stream+c->buf_stream_b, 
			  sizeof(c->buf_stream)-c->buf_stream_b-1);
	if (k < 0) { perror ("read socket"); disconnection (c); return; }
	if (k == 0) { 
		ERROR(L_VERBOSE, "server [%d]: maybe buffer is full", c->id);
		disconnection (c);
		return; 
	}
	TRACE(L_DEBUG, "server [%d]: read %d bytes", c->id, k);
   
    c->buf_stream_b += k;
    if ( c->buf_stream_b-c->buf_stream_a >= (int)(sizeof(Socks5Req)  + 4) ){
		TRACE(L_DEBUG, "server [%d]: testing dynamic client request ...", c->id);

		if ( c->config == NULL ){
			ERROR(L_NOTICE, "server [%d]: no config", c->id);
			disconnection (c); return;
		}

		TRACE(L_DEBUG, "server [%d]: try to connect on %s:%d ...",c->id,
			((ConfigDynamic*)c->config)->host, 
			((ConfigDynamic*)c->config)->port);
		
		c->soc_stream = new_client_socket(((ConfigDynamic*)c->config)->host, 
			((ConfigDynamic*)c->config)->port, &c->addr_stream, &c->addr_dest);
		if ( c->soc_stream < 0 ){
			disconnection (c); return;
		}
		
		c->req_a = 0;
		c->req_b = 0;

		c->state = E_WAIT;
		//c->stateC = E_W_VER_ACK;
	}
    return;
}

/* Write the request ack build by read_request
 */
void write_request_ack (Client *c){
	int k = 0;
	
	TRACE(L_DEBUG, "server [%d]: send request ack ...", c->id);
    if (c->req_b-c->req_a > 0) {
		if ( c->ver == SOCKS5_SSL_V){
#ifdef HAVE_LIBSSL
			k = SSL_write(c->ssl, c->req+c->req_a, c->req_b-c->req_a);
#endif
		}else{
			k = write (c->soc, c->req+c->req_a, c->req_b-c->req_a);
		}
        if (k < 0) { perror ("write socket"); disconnection (c); return; }
        TRACE(L_DEBUG, "server [%d]: send %d bytes", c->id, k);
        c->req_a += k;
    }

    if (c->req_b-c->req_a <= 0){
    	/* Next state recv  */
		c->state = E_REPLY;
		c->buf_client_w = 0; // ??
	}
}



/* Accept new connection and send request on soc_stream of the client
 * Build the second request
 * See RFC
 */
void build_request_bind(Client *c){
	TRACE(L_VERBOSE, "server [%d]: build binding packet ...", c->id);
	struct sockaddr_in adrC_tmp;

	Socks5ReqACK res;
	int ok = 1;
	
	c->soc_stream  = bor_accept_in (c->soc_bind, &adrC_tmp);
	if (c->soc_stream < 0) { disconnection (c); return; }
	TRACE(L_DEBUG, "server: established connection with %s", 
	bor_adrtoa_in(&adrC_tmp));

	append_log_client(c, "ACCEPT %s", bor_adrtoa_in(&adrC_tmp));
	
	/* Build second request of bind see RFC */
	res.ver = c->ver;
	/* 0x00 succeeded, 0x01 general SOCKS failure ... */
	res.rep = (ok == 1) ? 0x00 : 0x01; 

	res.rsv = 0;
	res.atyp = 0x01;
	/* TODO: set bndaddr and bndport see RFC */
	/* res.bndaddr = 0;
	res.bndport = 0; */

	/* Copy in buffer for send */
	memcpy(c->req, &res, sizeof(Socks5ReqACK));
	/* DUMP(c->req, sizeof(Socks5ReqACK)); */

	/* Reset counter and fix b flag */
	c->req_pos = 0;
	c->req_a = 0;
	c->req_b = sizeof(Socks5ReqACK);

	/* Next state write request ack */
	c->state = E_W_REQ_ACK;
}

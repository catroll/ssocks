/*
 *      socks5-client.c
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
#include "socks5-client.h"
#include "socks5-common.h"
#include "net-util.h"
#include "output-util.h"


void dispatch_client (Client *c){

	switch(c->stateC){
		case E_W_VER: write_version(c); break;
		case E_R_VER_ACK: read_version_ack(c); break;
		case E_W_AUTH: write_auth(c); break;
		case E_R_AUTH_ACK: read_auth_ack(c); break;
		case E_W_REQ: write_request(c); break;
		case E_R_REQ_ACK: read_request_ack(c); break;
		case E_SEND : write_client(c); break;
		case E_RECV : read_client(c); break;
		default : break;
	}
}

/* Build and write the client version packet
 *
 * Version packet:
 *	+----+----------+----------+
 *	|VER | NMETHODS | METHODS  |
 *	+----+----------+----------+
 *	| 1  |    1     | 1 to 255 |
 *	+----+----------+----------+
 *
 */
void write_version(Client *c){
	int k;
	
	/* Build version packet */
	if (c->req_a == 0 && c->req_b == 0){
		TRACE(L_DEBUG, "client: build version packet ...");

		Socks5Version req;
		req.ver = SOCKS5_V;
		req.nmethods = 0x02;
		memcpy(c->req, &req, sizeof(Socks5Version));

		/* Support no-auth method and username/password */
		*(c->req + sizeof(Socks5Version)) = 0x00; /* No auth */
		*(c->req + sizeof(Socks5Version)+1) = 0x02; /* Auth username/password */

		/* Fix buffer size we send 2 methods */
		c->req_b = sizeof(Socks5Version) + 2;
	}
	
    if (c->req_b-c->req_a > 0) {
    	TRACE(L_DEBUG, "client: write version packet (%d bytes)...", c->req_b-c->req_a);
        k = write (c->soc_stream, c->req+c->req_a, c->req_b-c->req_a);
        if (k < 0) { perror ("write socket"); disconnection (c); return; }
        TRACE(L_DEBUG, "client: wrote %d bytes", k);
        c->req_a += k;
    }

    if (c->req_b-c->req_a <= 0){
    	/* Next state write version ack */
		c->stateC = E_R_VER_ACK;

		/* Reset counter all data wrote */
		c->req_a = 0;
		c->req_b = 0;
	}	
}

/* Read version ack packet and set next state
 *
 * Version ack packet:
 *	+----+--------+
 *	|VER | METHOD |
 *	+----+--------+
 *	| 1  |   1    |
 *	+----+--------+
 */
void read_version_ack(Client *c){
    int k;
    
    /* Warm if the buffer is full, the third parameter read goes to 0,
     * so read return 0 as a disconnection */
    TRACE(L_DEBUG, "client: read version ...");
    k = read (c->soc_stream, 
              c->req+c->req_b, 
              sizeof(c->req)-c->req_b-1);
    if (k < 0) { perror ("read socket"); disconnection(c); return; }
    if (k == 0) {
    	ERROR(L_NOTICE, "client: maybe buffer is full");
    	disconnection(c);
    	return;
    }
    TRACE(L_DEBUG, "client: read %d bytes", k);
    
    c->req_b += k;
    if ( (unsigned int)c->req_b - c->req_a >= sizeof(Socks5VersionACK) ){
		TRACE(L_DEBUG, "client: testing version ...");
		
		Socks5VersionACK res;
		/* Copy in Socks5VersionACK struct data in req */
		memcpy(&res, c->req + c->req_a, sizeof(Socks5VersionACK));
		TRACE(L_DEBUG, "client: v0x%x, method 0x%02X", res.ver, res.method);
		
		/* Testing version */
		if ( res.ver != SOCKS5_V ){
			fprintf(stderr,"client: wrong socks5 version");
			disconnection (c);
			return;
		}

		/* Server request method not supported */
		if ( res.method != 0x00 && res.method != 0x02){
			fprintf(stderr,"client: not supported auth method");
			disconnection (c);
			return;
		}
		
		/* Reset counter */
		c->req_a = 0;
		c->req_b = 0;
		
		/* Change state in function of the method */
		if ( res.method == 0x02 )
			c->stateC = E_W_AUTH;
		else
			c->stateC = E_W_REQ;
	}
    return;	
}

/* Write authentication packet
 *
 * RFC 1929
 *
 * Authentication packet:
 *	+----+------+----------+------+----------+
 *	|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
 *	+----+------+----------+------+----------+
 *	| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
 *	+----+------+----------+------+----------+
 */
void write_auth(Client *c){
	int k;
	
	/* Build authentication packet */
	if (c->req_a == 0 && c->req_b == 0){
		TRACE(L_DEBUG, "client: build authentication packet ...");
		
		/* Get username and password from the 
		 * config struct associate to the client.
		 * Can be NULL error we need it */
		Socks5Auth req;
		char *uname = ((ConfigClient*)c->config)->uname;
		char *passwd = ((ConfigClient*)c->config)->passwd;
		
		if (uname == NULL || passwd == NULL){
			ERROR(L_NOTICE, "client: need a login/password");
			disconnection (c); return;
		}
		
		/* Build authentication request */
		req.ver = 0x01; // See RFC1929
		req.ulen = (strlen(uname) < sizeof(req.uname)-1) ?
				strlen(uname) : sizeof(req.uname)-1;
		strcpy(req.uname, uname);
		req.plen = (strlen(passwd) < sizeof(req.passwd)-1) ?
				strlen(passwd) : sizeof(req.passwd)-1;
		strcpy(req.passwd, passwd);
		
		/* Write the request in buffer req */
		c->req[0] = req.ver;
		c->req[1] = req.ulen;
		strcpy(&c->req[2], req.uname);
		c->req[2+req.ulen] = req.plen;
		strcpy(&c->req[3+req.ulen], req.passwd);
		
		/* Fix buffer size we send 2 methods */
		c->req_a = 0;
		c->req_b = 3 + req.ulen + req.plen;
	}

    if (c->req_b-c->req_a > 0) {
		TRACE(L_DEBUG, "client: write authentication packet ...");
        k = write (c->soc_stream, c->req+c->req_a, c->req_b-c->req_a);
        if (k < 0) { perror ("write authentication"); disconnection (c); return; }
        TRACE(L_DEBUG, "client: wrote %d bytes", k);
        c->req_a += k;
    }

    if (c->req_b-c->req_a <= 0){
    	/* Change state to read auth ack */
		c->stateC = E_R_AUTH_ACK;

		/* Reset counter */
		c->req_a = 0;
		c->req_b = 0;
	}
    return;
}

/* Read authentication ack packet and check status
 *
 * RFC 1929
 *
 * Authentication ack packet:
 *	+----+--------+
 *	|VER | STATUS |
 *	+----+--------+
 *	| 1  |   1    |
 *	+----+--------+
 */
void read_auth_ack(Client *c){
    int k;

    TRACE(L_DEBUG, "client: read authentication ack ...");
    k = read (c->soc_stream, 
              c->req+c->req_b, 
              sizeof(c->req)-c->req_b-1);
    if (k < 0) { perror ("read authentication"); disconnection(c); return; }
    if (k == 0) {
    	ERROR(L_NOTICE, "client: maybe buffer is full");
    	disconnection(c);
    	return;
    }
    TRACE(L_DEBUG, "client: read %d bytes", k);
    
    c->req_b += k;
    if ( (unsigned int)c->req_b - c->req_a >= sizeof(Socks5AuthACK) ){
		TRACE(L_DEBUG, "client: testing authentication ack ...");
		
		Socks5AuthACK res;
		/* Copy in Socks5AuthACK struct data in req */
		memcpy(&res, c->req + c->req_a, sizeof(Socks5AuthACK));
		TRACE(L_DEBUG, "client: v0x%x, status 0x%02X", res.ver, res.status);
		
		/* Testing results */
		if ( res.ver != 0x01 ){
			ERROR(L_NOTICE, "client: authentication need version 0x01");
			disconnection (c);
			return;
		}
		if ( res.status != 0x00){
			ERROR(L_NOTICE, "client: authentication error, " \
					"maybe incorrect username/password");
			disconnection (c);
			return;
		}
		
		/* Reset counter */
		c->req_a = 0;
		c->req_b = 0;
		
		/* Mode dynamic used by ssocks only */
		if ( c->mode == M_DYNAMIC ){
			/* Change state to recv on stateC and state and put flush of buf down */
			c->stateC = E_RECV; c->state = E_RECV; c->buf_stream_w = 1;
		}else{
			/* Change state to write request */
			c->stateC = E_W_REQ;
		}
	}
    return;	
}


/* Build and write request packet
 *
 * Request packet:
 *	+----+-----+-------+------+----------+----------+
 *	|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
 *	+----+-----+-------+------+----------+----------+
 *	| 1  |  1  | X'00' |  1   | Variable |    2     |
 *	+----+-----+-------+------+----------+----------+
 *
 * See RFC 1928 / 4.  Requests for full information
 */
void write_request(Client *c){
	int k;

	/* build request packet */
	if (c->req_a == 0 && c->req_b == 0){
		Socks5Req req;
		TRACE(L_DEBUG, "client: build request packet ...");
		TRACE(L_DEBUG, "client: try to connect to %s:%d ...", 
			((ConfigClient*)c->config)->host, 
			((ConfigClient*)c->config)->port);

		/* Recover destination host and port form the config */
		char *host = ((ConfigClient*)c->config)->host;
		int hostlen = strlen(host);
		short port = htons(((ConfigClient*)c->config)->port);

		/* Set the request */
		req.ver = SOCKS5_V;
		req.cmd = (c->mode == M_CLIENT_BIND) ? 0x02 : 0x01;
		req.rsv = 0x00;
		req.atyp = 0x03;
		
		/* Copy the request in the req buffer */
		memcpy(c->req, &req, sizeof(Socks5Req));
		c->req[sizeof(Socks5Req)] = hostlen;
		strcpy(&c->req[sizeof(Socks5Req)+1], host);		
		memcpy(&c->req[sizeof(Socks5Req)+1+hostlen], &port, 2);
		
		/* Fix req buffer size */
		c->req_b = sizeof(Socks5Req)+1+hostlen+2;
		/* dump(c->req, c->req_b); */
		c->req_a = 0;	
	}
	
    if (c->req_b-c->req_a > 0) {
        k = write (c->soc_stream, c->req+c->req_a, c->req_b-c->req_a);
        if (k < 0) { perror ("write request"); disconnection (c); return; }
        TRACE(L_DEBUG, "client: wrote %d bytes", k);
        c->req_a += k;
    }

    if (c->req_b-c->req_a <= 0){
    	/* Change state to read request ack */
		c->stateC = E_R_REQ_ACK;

		/* Reset counter */
		c->req_a = 0;
		c->req_b = 0;
	}
    return;
}

/*Read request packet ack
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
void read_request_ack(Client *c){
    int k;

    TRACE(L_DEBUG, "client: read request ack ...");
    k = read (c->soc_stream, 
              c->req+c->req_b, 
              sizeof(c->req)-c->req_b-1);
    if (k < 0) { perror ("read socket"); disconnection(c); return; }
    if (k == 0) {
    	ERROR(L_NOTICE, "client: maybe buffer is full");
    	disconnection(c);
    	return;
    }
    TRACE(L_DEBUG, "client: read %d bytes", k);
    
    c->req_b += k;
    if ( (unsigned int)c->req_b - c->req_a >= sizeof(Socks5ReqACK) ){
		TRACE(L_DEBUG, "client: testing request ack ...");
		
		Socks5ReqACK res;
		/* Copy in Socks5ReqACK struct data in req */
		memcpy(&res, c->req + c->req_a, sizeof(Socks5ReqACK));

		TRACE(L_DEBUG, "client: v0x%x, rep 0x%x, rsv 0x%x, atyp 0x%x", res.ver,
			res.rep, res.rsv, res.atyp);
		TRACE(L_VERBOSE, "client: pass through %s:%d",
				inet_ntoa(res.bndaddr), ntohs(res.bndport));

		/* Testing request ack */
		if ( res.ver != SOCKS5_V ){
			ERROR(L_NOTICE, "client: wrong socks5 version");
			disconnection (c);
			return;
		}
		if ( res.rep != 0x00){
			ERROR(L_VERBOSE, "client: socks request ack error!");
			ERROR(L_NOTICE, "client: error, destination is unavailable!");
			disconnection (c);
			return;
		}
		
		TRACE(L_DEBUG, "client: connection established");
		
		/* Reset counter */
		c->req_a = 0;
		c->req_b = 0;

		/* If is a bind request and is the first request ack */
		if ( (c->mode == M_CLIENT_BIND) &&
				((ConfigClient*)c->config)->naskbind == 0 ){
			/* Continue the loop until the bind
			 * socket accept a new connection
			 * and send new request ack*/
			((ConfigClient*)c->config)->naskbind = 1;
			TRACE(L_DEBUG, "server: pending connection ...");
		}else{
			/* Stop the the client loop we have a connection trough the socks*/
			((ConfigClient*)c->config)->loop = 0;
		}
	}
    return;		
}

/* Create a socket trough a socks5 server
 * and return this socket
 */
int new_socket_with_socks(char *sockshost, int socksport,
							char *host, int port,
							char *uname, char *passwd,
							int bind){
	int maxfd = 0, res;
	fd_set set_read, set_write;
    ConfigClient config;
    Client c;

	/* Configure the configuration struct */
	config.host = host;
	config.port = port;
	config.loop = 1;
	config.uname = uname;
	config.passwd = passwd;
	config.naskbind = 0;

	/* Initialization of the structure client in client mode */
	if ( bind ) init_client (&c, 0, M_CLIENT_BIND, &config);
	else init_client (&c, 0, M_CLIENT, &config);

	/* Make socket on the SOCKS server */
	c.soc_stream = new_client_socket(sockshost, socksport, &c.addr, &c.addr_stream);
	if ( c.soc_stream < 0 ){
		return -1;
	}

	/* Catch CTRL-C */
    //bor_signal (SIGINT, capte_fin, SA_RESTART);

    /* Select loop */
    while (config.loop && c.soc_stream != -1) {

		FD_ZERO (&set_read);
		FD_ZERO (&set_write);
		maxfd = 0;

		/* Adds the socket in read fds */
		FD_SET (c.soc_stream, &set_read);
		if (c.soc_stream > maxfd) maxfd = c.soc_stream; /* Fix maxfd */

		/* Adds the socket in write fds only if we need */
		if ( c.stateC == E_W_VER || c.stateC == E_W_AUTH
				|| c.stateC == E_W_REQ  ){
			FD_SET (c.soc_stream, &set_write);
			if (c.soc_stream > maxfd) maxfd = c.soc_stream; /* Fix maxfd */
		}

		res = select (maxfd+1, &set_read, &set_write, NULL, bor_timer_delay());
        if (res > 0) {  /* Search eligible sockets */
            if (FD_ISSET (c.soc_stream, &set_read)){
				dispatch_client(&c);
			}else if(FD_ISSET (c.soc_stream, &set_write)){
				dispatch_client(&c);
			}

        } else if ( res == 0){
            /* Timeout for a client
            int handle = bor_timer_handle();
			if (c.handle == handle){
				ERROR(L_NOTICE, "client: timeout server ...");
				close(c.soc_stream);
				return -1;
			}*/

        }else if (res < 0) {
            if (errno == EINTR) ; /* Received signal, it does nothing */
            else { perror ("select"); close(c.soc_stream); return -1; }
        }
	}

	return c.soc_stream;
}

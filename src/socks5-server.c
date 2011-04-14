/*
 *      socks5-server.c
 *      
 *      Created on: 2011-04-11
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

#include "socks-common.h"
#include "socks5-server.h"
#include "net-util.h"

#include "auth-util.h"
#include "bor-util.h"

#include <config.h>

#ifdef HAVE_LIBPTHREAD
	#include <pthread.h>
#endif

/* Version packet:
 *	+----+----------+----------+
 *	|VER | NMETHODS | METHODS  |
 *	+----+----------+----------+
 *	| 1  |    1     | 1 to 255 |
 *	+----+----------+----------+
 */
int analyse_version(s_socks *s, s_socks_conf *c, s_buffer *buf){
	int i, j;
	Socks5Version req;
	TRACE(L_DEBUG, "server [%d]: testing version ...", 
		s->id);
	
	memcpy(&req, buf->data, sizeof(Socks5Version));

	/* If too much method we truncate */
	if (sizeof(req.methods) < (unsigned int)req.nmethods){
		ERROR(L_VERBOSE, "server [%d]: truncate methods", 
			s->id);
		req.nmethods = sizeof(req.methods);
	}
	
	/* Show only in debug mode */
	if ( L_DEBUG <= verbosity ){
		printf("server [%d]: methods ", s->id);
	}

	/* Copy in methods the methods in the packet
	 * memcpy can do the trick too */
	for (i=0; i <  req.nmethods; ++i){
		req.methods[i] = *(buf->data + 2 + i );
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
	char *allowed = c->config.srv->allowed_version;
	while ( *allowed != 0 ){
		if ( *allowed == req.ver ){
			s->version = *allowed;
			TRACE(L_DEBUG, "server [%d]: version %d", 
				s->id, s->version);
			break;
		}
		allowed++;
	}
	
	/* No valid version find */
	if ( s->version == -1 ){
		ERROR(L_VERBOSE, "server [%d]: version error (%d)", 
			s->id, req.ver);	
		return -1;	
	}
	
	/* Searching valid methods:
	 * Methods 0x00, no authentication
	 *         0x01, GSSAPI no supported
	 *         0x02, username/password RFC1929
	 */
	for (i=0; i <  req.nmethods && s->method == -1; ++i){
		for (j = 0; j < c->config.srv->n_allowed_method; ++j ){
			if ( c->config.srv->allowed_method[j] == req.methods[i] ){
				s->method = c->config.srv->allowed_method[j];
				break;
			}
		}		
	}
	
	/* No valid method find */
	if ( s->method == -1 ){
		ERROR(L_VERBOSE, "server [%d]: method not supported", 
			s->id);	
		return -2;	
	}
	
	return 0;
}

/*
 * Version ack packet:
 *	+----+--------+
 *	|VER | METHOD |
 *	+----+--------+
 *	| 1  |   1    |
 *	+----+--------+
 */
void build_version_ack(s_socks *s, s_socks_conf *c, s_buffer *buf)
{
	Socks5VersionACK res;
	init_buffer(buf);
	res.ver = s->version;
	res.method = s->method;
	
	/* Copy in buffer for send */
	memcpy(buf->data, &res, sizeof(Socks5VersionACK));
	
	/* Reset counter and fix b flag */
	buf->a = 0;
	buf->b = sizeof(Socks5VersionACK);
}


int analyse_auth(s_socks *s, s_socks_conf *c, s_buffer *buf)
{
	Socks5Auth req;
	
	TRACE(L_DEBUG, "server [%d]: testing authentication ...", 
		s->id);
	
	/* Rebuild the packet in Socks5Auth struct
	 *  +----+------+----------+------+----------+
	 *	|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
	 *	+----+------+----------+------+----------+
	 *	| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
	 *	+----+------+----------+------+----------+
	 */
	memcpy(&req, buf->data, 2);
	memcpy(&req.plen, buf->data + 2 + (int)req.ulen , 2);

	/* Check username and password length truncate if too long
	 * RFC tell us max length 255 */
	if ( (unsigned int)req.ulen > sizeof(req.uname)-1){
		ERROR(L_NOTICE, "server [%d]: username too long", 
			s->id);
		req.ulen = sizeof(req.uname)-1;
	}
	if ( (unsigned int)req.plen > sizeof(req.passwd)-1){
		ERROR(L_NOTICE, "server [%d]: password  too long", 
			s->id);
		req.plen = sizeof(req.passwd)-1;
	}

	/* Extract username and fix NULL byte */
	strncpy(req.uname, buf->data + 2, req.ulen);
	*(req.uname + req.ulen) = '\0';

	/* Extract passwd and fix NULL byte */
	strncpy(req.passwd, buf->data + 2 + (int)req.ulen + 1, req.plen);
	*(req.passwd + req.plen) = '\0';
	//DUMP(buf->data, buf->b);
	TRACE(L_VERBOSE, "server [%d]: authentication attempt "\
						"v0x%02X (%d,%d) %s:%s", 
		s->id, 
		req.ver, req.ulen, req.plen, req.uname, req.passwd);
	
	/* Test version need 0x01 RFC */
	if ( req.ver != 0x01 ){
		ERROR(L_NOTICE, "server [%d]: wrong version need to be 0x01", 
			s->id);
		return -1;
	}
	
	/* Check username and password in authentication file */
	if ( check_auth(req.uname, req.passwd) == 1 ){
		TRACE(L_VERBOSE, "server [%d]: authentication OK!", 
			s->id);
		//append_log_client(c, "%s OK", req.uname);
		s->auth = 1;
	}else{
		ERROR(L_VERBOSE, "server [%d]: authentication NOK!", 
			s->id);
		//append_log_client(c, "%s NOK", req.uname);
		s->auth = 0;
	}
	
	return 0;	
}

/*
 *  +----+--------+
 *	|VER | STATUS |
 *	+----+--------+
 *	| 1  |   1    |
 *	+----+--------+
 */
void build_auth_ack(s_socks *s, s_socks_conf *c, s_buffer *buf)
{
	Socks5AuthACK res;
	init_buffer(buf);
	res.ver = 0x01;
	res.status = (s->auth) ? 0x00 : 0xFF; /* 0x00 == win! */
	
	/* Copy in buffer for send */
	memcpy(buf->data, &res, sizeof(Socks5VersionACK));
	
	/* Reset counter and fix b flag */
	buf->a = 0;
	buf->b = sizeof(Socks5VersionACK);
}

typedef struct {
	s_socks *socks;
	s_socket *soc_stream;
	s_socket *soc_bind;
	s_socket *soc;
	s_socks_conf *conf;
	s_buffer *buf;
}s_thr_req;

void *thr_request(void *d){
	s_thr_req *data = (s_thr_req*)d;

	int k = analyse_request(data->socks,
			data->soc_stream, data->soc_bind,
			data->conf, data->buf);

	if (k < 0){
		close_socket(data->soc);
#ifdef HAVE_LIBPTHREAD
		pthread_exit(NULL);
#else
		return NULL;
#endif
	} /* Error */

	build_request_ack(data->socks, data->conf,
			data->soc_stream, data->soc_bind,
			data->buf);

	data->socks->state = S_W_REQ_ACK;

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

int analyse_request(s_socks *s, s_socket *stream, s_socket *bind,
		s_socks_conf *c, s_buffer *buf)
{
	Socks5Req req;
	TRACE(L_DEBUG, "server [%d]: testing client request ...", 
		s->id);

	int port = 0, *p;
	char domain[256];
	unsigned char chAddr[4];
	unsigned int l;

	/* Rebuild the packet but don't extract
	 * DST.ADDR and DST.PORT in Socks5Req struct
	 *	|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	 *	+----+-----+-------+------+----------+----------+
	 *	| 1  |  1  | X'00' |  1   | Variable |    2     |
	 *	+----+-----+-------+------+----------+----------+
	 *
	 */
	memcpy(&req, buf->data, sizeof(Socks5Req));
	TRACE(L_DEBUG, "server [%d]: v0x%x, cmd 0x%x, rsv 0x%x, atyp 0x%x", 
		s->id, req.ver,
		req.cmd, req.rsv, req.atyp);
	
	/* Save the request cmd */
	s->cmd = req.cmd;
	
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
			l = *(buf->data + sizeof(Socks5Req)) ;

			/* Copy the domain name and blank at end
			 * little cheat to avoid overflow (dangerous here) */
			strncpy(domain, buf->data + sizeof(Socks5Req) + 1,
					( l < sizeof(domain) ) ? l : sizeof(domain)-1 );
			domain[(int)l] = 0;
			
			/* After domain we have the port
			 * big endian on 2 bytes*/
			p = (int*)(buf->data + sizeof(Socks5Req) + l  + 1) ;
			port = ntohs(*p);
			
			TRACE(L_DEBUG, "Server [%d]: asking for %s:%d", s->id, domain, port);
			break;

		case 0x01: /* IP address */
			memcpy(&chAddr, (buf->data + sizeof(Socks5Req)), 
					sizeof(chAddr));
			sprintf(domain, "%d.%d.%d.%d", chAddr[0],
				chAddr[1], chAddr[2], chAddr[3]);
				
			/* After domain we have the port
			 * big endian on 2 bytes*/
			p = (int*)(buf->data + sizeof(Socks5Req) + 4  ) ;
			port = ntohs(*p);
			break;

		/* TODO: ipv6 support */
		default:
			ERROR(L_NOTICE, "server [%d]: support domain name "\
								"and ipv4 only", 
				s->id);
			return -1;
	}
	
	//append_log_client(c, "v%d %s:%d", s->version, domain, port);
	
	/* CMD:
	 *  - CONNECT X'01'
	 *  - BIND X'02'
	 *  - UDP ASSOCIATE X'03'
	 *
	 * Open or bind connection here
	 */
	switch(req.cmd){
		case 0x01: /* TCP/IP Stream connection */
			stream->soc = new_client_socket(domain, port, &stream->adrC, 
				&stream->adrS);
			if ( stream->soc >= 0 ){
				//append_log_client(c, "CONNECT");
				s->connected = 1;
				/* In the reply to a CONNECT, BND.PORT contains
				 * the port number that the server assigned to
				 * connect to the target host, while BND.ADDR
				 * contains the associated IP address.
				 */
				TRACE(L_DEBUG, "client: assigned addr %s",
					bor_adrtoa_in(&stream->adrC));
			}
			break;
		case 0x02: /* TCP/IP port binding */
			bind->soc = new_listen_socket(port, 10, &bind->adrC);
			if ( bind->soc >= 0 ){
				//append_log_client(c, "BIND");
				s->connected = 0;
				s->listen = 1;
				/* TODO: Need to set bndaddr and bndport
				 * in port binding see RFC:
				 * The BND.PORT field contains the port number that the
				 * SOCKS server assigned to listen for an incoming
				 * connection. The BND.ADDR field contains
				 * the associated IP address.
				 */
			}

			break;
		/* TODO: udp support */
		default :
			//append_log_client(c, "ERROR request cmd");
			ERROR(L_NOTICE, "server [%d]: don't support udp", 
				s->id);
			return -2;
	}
	
	return 0;
}

int analyse_request_dynamic(s_socks *s, s_socks_conf *c, s_buffer *buf)
{
	return -1;
}

/* Request ack packet:
 *	+----+-----+-------+------+----------+----------+
 *	|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
 *	+----+-----+-------+------+----------+----------+
 *	| 1  |  1  | X'00' |  1   | Variable |    2     |
 *	+----+-----+-------+------+----------+----------+
 */
void build_request_ack(s_socks *s, s_socks_conf *c, 
		s_socket *stream, s_socket *bind, s_buffer *buf)
{
	
	Socks5ReqACK res;

	res.ver = 0x05;//s->version;
	res.rsv = 0;
	res.atyp = 0x01;
	
	init_buffer(buf);
	
	switch(s->cmd){
		case 0x01:
			/* 0x00 succeeded, 0x01 general SOCKS failure ... */
			if ( s->connected == 1){
				res.rep = 0x00;
				memcpy(&res.bndaddr, &stream->adrC.sin_addr.s_addr,
						sizeof(stream->adrC.sin_addr.s_addr));
				memcpy(&res.bndport, &stream->adrC.sin_port,
						sizeof(stream->adrC.sin_port));	
			}else{
				res.rep = 0x01;
			}
			break;
			
		case 0x02:
			/* 0x00 succeeded, 0x01 general SOCKS failure ... */
			if ( s->listen == 1 && s->connected == 0 ){
				res.rep = 0x00;
				memcpy(&res.bndaddr, &bind->adrC.sin_addr.s_addr,
						sizeof(bind->adrC.sin_addr.s_addr));
				memcpy(&res.bndport, &bind->adrC.sin_port,
						sizeof(bind->adrC.sin_port));
			}else if ( s->listen == 1 && s->connected == 1 ){
				res.rep = 0x00;
				memcpy(&res.bndaddr, &stream->adrC.sin_addr.s_addr,
						sizeof(stream->adrC.sin_addr.s_addr));
				memcpy(&res.bndport, &stream->adrC.sin_port,
						sizeof(stream->adrC.sin_port));
			}else{
				res.rep = 0x01;
			}
			

			break;
			
		default:
			res.rep = 0x00;
			break;
	}
	
	/* Copy in buffer for send */
	memcpy(buf->data, &res, sizeof(Socks5ReqACK));
	
	/* Reset counter and fix b flag */
	buf->a = 0;
	buf->b = sizeof(Socks5ReqACK);
}

int build_request_accept_bind(s_socks *s, s_socks_conf *c,
		s_socket *stream, s_socket *bind, s_buffer *buf)
{
	init_buffer(buf);
	
	TRACE(L_VERBOSE, "server [%d]: build binding packet ...", 
		s->id);

	stream->soc  = bor_accept_in (bind->soc, &stream->adrC);
	if ( stream->soc < 0 ){
		s->connected = -1; /* Send a error request ack */
		return -1;
	}
	
	s->connected = 1;
	
	TRACE(L_DEBUG, "server: established connection with %s", 
		bor_adrtoa_in(&stream->adrC));
		
	//append_log_client(c, "ACCEPT %s", bor_adrtoa_in(&stream->adrC));
	
	build_request_ack(s, c, stream, bind, buf);
	
	return 0;
}

int dispatch_server_write(s_socket *soc, s_socks *socks,
		s_buffer *buf, s_socks_conf *conf)
{
	int k = 0;
	switch(socks->state){
		case S_W_VER_ACK:
			WRITE_DISP(k, soc, buf);

			if ( socks->method == 0x02 )
				socks->state = S_R_AUTH;
			else
				socks->state = S_R_REQ;

			break;

		case S_W_AUTH_ACK:
			WRITE_DISP(k, soc, buf);
			if ( socks->auth == 0 ){
				/* close_socket(soc); */
				k = -1;
				break;
			}
			socks->state = S_R_REQ;
			break;

		case S_W_REQ_ACK:
			WRITE_DISP(k, soc, buf);
			/* If listen and not connected we are in bind mode */
			if ( socks->listen == 1 && socks->connected == 0 ){
				/* Wait until a soc_bind accept a connection */
				socks->state = S_WAIT;
			}else if (socks->connected == 1){
				/* We are connected let's go */
				socks->state = S_REPLY;
			}else{
				/* Error not connected, normally can happen only in bind mode
				 * we return a error */
				k = -1;
			}
			break;

		case S_REPLY:
				k = write_socks(soc, buf);
				if (k < 0){ /* close_socket(soc); */ break; } /* Error */
				init_buffer(buf);
			break;

		default:
			break;
	}

	return k;
}

int dispatch_server_read(s_socket *soc, s_socket *soc_stream, s_socket *soc_bind,
		s_socks *socks, s_buffer *buf, s_buffer *buf_stream, s_socks_conf *conf){
	int k = 0;
	struct sockaddr_in adrC, adrS;

	switch(socks->state){
		case S_R_VER:
			READ_DISP(k, soc, buf, 3);

			k = analyse_version(socks, conf,
								buf);
			if (k < 0){ /* close_socket(soc); */ break; } /* Error */

			build_version_ack(socks, conf,
								buf);

			socks->state = S_W_VER_ACK;

			break;

		case S_R_AUTH:
			READ_DISP(k, soc, buf, 4);

			k = analyse_auth(socks, conf,
								buf);
			if (k < 0){ /* close_socket(soc); */ break; } /* Error */

			build_auth_ack(socks, conf,
								buf);

			socks->state = S_W_AUTH_ACK;

			break;

		case S_R_REQ:
			if ( socks->mode == M_DYNAMIC){
				READ_DISP(k, soc, buf,
					sizeof(Socks5Req)  + 4);
				soc_stream->soc = new_client_socket(conf->config.cli->sockshost,
									conf->config.cli->socksport,
									&adrC, &adrS);

				if ( soc_stream->soc < 0 ){
					ERROR(L_NOTICE, "client: connection to socks5 server impossible!");
					k = -1;
					/* close_socket(soc); */
				}

				socks->state = S_WAIT;
				break;
			}
			READ_DISP(k, soc, buf,
				sizeof(Socks5Req)  + 4);

#ifdef HAVE_LIBPTHREAD
			s_thr_req *d = (s_thr_req*)malloc(sizeof(s_thr_req));

			d->soc_bind = soc_bind;
			d->soc = soc;
			d->buf = buf;
			d->conf = conf;
			d->socks = socks;
			d->soc_stream = soc_stream;

	    	/* This avoid to block all socks client when we do a connection */
	    	pthread_t thr;
	    	pthread_create( &thr, NULL, thr_request, (void*) d);

	    	/* We never join this thread, to notify the end
	    	 * it send a signal SIGUSR1 */
	    	pthread_detach(thr);
	    	socks->state = S_WAIT;
#else


			k = analyse_request(socks,
								soc_stream, soc_bind,
								conf, buf);

			if (k < 0){ /* close_socket(soc); */ break; } /* Error */

			build_request_ack(socks, conf,
								soc_stream, soc_bind,
								buf);

			socks->state = S_W_REQ_ACK;
#endif
			break;

		case S_REPLY:
			if ( buf_free(buf_stream) > 0 ){
				k = read_socks(soc, buf_stream, 0);
				if (k < 0){ /* close_socket(soc); */ break; } /* Error */
			}
			break;
		default:
			break;
	}
	return k;
}


void dispatch_server(s_client *client, fd_set *set_read, fd_set *set_write)
{
	int k = 0;
	
	/* Dispatch server socket */
	if (client->soc.soc != -1 && FD_ISSET (client->soc.soc, set_read))
		k = dispatch_server_read(&client->soc, &client->soc_stream, &client->soc_bind,
				&client->socks, &client->buf, &client->stream_buf, client->conf);

	else if (client->soc.soc != -1 && 
			FD_ISSET (client->soc.soc, set_write))
		k = dispatch_server_write(&client->soc, &client->socks, &client->buf, client->conf);
	if (k < 0){ disconnection(client); }
	
	/* Dispatch stream socket */
	if (client->soc_stream.soc != -1 
			&& FD_ISSET (client->soc_stream.soc, set_read)){
		if ( buf_free(&client->buf) > 0 ){
			k = read_socks(&client->soc_stream, &client->buf, 0); 
			if (k < 0){ disconnection(client); } /* Error */
		}

	}else if (client->soc_stream.soc != -1 
			&& FD_ISSET (client->soc_stream.soc, set_write)){
		
			k = write_socks(&client->soc_stream, &client->stream_buf);
			if (k < 0){ disconnection(client); } /* Error */ 
			init_buffer(&client->stream_buf);
	}
		
	if (client->soc_bind.soc != -1 &&
			FD_ISSET (client->soc_bind.soc, set_read)){
		if ( build_request_accept_bind(&client->socks, client->conf, 
				&client->soc_stream, &client->soc_bind, &client->buf) == 0 ){
			client->socks.state = S_W_REQ_ACK;
		}
	}
}

void init_select_server_cli (s_socket *soc,	s_socks *s, s_buffer *buf,
		int *maxfd,	fd_set *set_read, fd_set *set_write){
	if ( soc->soc != -1 ){
		if ( s->state == S_R_VER ||
			 s->state == S_R_AUTH ||
			 s->state == S_R_REQ )
		{
			FD_SET(soc->soc, set_read);
		}else if (s->state == S_W_VER_ACK ||
				  s->state == S_W_AUTH_ACK ||
			      s->state == S_W_REQ_ACK)
		{
			FD_SET(soc->soc, set_write);
		}else if (s->state == S_WAIT ){

		}else if (s->state == S_REPLY )	{
			if ( buf_empty(buf) == 0 ){
				FD_SET(soc->soc, set_write);
			}else{
				FD_SET(soc->soc, set_read);
			}
		}
		if (soc->soc > *maxfd) *maxfd = soc->soc;
	}
}

void init_select_server_stream (s_socket *soc, s_buffer *buf,
		int *maxfd,	fd_set *set_read, fd_set *set_write){
	if ( soc->soc != -1 ){
		if ( buf_empty(buf) == 0 ){
			FD_SET(soc->soc, set_write);
		}else{
			FD_SET(soc->soc, set_read);
		}
		if (soc->soc > *maxfd) *maxfd = soc->soc;
	}
}

/* TODO: init_select_server
 */
void init_select_server (int soc_ec, s_client *tc, int *maxfd,
		fd_set *set_read, fd_set *set_write)
{
    int nc;
    /* TODO: move FD_ZERO */
    FD_ZERO (set_read);
    FD_ZERO (set_write);
    FD_SET (soc_ec, set_read);

    *maxfd = soc_ec;
    for (nc = 0; nc < MAXCLI; nc++){
		s_client *client = &tc[nc];
		
		init_select_server_cli(&client->soc, &client->socks, &client->buf,
				maxfd, set_read, set_write);

		init_select_server_stream(&client->soc_stream, &client->stream_buf,
				maxfd, set_read, set_write);

		
		if ( client->soc_bind.soc != -1 ){
			FD_SET(client->soc_bind.soc, set_read);
			if (client->soc_bind.soc > *maxfd) *maxfd = client->soc_bind.soc;
		}
	}
}

void init_select_server_reverse (s_client *tc, int *maxfd,
		int ncon, fd_set *set_read, fd_set *set_write)
{
	/* Security to avoid segmentation fault on tc tab */
	if ( ncon >= MAXCLI ) ncon = MAXCLI-1;

    int nc, cpt = 0;

    FD_ZERO (set_read);
    FD_ZERO (set_write);

    *maxfd = 0;
    for (nc = 0; nc < MAXCLI; nc++){
		s_client *client = &tc[nc];

		/* Count available connection */
		if ( client->soc.soc != -1 ) cpt++;

		init_select_server_cli(&client->soc, &client->socks, &client->buf,
				maxfd, set_read, set_write);

		init_select_server_stream(&client->soc_stream, &client->stream_buf,
				maxfd, set_read, set_write);


		if ( client->soc_bind.soc != -1 ){
			FD_SET(client->soc_bind.soc, set_read);
			if (client->soc_bind.soc > *maxfd) *maxfd = client->soc_bind.soc;
		}
	}

    /* */
	while(cpt < ncon){
		/* Open connection to the socks client */
		for (nc = 0; nc < MAXCLI; nc++) if ( tc[nc].soc.soc == -1 ) break;
		if (nc >= MAXCLI) return;
		tc[nc].soc.soc = new_client_socket(tc[nc].conf->config.cli->sockshost,
				tc[nc].conf->config.cli->socksport, &tc[nc].soc.adrC,
				&tc[nc].soc.adrS);
		if ( tc[nc].soc.soc < 0 ){
			TRACE(L_DEBUG, "client: connection to %s error",
					tc[nc].conf->config.cli);
			return;
		}
		init_select_server_cli(&tc[nc].soc, &tc[nc].socks, &tc[nc].buf,
				maxfd, set_read, set_write);
		cpt++;
	}
}

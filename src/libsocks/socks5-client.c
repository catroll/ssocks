/*
 *      socks5-client.c
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
#include "socks5-client.h"
#include "socks5-server.h"
#include "net-util.h"
#include "bor-util.h"

void build_version(s_socks *s, s_socks_conf *c, s_buffer *buf)
{
	Socks5Version req;
	init_buffer(buf);
	req.ver = c->config.cli->version;
	//req.nmethods = c->n_allowed_method;
	req.nmethods = 2;
	memcpy(buf->data, &req, 2);
	memcpy(buf->data+2, c->config.cli->allowed_method, req.nmethods);
	
	/* Reset counter and fix b flag */
	buf->a = 0;
	buf->b = sizeof(Socks5VersionACK) + req.nmethods;
}

int analyse_version_ack(s_socks *s, s_socks_conf *c, s_buffer *buf)
{
	Socks5VersionACK res;
	int j;
	TRACE(L_DEBUG, "client: testing version ack ...");	
	
	memcpy(&res, buf->data, sizeof(Socks5VersionACK));
	if ( res.ver != c->config.cli->version ){
		ERROR(L_NOTICE, "client: wrong socks version");
		return - 1;		
	}
	s->version = res.ver;
	
	for (j = 0; j < c->config.cli->n_allowed_method; ++j ){
		if ( c->config.cli->allowed_method[j] == res.method ){
			s->method = c->config.cli->allowed_method[j];
			break;
		}
	}
	
	/* No valid method find */
	if ( s->method == -1 ){
		ERROR(L_VERBOSE, "client: methode not supported", 
			s->id);	
		return -2;	
	}
	s->method = res.method;
	
	return 0;
}
	
int build_auth(s_socks *s, s_socks_conf *c, s_buffer *buf)
{
	Socks5Auth req;
	char *uname, *passwd;
	
	init_buffer(buf);

	uname = c->config.cli->username;
	passwd = c->config.cli->password;

	if (uname == NULL || passwd == NULL){
		ERROR(L_NOTICE, "client: need a login/password");
		return -1;
	}	
	
	/* Build authentication request */
	req.ver = 0x01; // See RFC1929
	req.ulen = (strlen(uname) < sizeof(req.uname)-1) ?
			strlen(uname) : sizeof(req.uname)-1;
	strcpy(req.uname, uname);
	req.plen = (strlen(passwd) < sizeof(req.passwd)-1) ?
			strlen(passwd) : sizeof(req.passwd)-1;
	strcpy(req.passwd, passwd);
	
	memcpy(buf->data, &req, 2);
	strcpy(&buf->data[2], req.uname);
	buf->data[2+req.ulen] = req.plen;
	strcpy(&buf->data[2+req.ulen+1], req.passwd);

	/* Reset counter and fix b flag */
	buf->a = 0;
	buf->b =  3 + req.ulen + req.plen;

	return 0;
}

int analyse_auth_ack(s_socks *s, s_socks_conf *c, s_buffer *buf)
{
	Socks5AuthACK res;
	TRACE(L_DEBUG, "client: testing authentication ack ...");	

	memcpy(&res, buf->data, sizeof(Socks5VersionACK));
	TRACE(L_DEBUG, "client: v0x%x, status 0x%02X", res.ver, res.status);
	
	/* Testing results */
	if (res.ver != 0x01 ) {
		ERROR(L_NOTICE, "client: authentication need version 0x01");
		return -1;
	}
	
	if ( res.status != 0x00){
		s->auth = 0;
		ERROR(L_NOTICE, "client: authentication error, " \
				"maybe incorrect username/password");
		return -2;
	}
	
	s->auth = 1;
	
	return 0;
}

void build_request(s_socks *s, s_socks_conf *c, s_buffer *buf)
{
	Socks5Req req;
	init_buffer(buf);
	
	TRACE(L_DEBUG, "client: build request packet ...");
	TRACE(L_DEBUG, "client: try to connect to %s:%d ...", 
		c->config.cli->host,
		c->config.cli->port);
	
	/* Set the request */
	req.ver = s->version;

	req.rsv = 0x00;
	req.atyp = 0x03;	

	char *host;
	short port;

	req.cmd = s->cmd = c->config.cli->cmd;

	/* Command BIND */
	if ( req.cmd == CMD_BIND ){
		host = "0.0.0.0";
		port = htons(c->config.cli->listen);
	}else if ( req.cmd == CMD_CONNECT ){
		host = c->config.cli->host;
		port = htons(c->config.cli->port);
	}else{
		ERROR(L_VERBOSE, "client: configuration error, unknown command");
		return;
	}

	/* Recover destination host and port form the config */
	int hostlen = strlen(host);


	/* Copy the request in the req buffer */
	memcpy(buf->data, &req, sizeof(Socks5Req));
	buf->data[sizeof(Socks5Req)] = hostlen;
	strcpy(&buf->data[sizeof(Socks5Req) + 1], host);
	memcpy(&buf->data[sizeof(Socks5Req) + 1 + hostlen], &port, 2);
	
	/* Reset counter and fix b flag */
	buf->a = 0;
	buf->b =  sizeof(Socks5Req) + 1 + hostlen + 2;
}

int analyse_request_ack(s_socks *s, s_socks_conf *c, s_buffer *buf)
{
	Socks5ReqACK res;
	
	TRACE(L_DEBUG, "client: testing request ack ...");

	memcpy(&res, buf->data, sizeof(Socks5ReqACK));
	
	TRACE(L_DEBUG, "client: v0x%x, rep 0x%x, rsv 0x%x, atyp 0x%x", 
	res.ver, res.rep, res.rsv, res.atyp);
	
	if ( res.rep != 0x00){
		ERROR(L_VERBOSE, "client: socks request ack error!");
		ERROR(L_NOTICE, "client: error, destination is unavailable!");
		return -1;
	}

	if ( c->config.cli->cmd == CMD_BIND ){
		if ( s->listen == 0 ){
			s->listen = 1;
			TRACE(L_VERBOSE, "client: listen on %s:%d",
					inet_ntoa(res.bndaddr), ntohs(res.bndport));
		}
		else{
			s->connected = 1;
			TRACE(L_DEBUG, "client: connection established with %s:%d",
					inet_ntoa(res.bndaddr), ntohs(res.bndport));

		}
	}else{
		TRACE(L_VERBOSE, "client: pass through %s:%d",
				inet_ntoa(res.bndaddr), ntohs(res.bndport));

		TRACE(L_DEBUG, "client: connection established");

		s->connected = 1;
	}



	return 0;
}


int dispatch_client_write(s_socket *soc, s_socks *socks,
		s_buffer *buf, s_socks_conf *conf)
{
	int k = 0;
	switch(socks->state){
		case S_W_VER:
			if ( buf_empty(buf) )
				build_version(socks, conf, buf);
			
			WRITE_DISP(k, soc, buf);
			socks->state = S_R_VER_ACK;

			break;
			
		case S_W_AUTH:
			WRITE_DISP(k, soc, buf);
			socks->state = S_R_AUTH_ACK;
			break;
			
		case S_W_REQ:
			WRITE_DISP(k, soc, buf);
			socks->state = S_R_REQ_ACK;
			break;		

		case S_REPLY:
			k = write_socks(soc, buf);
			if (k < 0){ close_socket(soc);  break; } /* Error */
			init_buffer(buf);
			break;

		default:
			break;
	}

	return k;
}

int dispatch_client_read(s_socket *soc, s_socket *soc_stream,
		s_socks *socks, s_buffer *buf, s_buffer *buf_stream, s_socks_conf *conf)
{
	int k = 0;
	switch(socks->state){
		case S_R_VER_ACK:
			READ_DISP(k, soc, buf, sizeof(Socks5VersionACK));

			k = analyse_version_ack(socks, conf,
								buf);
			if (k < 0){ close_socket(soc); break; } /* Error */

			if ( socks->method == 0x02 ){
				if ( build_auth(socks, conf,
								buf) < 0 ){
					close_socket(soc); break;
				}
				socks->state = S_W_AUTH;
			}else{
				if ( socks->mode == M_DYNAMIC_CLIENT ){
					socks->state = S_REPLY;
					break;
				}
				build_request(socks, conf,
								buf);
				socks->state = S_W_REQ;
			}
			break;

		case S_R_AUTH_ACK:
			READ_DISP(k, soc, buf,
				sizeof(Socks5AuthACK));

			k = analyse_auth_ack(socks, conf,
								buf);
			if (k < 0){ close_socket(soc); break; } /* Error */

			build_request(socks, conf, buf);
			socks->state = S_W_REQ;
			break;

		case S_R_REQ_ACK:
			READ_DISP(k, soc, buf,
				sizeof(Socks5ReqACK));

			k = analyse_request_ack(socks, conf,
									buf);

			if (k < 0){ close_socket(soc); break; } /* Error */

			if ( conf->config.cli->cmd == CMD_BIND ){
				if ( socks->connected == 0 && socks->listen == 1)
					socks->state = S_R_REQ_ACK;
				else{
					socks->state = S_REPLY;
					/* End, stop client loop */
					conf->config.cli->loop = 0;
				}
			}else{
				socks->state = S_REPLY;
				/* End, stop client loop */
				conf->config.cli->loop = 0;
			}


			init_buffer(buf);
			break;

		case S_REPLY:
			if ( buf_free(buf_stream) > 0 ){
				k = read_socks(soc, buf_stream, 0);
				if (k < 0){ close_socket(soc); break; } /* Error */
			}
			break;
		default:
			break;
	}
	return k;
}


void dispatch_client(s_client *client, fd_set *set_read, fd_set *set_write)
{
	int k = 0;
	/* Dispatch server socket */
	if (client->soc.soc != -1 && FD_ISSET (client->soc.soc, set_read))
		k = dispatch_client_read(&client->soc, &client->soc_stream,
				&client->socks, &client->buf, &client->stream_buf, client->conf);
	else if (client->soc.soc != -1 && 
			FD_ISSET (client->soc.soc, set_write))
		k = dispatch_client_write(&client->soc, &client->socks, &client->buf, client->conf);

	if (k < 0){ disconnection(client); }
}

void dispatch_dynamic(s_client *client, fd_set *set_read, fd_set *set_write)
{
	int k = 0;
	/* Dispatch server socket */
	if (client->soc.soc != -1 && FD_ISSET (client->soc.soc, set_read))
		k = dispatch_server_read(&client->soc, &client->soc_stream, &client->soc_bind,
				&client->socks, &client->buf, &client->stream_buf, client->conf);

	else if (client->soc.soc != -1 &&
			FD_ISSET (client->soc.soc, set_write))
		k = dispatch_server_write(&client->soc, &client->socks, &client->buf, client->conf);
	if (k < 0){ disconnection(client);	return;}

	/* Dispatch stream socket */
	if (client->soc_stream.soc != -1 && FD_ISSET (client->soc_stream.soc, set_read))
		k = dispatch_client_read(&client->soc_stream, &client->soc,
				&client->socks_stream, &client->stream_buf, &client->buf, client->conf);
	else if (client->soc_stream.soc != -1 &&
			FD_ISSET (client->soc_stream.soc, set_write))
		k = dispatch_client_write(&client->soc_stream, &client->socks_stream, &client->stream_buf, client->conf);
	if (k < 0){ disconnection(client);	return;}

	if (client->soc_bind.soc != -1 &&
			FD_ISSET (client->soc_bind.soc, set_read)){
		if ( build_request_accept_bind(&client->socks, client->conf,
				&client->soc, &client->soc_bind, &client->stream_buf) == 0 ){
			client->socks.state = S_W_REQ_ACK;
		}
	}

}

void init_select_client (s_socket *soc, s_socks *s, s_buffer *buf, int *maxfd,
		fd_set *set_read, fd_set *set_write)
{
	if ( soc->soc != -1 ){
		if ( s->state == S_R_VER_ACK ||
			 s->state == S_R_AUTH_ACK ||
			 s->state == S_R_REQ_ACK )
		{
			FD_SET(soc->soc, set_read);
		}else if (s->state == S_W_VER ||
				  s->state == S_W_AUTH ||
				  s->state == S_W_REQ)
		{
			FD_SET(soc->soc, set_write);
		}else if ( s->state == S_REPLY ){
			if ( buf_empty(buf) == 0 ){
				FD_SET(soc->soc, set_write);
			}else{
				FD_SET(soc->soc, set_read);
			}
		}
		
		if (soc->soc > *maxfd) *maxfd = soc->soc;
	}
}

void init_select_dynamic (int soc_ec, s_client *tc, int *maxfd,
		fd_set *set_read, fd_set *set_write)
{
    int nc;

    FD_ZERO (set_read);
    FD_ZERO (set_write);
    FD_SET (soc_ec, set_read);

    *maxfd = soc_ec;
    for (nc = 0; nc < MAXCLI; nc++){
		s_client *client = &tc[nc];

		if (client->socks_stream.state == S_REPLY &&  client->socks.state == S_WAIT){
			client->socks.state = S_REPLY;
			memcpy(&client->stream_buf, &client->buf, sizeof(s_buffer));
			init_buffer(&client->buf);
		}

		init_select_server_cli(&client->soc, &client->socks, &client->buf,
				maxfd, set_read, set_write);

		init_select_client(&client->soc_stream, &client->socks_stream, &client->stream_buf,
				maxfd, set_read, set_write);


		if ( client->soc_bind.soc != -1 ){
			FD_SET(client->soc_bind.soc, set_read);
			if (client->soc_bind.soc > *maxfd) *maxfd = client->soc_bind.soc;
		}
	}
}

int new_socket_with_socks(s_socket *s,
		char *sockshost, int socksport,
		char *username, char *password,
		char *host, int port, int listen,
		int version, int cmd)
{
	int maxfd = 0, res;
	fd_set set_read, set_write;
	
	s_socks_conf conf;
	s_socks_client_config config;
	conf.config.cli = &config;

	char method[] =  { 0x00, 0x02 };
	conf.config.cli->n_allowed_method = 2;
	conf.config.cli->allowed_method = method;
	
	/* If no username or password  we don't use auth */
	if ( username == NULL || password == NULL )
		--conf.config.cli->n_allowed_method;

	conf.config.cli->loop = 1;
	conf.config.cli->cmd = cmd;
	conf.config.cli->host = host;
	conf.config.cli->port = port;
	conf.config.cli->listen = listen;
	conf.config.cli->version = version;
	conf.config.cli->username = username;
	conf.config.cli->password = password;

	//memcpy(&conf.config, &config, sizeof(s_socks_serv_cli_config));
	
    s_client c;
	init_client (&c, 0, M_CLIENT, &conf);

	c.soc.soc = new_client_socket(sockshost, socksport, 
		&c.soc.adrC, &c.soc.adrS);
	if ( c.soc.soc < 0 ){
		return -1;
	}
	
    /* Select loop */
    while (conf.config.cli->loop  == 1 && c.soc.soc != -1) {

		FD_ZERO (&set_read);
		FD_ZERO (&set_write);
		maxfd = 0;

		/* Adds the socket in read fds */
		init_select_client(&c.soc, &c.socks, &c.buf, &maxfd, &set_read, &set_write);
		
		res = select (maxfd+1, &set_read, &set_write, NULL, NULL);
        if (res > 0) { 
            dispatch_client(&c, &set_read, &set_write);
        } else if ( res == 0){
		
        }else if (res < 0) {
            if (errno == EINTR) ; /* Received signal, it does nothing */
            else { perror ("select"); disconnection(&c); return -1; }
        }
	}
	
	memcpy(s, &c.soc, sizeof(s_socket));
	return (c.soc.soc >= 0);
}

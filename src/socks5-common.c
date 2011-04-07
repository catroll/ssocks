/*
 *      socks5-common.c
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

#include "socks5-common.h"
#include "output-util.h"

/* Read in buf_stream buffer on soc ( client socket )
 */
void read_server (Client *c){
	int k = 0;

	/* If we have free space in the buffer we read */
	 if ( c->buf_stream_b < (int)(sizeof(c->buf_stream) - 1) ){
		TRACE(L_DEBUG, "server [%d]: read packet server ...", c->id);
		if ( c->ver == SOCKS5_SSL_V && c->mode != M_DYNAMIC){
	#ifdef HAVE_LIBSSL
			TRACE(L_DEBUG, "server [%d]: ssl ...", c->id);
		    k = SSL_read (c->ssl,
					  c->buf_stream + c->buf_stream_b,
					  sizeof(c->buf_stream) - c->buf_stream_b - 1);
	#endif
		}else{
		    k = read (c->soc,
					  c->buf_stream + c->buf_stream_b,
					  sizeof(c->buf_stream) - c->buf_stream_b - 1);
		}

		if (k < 0) { perror ("read_server"); disconnection (c); return; }
		if (k == 0) { disconnection (c); return; }
		TRACE(L_DEBUG, "server [%d]: read %d bytes", c->id, k);

		/* Increase the counter
		 * and set buf_client_w flag to 1 mean
		 * we have data to write */
		c->buf_stream_b += k;
		c->buf_stream_w = 1;
	 }else{
		 ERROR(L_VERBOSE, "server [%d]: Oups server need more place!...", c->id);
	 }
}

/* Write the buf_client buffer on soc ( client socket )
 */
void write_server (Client *c){
	int k = 0;

	/* Normally with select we have something to write,
	 * (see in client.c init_select and the buf_client_w flag,
	 * maybe don't need check */
	if (c->buf_client_b - c->buf_client_a > 0) {
		TRACE(L_DEBUG, "server [%d]: write packet server ...", c->id);
		if ( c->ver == SOCKS5_SSL_V && c->mode != M_DYNAMIC){
#ifdef HAVE_LIBSSL
			TRACE(L_DEBUG, "server [%d]: ssl ...", c->id);
			k = SSL_write(c->ssl, c->buf_client + c->buf_client_a,
	        		c->buf_client_b - c->buf_client_a);
#endif
		}else{
			k = write (c->soc, c->buf_client + c->buf_client_a,
	        		c->buf_client_b - c->buf_client_a);
		}
        if (k < 0) { perror ("write socket"); disconnection (c); return; }
        TRACE(L_DEBUG, "server [%d]: wrote %d bytes", c->id, k);
        c->buf_client_a += k;

        if ( c->buf_client_b - c->buf_client_a == 0 ){
			c->buf_client_a = 0;
			c->buf_client_b = 0;
			c->buf_client_w = 0;
		}
    }
}

/* Read in buf_client buffer on soc_stream ( destination for the client )
 */
void read_client (Client *c){
	int k;

	/* If we have free space in the buffer we read */
	 if ( c->buf_client_b < (int)(sizeof(c->buf_client) - 1) ){
		TRACE(L_DEBUG, "server [%d]: client: read packet ...", c->id);
		k = read (c->soc_stream,
				  c->buf_client + c->buf_client_b,
				  sizeof(c->buf_client) - c->buf_client_b - 1);
		/* TODO: Take a look here too see if it close properly
		 * or if we need to close only soc_stream */
		if (k < 0) { perror ("read socket"); disconnection (c); return; }
		if (k == 0) {  disconnection(c); return; }
		TRACE(L_DEBUG, "server [%d]: client: read %d bytes", c->id, k);

		/* Increase the counter
		 * and set buf_client_w flag to 1 mean
		 * we have data to write */
		c->buf_client_b += k;
		c->buf_client_w = 1;
	 }
}

/* Write the buf_stream buffer on soc_stream ( destination for the client )
 */
void write_client (Client *c){
	int k;

	/* Normally with select we have something to write,
	 * (see in client.c init_select and the buf_stream_w flag,
	 * maybe don't need check */
	if (c->buf_stream_b-c->buf_stream_a > 0) {
		TRACE(L_DEBUG, "server [%d]: client: write packet client ...", c->id);
        k = write (c->soc_stream, c->buf_stream + c->buf_stream_a,
        		c->buf_stream_b - c->buf_stream_a);
        if (k < 0) { perror ("write socket"); disconnection (c); return; }
        TRACE(L_DEBUG, "server [%d]: client: wrote %d bytes", c->id, k);
        c->buf_stream_a += k;

        if ( c->buf_stream_b - c->buf_stream_a == 0 ){
			c->buf_stream_a = 0;
			c->buf_stream_b = 0;
			c->buf_stream_w = 0;
		}
    }
}

/* Read in buf_client buffer on soc_stream ( destination for the client )
 */
void read_client_ssl (Client *c){
	int k = 0;

	/* If we have free space in the buffer we read */
	 if ( c->buf_client_b < (int)(sizeof(c->buf_client) - 1) ){
		TRACE(L_DEBUG, "server [%d]: client: read packet client ssl ...", c->id);
#ifdef HAVE_LIBSSL
		k = SSL_read (c->ssl,
				  c->buf_client + c->buf_client_b,
				  sizeof(c->buf_client) - c->buf_client_b - 1);
#endif
		/* TODO: Take a look here too see if it close properly
		 * or if we need to close only soc_stream */
		if (k < 0) { perror ("read socket"); disconnection (c); return; }
		if (k == 0) {  disconnection(c); return; }
		TRACE(L_DEBUG, "server [%d]: client: read %d bytes", c->id, k);

		/* Increase the counter
		 * and set buf_client_w flag to 1 mean
		 * we have data to write */
		c->buf_client_b += k;
		c->buf_client_w = 1;
	 }
}

/* Write the buf_stream buffer on soc_stream ( destination for the client )
 */
void write_client_ssl (Client *c){
	int k = 0;

	/* Normally with select we have something to write,
	 * (see in client.c init_select and the buf_stream_w flag,
	 * maybe don't need check */
	if (c->buf_stream_b-c->buf_stream_a > 0) {
		TRACE(L_DEBUG, "server [%d]: client: write packet client ssl ...", c->id);
#ifdef HAVE_LIBSSL
        k = SSL_write (c->ssl, c->buf_stream + c->buf_stream_a,
        		c->buf_stream_b - c->buf_stream_a);
#endif
        if (k < 0) { perror ("write socket"); disconnection (c); return; }
        TRACE(L_DEBUG, "server [%d]: client: wrote %d bytes", c->id, k);
        c->buf_stream_a += k;

        if ( c->buf_stream_b - c->buf_stream_a == 0 ){
			c->buf_stream_a = 0;
			c->buf_stream_b = 0;
			c->buf_stream_w = 0;
		}
    }
}


/*
 *      ssocks.c
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

#include "bor-util.h"
#include "net-util.h"
#include "bor-timer.h"

#include "socks5-client.h"
#include "socks5-server.h"
#include "socks5-common.h"

#include <getopt.h>


#define PORT 1080

int boucle_princ = 1;
void capte_fin (int sig)
{
    printf ("Serveur: signal %d capté\n", sig);
    boucle_princ = 0;
}

void usage(char *name){
	printf("Server Socks5 v%s\n", "0.1");
	printf("Options:\n");
	printf("\t--verbose (-v) set verbose level\n");
	printf("------------------------------------------------------------\n");
	printf("\t--port <port> (-p port) set verbose mode\n");
	printf("\t--host <host> (-h port) set verbose mode\n");
	printf("------------------------------------------------------------\n");
	printf("Usage:\n");
	printf("\t%s --port 1080 --host localhost\n", name);
}

void server(char *sockshost, int socksport, int port){
    int soc_ec = -1, maxfd, res, nc;  
    Client tc[MAXCLI]; 
    ConfigDynamic config;
    config.host = sockshost;
    config.port = socksport;
    
    fd_set set_read;
    fd_set set_write;
    
    /* Init client tab */
    for (nc = 0; nc < MAXCLI; nc++) init_client (&tc[nc], nc, M_DYNAMIC, &config);
    
    soc_ec = new_listen_socket (port, MAXCLI); 
    if (soc_ec < 0) goto fin_serveur;
    
    bor_signal (SIGINT, capte_fin, SA_RESTART);
    
    while (boucle_princ) {
        init_select_dynamic (soc_ec, tc, &maxfd, &set_read, &set_write);
        
        res = select (maxfd+1, &set_read, &set_write, NULL, bor_timer_delay());

        if (res > 0) {  /* Search eligible sockets */
            if (FD_ISSET (soc_ec, &set_read))
                if (new_connection (soc_ec, tc) < 0) goto fin_serveur;
            
            for (nc = 0; nc < MAXCLI; nc++){
				if ( tc[nc].state != E_WAIT ){
					if (tc[nc].soc != -1 && FD_ISSET (tc[nc].soc, &set_read))
						dispatch_server_read (&tc[nc]);
					else if (tc[nc].soc != -1 && FD_ISSET (tc[nc].soc, &set_write))
						dispatch_server_write (&tc[nc]);
                }
                    
				if (tc[nc].soc_stream != -1 && FD_ISSET (tc[nc].soc_stream, &set_read)){
					dispatch_client(&tc[nc]);
				}else if(tc[nc].soc_stream != -1 && FD_ISSET (tc[nc].soc_stream, &set_write)){
					dispatch_client(&tc[nc]);
				}
			}
                
        } else if ( res == 0){
            /* Client timeout
            int handle = bor_timer_handle();
            for (nc = 0; nc < MAXCLI; nc++)
                if (tc[nc].handle == handle){
                    printf("Serveur [%d]: timeout\n", nc);
                    disconnection (&tc[nc]);
                }
            */
        }else if (res < 0) { 
            if (errno == EINTR) ; /* Signal reçu, on ne fait rien */
            else { perror ("select"); goto fin_serveur; }
        }
    }   

fin_serveur: 
    printf ("Serveur: closing sockets ...\n");
    //fclose (stdout); 
    //fclose (stderr); 
    if (soc_ec != -1) close (soc_ec); 
    for (nc = 0; nc < MAXCLI; nc++) raz_client (&tc[nc]);
}





void unit_creer_socket_with_socks(){
	int soc, k;
	char buf[4096];
	char *host = "dedi.codsec.com";
	char *script = "~y0ug/";
	char *uname = "y0ug";
	char *passwd = "1234";
	
	soc = new_socket_with_socks("localhost", 1080, host, 80, uname, passwd, 0);
	if ( soc < 0 ){
		fprintf(stderr, "test: connexion error\n");
		exit(1);
	}
	
	snprintf(buf, sizeof(buf), "GET /%s HTTP/1.1\nHost: %s\n\n", script, host);
	k = write(soc, buf, strlen(buf));
	if ( k<0 ){ perror("write"); close(soc); exit(1); }
	printf("test: envoié %d octets\n", k);
	k = read(soc, buf, sizeof(buf)-1);
	if ( k<0 ){ perror("read"); close(soc); exit(1); }
	if ( k == 0 ) { fprintf(stderr,"test: deconnexion read 0\n"); close(soc); exit(1); }
	buf[k] = 0;
	printf("test: reçu %d octets\n", k);
	printf("%s", buf);
	
	close(soc);	
}

/*int main (int argc, char *argv[]){*/
int main (){
	server("localhost", 1080, 1088);
	/*unit_creer_socket_with_socks();*/

	exit(0);
}

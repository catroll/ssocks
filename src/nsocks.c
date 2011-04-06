/*
 *      nsocks.c
 * 
 * 		Netcat like who pass through a socks5
 * 
 *      Created on: 2011-04-01
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
#include "output-util.h"
#include "socks5-client.h"

#include <config.h>
#include <getopt.h>




int boucle_princ = 1;
void capte_fin (int sig){
    TRACE(L_VERBOSE, "client: signal %d caught\n", sig);
    boucle_princ = 0;
}

void netcat_like(int soc){
	/* Catch CTRL-C */
    bor_signal (SIGINT, capte_fin, SA_RESTART);
    
	int maxfd=0, res;
	fd_set set_read, set_write;
	char buf[4096];
	int buf_a = 0, buf_b = 0, k;
	
	while (boucle_princ){
		FD_ZERO (&set_read);
		FD_ZERO (&set_write);
		
		FD_SET (0, &set_read);
		FD_SET (soc, &set_read);
		if (soc > maxfd) maxfd = soc; /* Fix maxfd */	
		
		if ( buf_b - buf_a > 0 ){
			FD_SET (soc, &set_write);
		}
		
		res = select (maxfd+1, &set_read, &set_write, NULL, bor_timer_delay());
        if (res > 0) {  /* Search eligible sockets */
			
			/* Read on stdin ? */
			if (FD_ISSET (0, &set_read)){
				k = read(0, buf+buf_b, sizeof(buf)-buf_b-1);
				if ( k < 0 ) { perror("read stdin"); close(soc); exit(1); }
				if ( k == 0 ) { ERROR(L_DEBUG, "client: read 0 bytes on stdin\n"); boucle_princ = 0; }
				//printf("client: read %d bytes in stdin\n", k);
				buf_b += k;			
			}
			
			/* Read on socket ? */
			if (FD_ISSET (soc, &set_read)){
				k = read(soc, buf+buf_b, sizeof(buf)-buf_b-1);
				if ( k < 0 ) { perror("read socket"); close(soc); exit(1); }
				if ( k == 0 ) { ERROR(L_DEBUG, "client: read 0 bytes!\n"); boucle_princ = 0; }
				//printf("client: read %d bytes in socket\n", k);	
				k = write(1, buf, k);
			}
			
			/* Write on socket ? */
			if(FD_ISSET (soc, &set_write)){
				k = write(soc, buf+buf_a, buf_b - buf_a);
				if ( k < 0 ) { perror("write socket"); boucle_princ = 0; }
				//printf("client: wrote %d bytes on socket\n", k);
				buf_a += k;
				if ( buf_b - buf_a == 0 ){
					buf_b = 0;
					buf_a = 0;	
				}
			}		
			
        } else if ( res == 0){
            /* Timeout */
                
        }else if (res < 0) { 
            if (errno == EINTR) ; /* Received signal, it does nothing */
            else { perror ("select"); boucle_princ = 0; }
        }
	}	
}

void netcat_socks(char *hostsocks, int portsocks, 
				char *host, int port, 
				char *uname, char *passwd){

	int soc;
	
	soc = new_socket_with_socks(hostsocks, portsocks, host, port, uname, passwd, 0);
	if ( soc < 0 ){
		ERROR(L_NOTICE, "client: connection error");
		exit(1);
	}
	
	TRACE(L_VERBOSE, "client: established connection");
	netcat_like(soc);
	TRACE(L_VERBOSE, "client: close socket ...");
	
	close(soc);
}

void netcat_socks_bind(char *hostsocks, int portsocks, 
				char *host, int port, 
				char *uname, char *passwd){

	int soc_ec;
	
	soc_ec = new_socket_with_socks(hostsocks, portsocks, host, port, uname, passwd, 1);
	if ( soc_ec < 0 ){
		ERROR(L_NOTICE, "client: connection error");
		exit(1);
	}
	
	TRACE(L_VERBOSE, "client: established connection");
	netcat_like(soc_ec);
	TRACE(L_VERBOSE, "client: close socket ...");
	
	close(soc_ec);
}

struct globalArgs_t {
	char *host;				// -h option
	unsigned int port;		// -p option
	unsigned int listen;	// -l option
	unsigned int verbosity;	// -v
	char *uname;			// -u option
	char *passwd;			// -p option
	
	char *sockshost;		// -s host:port
	int socksport;

} globalArgs;

void usage(char *name){
	printf("nsocks v%s ( Netcat like with Socks5 support )\n", PACKAGE_VERSION);
	printf("Actually close on EOF (CTRL-D)\n");
	printf("Usage:\n");
	printf("\t%s --socks localhost:1080 mywebserv.com 80\n", name);
	printf("\t%s -s localhost:1080 -u y0ug -p 1234 mywebserv.com 80\n", name);
	printf("\t%s -s localhost:1080 -l 8080\n", name);
	printf("Options:\n");
	printf("\t--verbose (increase verbose level)\n\n");
	printf("\t--socks {host:port}\n");
	printf("\t--uname {uname}\n");
	printf("\t--passwd {passwd}\n");
	printf("\t--listen {port}\n");
	printf("\n");
	printf("Bug report %s\n", PACKAGE_BUGREPORT);
}

void parseArg(int argc, char *argv[]){
	memset(&globalArgs, 0, sizeof(globalArgs));

	int c;
	while (1){
		static struct option long_options[] = {
			{"help",    no_argument,       0, 'h'},
			{"verbose", no_argument,       0, 'v'},
			{"socks",   required_argument, 0, 's'},
			{"uname",   required_argument, 0, 'u'},
			{"passwd",  required_argument, 0, 'p'},
			{"listen",  required_argument, 0, 'l'},
			{0, 0, 0, 0}
		};

		/* getopt_long stores the option index here. */
		int option_index = 0;

		c = getopt_long (argc, argv, "h?vs:u:p:l:",
					long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

		char *port;

		switch (c)	{
			case 0:
				/* If this option set a flag, do nothing else now. */
				if (long_options[option_index].flag != 0)
					break;
				printf ("option %s", long_options[option_index].name);
				if (optarg)
					printf (" with arg %s", optarg);
				printf ("\n");
				break;

			case 'v':
				//globalArgs.verbosity++;
				verbosity++;
				break;

			case 's':

				port = strchr(optarg, ':');
				if ( port == NULL ){
					usage(argv[0]);
					exit(1);
				}
				*port = 0; port++;
				globalArgs.sockshost = optarg;
				globalArgs.socksport = atoi(port);
				/*printf("Connect trought socks %s:%d\n",
					globalArgs.sockshost, globalArgs.socksport);*/
				break;

			case 'u':
				/* printf("Username: %s\n", optarg); */
				globalArgs.uname = optarg;
				break;

			case 'p':
				/* printf("Passwd: %s\n", optarg); */
				globalArgs.passwd = optarg;
				break;

			case 'l':
				/* printf("Listening on port: %d\n", atoi(optarg)); */
				globalArgs.listen = atoi(optarg);
				break;

			case '?':
				/* getopt_long already printed an error message. */
				usage(argv[0]);
				exit(1);
				break;

			case 'h':
				usage(argv[0]);
				exit(1);
				break;

			default:
				abort ();
		}
	}

	if (argc - optind == 2 ){
		globalArgs.host = argv[optind++];
		globalArgs.port = atoi(argv[optind++]);
	}else if(globalArgs.listen != 0){

	}else{
		usage(argv[0]);
		exit(1);
	}

	if ( globalArgs.sockshost == NULL || globalArgs.socksport == 0 ){
		usage(argv[0]);
		exit(1);
	}
}

int main (int argc, char *argv[]){
	parseArg(argc, argv);
	
	if ( globalArgs.listen != 0 )
		netcat_socks_bind(globalArgs.sockshost, globalArgs.socksport, 
					"0.0.0.0", globalArgs.listen, 
					globalArgs.uname, globalArgs.passwd);
	else
		netcat_socks(globalArgs.sockshost, globalArgs.socksport, 
					globalArgs.host, globalArgs.port, 
					globalArgs.uname, globalArgs.passwd);	
	exit(0);
}

/*
 *      ssocksd.c
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

#include "net-util.h"
#include "bor-timer.h"
#include "output-util.h"

#include "socks5-server.h"
#include "socks5-common.h"

#include "auth-util.h"
#include "log-util.h"
#include "configd-util.h"

#include <getopt.h>
#include <unistd.h>
#include <config.h>

#define DEFAULT_PORT 1080
#define PID_FILE "/var/run/ssocksd.pid"

int boucle_princ = 1;
void capte_fin (int sig){
    printf ("serveur: signal %d caught\n", sig);
    boucle_princ = 0;
}

void usage(char *name){
	printf("ssockd - Server Socks5 v%s\n", PACKAGE_VERSION);

	printf("Usage:\n");
	printf("\t%s --port 8080\n", name);
	printf("\t%s -p 8080 -a ssocksd.auth -d\n", name);
	printf("\t%s -vv\n", name);
	printf("\n");
	printf("Options:\n");
	printf("\t--daemon   daemon mode (background)\n");
	printf("\t--verbose  increase verbose level\n\n");
	printf("\t--port {port}  listening port (default 1080)\n");
	printf("\t--file {file}  see man 5 ssocksd.conf\n");
	printf("\t--auth {file}  see man 5 ssocksd.auth\n");
	printf("\t--log {file}   if set connections are log in this file\n");
	printf("\n");
	printf("Bug report %s\n", PACKAGE_BUGREPORT);
}

/* TODO: Add --pid-file option to server
 */
void parseArg(int argc, char *argv[]){
	int c;
	
	globalArgsServer.fileauth[0] = 0;
	globalArgsServer.filelog[0] = 0;
	globalArgsServer.fileconfig[0] = 0;
	globalArgsServer.port = DEFAULT_PORT;
	globalArgsServer.verbosity = 0;
	globalArgsServer.guest = 1;
	
	while (1){
		static struct option long_options[] = {
			{"help", no_argument,       0, 'h'},
			{"verbose", no_argument,       0, 'v'},
			{"daemon",     no_argument,       0, 'd'},
			{"guest",     no_argument,       0, 'g'},
			{"port",  required_argument, 0, 'p'},
			{"file",  required_argument, 0, 'f'},
			{"auth",    required_argument, 0, 'a'},
			{"log",  required_argument, 0, 'l'},
			{0, 0, 0, 0}
		};
		
		/* getopt_long stores the option index here. */
		int option_index = 0;

		c = getopt_long (argc, argv, "h?vgdf:a:p:l:",
					long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

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
				globalArgsServer.verbosity++;
				verbosity++;
				break;

			case 'd':
				globalArgsServer.daemon = 1;
				break;
				
			case 'g':
				globalArgsServer.guest = 1;
				break;
				
			case 'p':
				globalArgsServer.port = atoi(optarg);
				break;

			case 'a':
				strcpy(globalArgsServer.fileauth, optarg);
				break;
				
			case 'l':
				strcpy(globalArgsServer.filelog, optarg);
				break;
				
			case 'f':
				strcpy(globalArgsServer.fileconfig, optarg);
				if ( loadConfigFile(optarg, &globalArgsServer) < 0 ){
					ERROR(L_NOTICE, "config: config file error\n");
					ERROR(L_NOTICE, "server: can't start misconfiguration");
					exit(1);
				}	
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
	

	if ( globalArgsServer.filelog[0] != 0 ){
		openLog(globalArgsServer.filelog);
	}
	if ( globalArgsServer.fileauth[0] != 0 ){
		globalArgsServer.guest = 0;
		if ( (c = load_auth_file(globalArgsServer.fileauth)) <= 0 ){
			ERROR(L_NOTICE, "auth: no username load");
			ERROR(L_NOTICE, "server: can't start misconfiguration");
			exit(1);
		}else{
			TRACE(L_NOTICE, "auth: %d usernames load", c);
		}
	}else{
		TRACE(L_NOTICE, "warning: no authentification enable");
	}

	verbosity = globalArgsServer.verbosity;

}

void capte_usr1(){
	TRACE(L_DEBUG, "server: catch USR1 signal ...");
}

void server(int port){
    int soc_ec = -1, maxfd, res, nc;  
    Client tc[MAXCLI];  
    fd_set set_read;
    fd_set set_write;
    
    /* Init client tab */
    for (nc = 0; nc < MAXCLI; nc++) init_client (&tc[nc], nc, 0, NULL);
    
    soc_ec = new_listen_socket (port, 0);
    if (soc_ec < 0) goto fin_serveur;
    
	
	if ( globalArgsServer.daemon == 1 ){
		TRACE(L_NOTICE, "server: mode daemon ...");
		if ( daemon(0, 0) != 0 ){
			perror("daemon");
			exit(1);
		}
		writePID(PID_FILE);
	}    
    
    bor_signal (SIGINT, capte_fin, SA_RESTART);

    /* Need in daemon to remove the PID file properly */
    bor_signal (SIGTERM, capte_fin, SA_RESTART);

    /* TODO: Find a better way to exit the select and recall the init_select
     * SIGUSR1 is send by a thread to unblock the select */
    bor_signal (SIGUSR1, capte_usr1, SA_RESTART);

    while (boucle_princ) {
        init_select (soc_ec, tc, &maxfd, &set_read, &set_write);
        
        res = select (maxfd+1, &set_read, &set_write, NULL, NULL);

        if (res > 0) { /* Search eligible sockets */
            if (FD_ISSET (soc_ec, &set_read))
                if (new_connection (soc_ec, tc) < 0) goto fin_serveur;
            
            for (nc = 0; nc < MAXCLI; nc++){
				
                if (tc[nc].soc != -1 && FD_ISSET (tc[nc].soc, &set_read))
                    dispatch_server_read (&tc[nc]);

                else if (tc[nc].soc != -1 &&
                		FD_ISSET (tc[nc].soc, &set_write))
                    dispatch_server_write (&tc[nc]);
                

                if (tc[nc].soc_stream != -1 &&
                		FD_ISSET (tc[nc].soc_stream, &set_read))
                    read_client (&tc[nc]);

                else if (tc[nc].soc_stream != -1 &&
                		FD_ISSET (tc[nc].soc_stream, &set_write))
                    write_client (&tc[nc]);
                    

                 if (tc[nc].soc_bind != -1 &&
                		 FD_ISSET (tc[nc].soc_bind, &set_read))
					build_request_bind(&tc[nc]);
			}
                
        } else if ( res == 0){

            //int handle = bor_timer_handle();
            /*for (nc = 0; nc < MAXCLI; nc++)
                if (tc[nc].handle == handle){
                    TRACE(L_VERBOSE, "server [%d]: client timeout\n", nc);
                    disconnection (tc, nc);
                }*/
                
        }else if (res < 0) { 
            if (errno == EINTR) ; /* Received signal, it does nothing */
            else { perror ("select"); goto fin_serveur; }
        }
    }   

fin_serveur: 
    TRACE(L_NOTICE, "server: closing sockets ...");

    if (soc_ec != -1) close (soc_ec);
    closeLog();
    for (nc = 0; nc < MAXCLI; nc++) raz_client (&tc[nc]);
    if ( globalArgsServer.daemon == 1 )	removePID(PID_FILE);
}

int main (int argc, char *argv[]){
	parseArg(argc, argv);
	server(globalArgsServer.port);
    exit (0);
}

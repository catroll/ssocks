/*
 *      rcsocks
 *
 *      Created on: 2011-04-13
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

#include <libsocks/bor-util.h>
#include <libsocks/net-util.h>

#include <libsocks/output-util.h>
#include <libsocks/socks-common.h>
#include <libsocks/socks5-client.h>
#include <libsocks/socks5-server.h>

#include <config.h>
#include <getopt.h>


#define PORT 1080

struct globalArgs_t {
	char *host;				// -h option
	unsigned int port;		// -p option
	unsigned int listen;	// -l option
	unsigned int verbosity;	// -v
	unsigned int background;// -b

#ifdef HAVE_LIBSSL
	unsigned int ssl;		// -k option
	char *certfile;			// -c option
#endif

	char *uname;			// -u option
	char *passwd;			// -p option

	char *sockshost;		// -s host:port
	int socksport;
} globalArgs;

int boucle_princ = 1;
void capte_fin (int sig){
    TRACE(L_VERBOSE, "server: signal %d caught\n", sig);
    boucle_princ = 0;
}

/*
 * TODO: Bind localhost not 0.0.0.0
 */
void usage(char *name){
	printf("rcSocks Reverse Client Socks5 v%s\n", PACKAGE_VERSION);
	printf("Usage:\n");
	printf("\t%s -p 1088 -l 1080 -b\n", name);
	printf("Options:\n");
	printf("\t--verbose (increase verbose level)\n\n");
	printf("\t--listen {port}\n");
	printf("\t--port {port}\n");
#ifdef HAVE_LIBSSL
	printf("\t--cert  {certfile.crt} Certificate of dst server (enable SSL)\n");
#endif
	printf("\t--background\n");
	printf("\n");
	printf("Bug report %s\n", PACKAGE_BUGREPORT);
}

void capte_usr1(){
	TRACE(L_DEBUG, "server: catch USR1 signal ...");
}

void new_connection_reverse (int soc_ec, s_client *tc, s_socket *socks_pool)
{
    int nc, nc2, soc_tmp;
    struct sockaddr_in adrC_tmp;

    TRACE(L_DEBUG, "server: connection in progress ...");
    soc_tmp = bor_accept_in (soc_ec, &adrC_tmp);
    if (soc_tmp < 0) { return; }

    /* Search free space in tc[].soc */
    for (nc = 0; nc < MAXCLI; nc++)
        if (tc[nc].soc.soc == -1) break;

    /* Search for a relay in socks_pool */
    for (nc2 = 0; nc2 < MAXCLI; nc2++)
        if (socks_pool[nc2].soc != -1) break;

    if (nc < MAXCLI && nc2 < MAXCLI) {
    	init_client(&tc[nc], tc[nc].id, tc[nc].socks.mode, tc[nc].conf);
        tc[nc].soc.soc = soc_tmp;
        tc[nc].socks.state = S_REPLY;

        memcpy(&tc[nc].soc_stream, &socks_pool[nc2], sizeof(s_socks));

        /* Remove from the pool */
        socks_pool[nc2].soc = -1;

        memcpy(&tc[nc].soc.adrC, &adrC_tmp, sizeof(struct sockaddr_in));
        TRACE(L_VERBOSE, "server [%d]: established connection with %s",
            nc, bor_adrtoa_in(&adrC_tmp));

        //append_log_client(&tc[nc], "%s", bor_adrtoa_in(&adrC_tmp));
		//set_non_blocking(tc[nc].soc);
    } else {
        close (soc_tmp);
        ERROR (L_NOTICE, "server: %s connection refused : too many clients!",
            bor_adrtoa_in(&adrC_tmp));
    }

}

void new_connection_socket(int soc_ec, s_socket *tc)
{
    int nc, soc_tmp;
    struct sockaddr_in adrC_tmp;

    TRACE(L_DEBUG, "server: connection server in progress ...");
    soc_tmp = bor_accept_in (soc_ec, &adrC_tmp);
    if (soc_tmp < 0) { return; }

    /* Search free space in tc[].soc */
    for (nc = 0; nc < MAXCLI; nc++)
        if (tc[nc].soc == -1) break;

    if (nc < MAXCLI) {
    	init_socket(&tc[nc]);
        tc[nc].soc = soc_tmp;
        memcpy (&tc[nc].adrC, &adrC_tmp, sizeof(struct sockaddr_in));
        TRACE(L_VERBOSE, "server [%d]: established server connection with %s",
            nc, bor_adrtoa_in(&adrC_tmp));

        //append_log_client(&tc[nc], "%s", bor_adrtoa_in(&adrC_tmp));
		//set_non_blocking(tc[nc].soc);
    } else {
        close (soc_tmp);
        ERROR (L_NOTICE, "server: %s connection refused : too many clients!",
            bor_adrtoa_in(&adrC_tmp));
    }
}

void init_select_reverse (int soc_ec, int soc_ec_cli, s_client *tc, int *maxfd,
		fd_set *set_read, fd_set *set_write)
{
    int nc;
    /* TODO: move FD_ZERO */
    FD_ZERO (set_read);
    FD_ZERO (set_write);

    FD_SET (soc_ec, set_read);
    FD_SET (soc_ec_cli, set_read);

    *maxfd = soc_ec_cli;
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

void server_relay(int port, int listen, int ssl){
    int soc_ec_cli = -1, soc_ec = -1, maxfd, res, nc;
    fd_set set_read;
    fd_set set_write;
    struct sockaddr_in addrS;



    s_socket socks_pool[MAXCLI];
    s_client tc[MAXCLI];

    /* Init client tab */
    for (nc = 0; nc < MAXCLI; nc++)
    	init_socket(&socks_pool[nc]);

    for (nc = 0; nc < MAXCLI; nc++)
    	init_client (&tc[nc], nc, 0, NULL);

    soc_ec = new_listen_socket (port, MAXCLI, &addrS);
    if (soc_ec < 0) goto fin_serveur;

    soc_ec_cli = new_listen_socket (listen, MAXCLI, &addrS);
    if (soc_ec_cli < 0) goto fin_serveur;

	if ( globalArgs.background == 1 ){
		TRACE(L_NOTICE, "server: background ...");
		if ( daemon(0, 0) != 0 ){
			perror("daemon");
			exit(1);
		}
	}

    bor_signal (SIGINT, capte_fin, SA_RESTART);

    /* TODO: Find a better way to exit the select and recall the init_select
     * SIGUSR1 is send by a thread to unblock the select */
    bor_signal (SIGUSR1, capte_usr1, SA_RESTART);
    while (boucle_princ) {
    	init_select_reverse(soc_ec, soc_ec_cli, tc, &maxfd, &set_read, &set_write);

        res = select (maxfd+1, &set_read, &set_write, NULL,NULL);

        if (res > 0) {  /* Search eligible sockets */

            if (FD_ISSET (soc_ec, &set_read))
               new_connection_socket (soc_ec, socks_pool);

            if (FD_ISSET (soc_ec_cli, &set_read))
                new_connection_reverse (soc_ec_cli, tc, socks_pool);

            for (nc = 0; nc < MAXCLI; nc++){
            	dispatch_server(&tc[nc], &set_read, &set_write);
			}
        } else if ( res == 0){
            /* If timeout was set in select and expired */
        }else if (res < 0) {
            if (errno == EINTR) ;  /* Received signal, it does nothing */
            else { perror ("select"); goto fin_serveur; }
        }
    }

fin_serveur:
#ifdef HAVE_LIBSSL
	if (ssl == 1)
		ssl_cleaning();
#endif
    printf ("Server: closing sockets ...\n");
    if (soc_ec != -1) close (soc_ec);
    for (nc = 0; nc < MAXCLI; nc++) close_socket(&socks_pool[nc]);
    for (nc = 0; nc < MAXCLI; nc++) disconnection(&tc[nc]);
}


void parse_arg(int argc, char *argv[]){
	memset(&globalArgs, 0, sizeof(globalArgs));

	int c;
	while (1){
		static struct option long_options[] = {
			{"help",    no_argument,       0, 'h'},
			{"verbose", no_argument,       0, 'v'},
			{"background", no_argument,    0, 'b'},
			{"listen",  required_argument, 0, 'l'},
			{"port",  required_argument, 0, 'p'},
#ifdef HAVE_LIBSSL
			{"cert",      required_argument, 0, 'c'},
#endif
			{0, 0, 0, 0}
		};

		/* getopt_long stores the option index here. */
		int option_index = 0;

		c = getopt_long (argc, argv, "h?bvc:p:l:",
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
				//globalArgs.verbosity++;
				verbosity++;
				break;

#ifdef HAVE_LIBSSL
			case 'c':
				globalArgs.ssl = 1;
				globalArgs.certfile = optarg;
				break;
			case 'k':
				globalArgs.ssl = 1;
				break;
#endif

			case 'b':
				globalArgs.background = 1;
				break;

			case 'p':
				/* printf("Passwd: %s\n", optarg); */
				globalArgs.port = atoi(optarg);
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

#ifdef HAVE_LIBSSL
	/*Initialize ssl with the CA certificate file
	 */
	if (globalArgs.certfile != NULL){
		SSL_load_error_strings();  /* readable error messages */
		SSL_library_init();        /* initialize library */
		TRACE(L_VERBOSE, "client: init ssl ...");
		if (globalArgs.certfile == NULL){
			ERROR(L_NOTICE, "client: actually need CA certificate file");
			exit(1);
		}
		if ( ssl_init_client(globalArgs.certfile) != 0){
			ERROR(L_NOTICE, "client: ssl config error");
			exit(1);
		}
		TRACE(L_VERBOSE, "client: ssl ok.");
	}
#endif
}


int main (int argc, char *argv[]){
	parse_arg(argc, argv);
	server_relay(globalArgs.port, globalArgs.listen,
#ifdef HAVE_LIBSSL
			globalArgs.ssl
#else
			0
#endif
			);
	exit(0);
}

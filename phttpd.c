/*****************************************
   pHTTPd

   Started 2010-10-13 by Petter Rodhelind

 *****************************************/


/*
   include och define
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>

#define DEFAULTPORT 8080
#define BACKLOG 1			
#define MAX_ALLOWED_CLIENTS 100	// +1 for desired value (3 gives 2 allowed clients)
#define BUFSIZE	8192			// bytes

#define ERROR 666
#define WARNING 667
#define INFO 668

/* global variables */

// allowed file extensions
struct {
	char *ext;
	char *mime;
} extension[] = {
	{"htm"	,	"text/html"},
	{"html"	,	"text/html"},
	{"txt"	,	"text/plain"},
	{"gif"	,	"image/gif"},
	{"jpg"	,	"image/jpeg"},
	{"jpeg"	,	"image/jpeg"},
	{"png"	,	"image/png"},
	{"bmp"	,	"image/bmp"},
	{"ico"	,	"image/x-icon"},
	{0,0}
};

// placeholder for client connections
struct Client_t {
	int socket;
	struct sockaddr_in addr;
	time_t time_of_connection;	// used for time-out and prevention of DoS-attacks *** NOT IMPLEMENTED ***
} client[MAX_ALLOWED_CLIENTS];

// keep track of server uptime, just for fun
time_t server_start_time;

// global log message
char logbuf[BUFSIZE*2]; // to be able to hold the entire network buffer along with some overhead data


/* log server messages and activity */

void logging(int status, char *msg) {
	switch (status) {
		case ERROR:
			printf("[ERROR] %s\n", msg);
			exit(1);
			break;
		case WARNING:
			printf("[WARN] %s\n", msg);
			break;
		case INFO:
			printf("[INFO] %s\n", msg);
			break;
		default:
			printf("%s\n", msg);
			break;
	}
}


/* error message */

void error(char *msg) {
	perror(msg);
	exit(1);
}


/* numeric string check */

int isnumeric(char *str) {
	while (*str) {
		if (!isdigit(*str))
			return 0;
		str++;
	}
	return 1;
}


/* calculate time since given time_t */

unsigned int getUptime(time_t t) {
	return (unsigned int) (time(0) - t);
}


/* close an open client connection */

int close_client_connection(struct Client_t *cli) {
	int temp_sock = cli->socket;
	close(cli->socket);
	cli->socket = 0;
	sprintf(logbuf, "Closed connection (%s on socket %d after %d seconds)\n", inet_ntoa(cli->addr.sin_addr), temp_sock, getUptime(cli->time_of_connection));
	logging(INFO, logbuf);

	return 0;
}


/* send a server response */

int send_response(struct Client_t *cli, char *msg) {
	char sdata[BUFSIZE];
	memset(&sdata, '\0', BUFSIZE);
	strcpy(sdata, msg);
	strcat(sdata, "\n\r");

	int len = strlen(sdata) + 1;	// include '\0'
	int sc;

	if ((sc = send(cli->socket, sdata, len, 0)) == -1)
		return -1;
	if (sc < len) {
		return -2;
	}

	return 0;
}


/* verify access to any given file or directory
   return value of 1 is good */

int check_access(char *fn) {
	int i, fd;
	/* don't allow parent directory, ie URLs containing '..' */
	for (i=0; i<sizeof fn; i++)
		if (fn[i]=='.' && fn[i+1]=='.')
			return 0;

	if((fd=open(fn, O_RDONLY)) == -1)
		return 0;
	else {
		close(fd);
		return 1;
	}
}


/* the real stuff - processing of data in and out */

int web(struct Client_t *cli) {

	int i;

	/* recieve data */
	static char buffer[BUFSIZE+1];
	memset(buffer, '\0', sizeof buffer);
	int rc = recv(cli->socket, buffer, sizeof buffer, 0);
	if (!(rc < BUFSIZE+1)) // buffer overflow
		return 0;
	
	/* check number of bytes recieved */
	if (rc == 0) { // exit signal
		close_client_connection(cli);
	}
	else if (rc < 0) { // -1 means error
		sprintf(logbuf, "%s: Recieve error\n%s", inet_ntoa(cli->addr.sin_addr), strerror(errno));
		logging(ERROR, logbuf);
	}
	else {	// if recieved data is more than 0 bytes

		/* log incoming buffer */
		/*sprintf(logbuf, "From: %s\n%s", inet_ntoa(cli->addr.sin_addr), buffer);
		logging(INFO, logbuf);*/

		/* remove CR and LF - parse only the first line of the incoming data */
		for (i=0; i<rc; i++) 
			if ((buffer[i]=='\r') || (buffer[i]=='\n'))
				buffer[i]='\0';

		/* log incoming buffer */
		sprintf(logbuf, "\tFrom: %s\n\t%s", inet_ntoa(cli->addr.sin_addr), buffer);
		logging(INFO, logbuf);

		/* Allowed HTTP commands */
		if (!strncmp(buffer, "GET ", 4) || !strncmp(buffer, "get ", 4)) {			
			/* cut off the data after the second space (leaves "GET <url>") */
			for (i=4; i<rc; i++)
				if (buffer[i]==' ')
					buffer[i] = '\0';

			/* get requested filename */
			char *file;
			file = malloc(sizeof(char)*strlen(buffer));
			// set to default index file if / is given
			if (!strncmp(buffer, "GET /\0", 6) || !strncmp(buffer, "get /\0", 6)) {
				free(file);
				strcpy(file, "index.html");
			}
			else {
				free(file);
				file = &buffer[5]; // 5 for stripping out "GET " including the space character
			}
			
			/* log what file the client requests */
			sprintf(logbuf, "\tFile: %s", file);
			logging(INFO, logbuf);

			/* check for valid extension and file type */
			char *mime;
			int fileLen, extLen;
			mime = (char *) 0;
			fileLen = strlen(file);
			for (i=0; extension[i].ext != 0; i++) {
				extLen = strlen(extension[i].ext);
				if ( !strncmp(&file[fileLen-extLen], extension[i].ext, extLen) ) {
					mime = extension[i].mime;
					break;
				}
			}

			/* check for valid file access */
			if (!check_access(file)) {
				send_response(cli, "HTTP/1.0 404 Not found\r\nContent-type: text/html\r\n\r\n<h1>404 Not found</h1>File not found."); // don't bother with 403 :p
				close_client_connection(cli);
			}
			/* if file type not supported, abort */
			else if (mime == 0) {
				sprintf(logbuf, "\tFile extension type not supported. Ignoring file request and sending 415.");
				logging(WARNING, logbuf);
				send_response(cli, "HTTP/1.0 415 Unsupported media type\r\nContent-type: text/html\r\n\r\n<h1>415 Unsupported media type</h1>The file type is not supported by this server.");
				close_client_connection(cli);
			}
			/* open requested file and send header and file data */
			else {
				int file_fd;
				if (!((file_fd = open(file, O_RDONLY)) == -1)) {
					sprintf(buffer, "HTTP/1.0 200 OK\r\nContent-type: %s\r\n\r\n", mime);	// HTTP header info
					send(cli->socket, buffer, strlen(buffer), 0);
					
					int readcount, total_sent = 0;
					while ((readcount = read(file_fd, buffer, BUFSIZE)) > 0) {
						if (send(cli->socket, buffer, readcount, 0) != -1)
							total_sent = total_sent + readcount;
					}
					sprintf(logbuf, "\tData sent: %d bytes", total_sent);
					logging(INFO, logbuf);
					close(file_fd);
					close_client_connection(cli);
				}
			}
		} // end if command is "GET " or "get " (spaces intented)


		/* for telnet commands */
		if (!strcmp("exit",buffer)) {
			close_client_connection(cli);
			return 0;
		}
		else if (!strcmp("help",buffer)) 
			send_response(cli, "Commands: help status exit");
		else if (!strcmp("status",buffer)) {
			char resp[80];
			if(!sprintf(resp, "Server uptime: %d seconds\nActive session: %d seconds", getUptime(server_start_time), getUptime(cli->time_of_connection)))
				error("sprintf");

			send_response(cli, resp);
		}
	}
	return 0;

}


/* main */

int main(int argc, char *argv[]) {

	/* time when the server starts */
	server_start_time = time(0);
	
	logging(0, "pHTTPd - Server started\nLogging to console\n");

	/* check for -? flag, show info and then exit */
	if (argc < 3 || argc > 3 || !strcmp(argv[1],"-?")) {
		printf("Usage: %s <port> <topdir>\n", argv[0]);
		exit(0);
	}
	
	unsigned int portno;
	char *topdir;
	int master_sockfd;						// master socket file descriptor
	struct sockaddr_in serv_addr;


	/* set server port and home directory */
	if (argc == 3) {
		if (!isnumeric(argv[1])) {
			sprintf(logbuf, "Port argument non-numeric, using default (%d)", DEFAULTPORT);
			logging(WARNING, logbuf);
			portno = DEFAULTPORT;
		}
		else {
			portno = atoi(argv[1]);
			sprintf(logbuf, "Using port %d", portno);
			logging(INFO, logbuf);
		}

		if (	!strncmp(argv[2], "/", 2) ||
				!strncmp(argv[2], "/sbin", 6) ||
				!strncmp(argv[2], "/bin", 5) ||
				!strncmp(argv[2], "/var", 5) ||
				!strncmp(argv[2], "/tmp", 5) ||
				!strncmp(argv[2], "/usr", 5) ||
				!strncmp(argv[2], "/etc", 5) ||
				!strncmp(argv[2], "/dev", 5)			
				) {
			sprintf(logbuf, "Disallowed base directory. See %s -?.", argv[0]);
			logging(ERROR, logbuf);
		}
		else {
			topdir = argv[2];
			if (chdir(topdir) == -1) {
				sprintf(logbuf, "Can't change directory to %s", topdir);
				logging(ERROR, logbuf);
			}
			sprintf(logbuf, "Using %s as base directory", topdir);
			logging(INFO, logbuf);
		}

	}
	/* this will never happen, but you know - just in case the first if statement suddenly explodes and jumps right into this */
	else {
		sprintf(logbuf, "See %s -?.", argv[0]);
		logging(ERROR, logbuf);
	}


	/* set up server socket */
	if ((master_sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		logging(ERROR, "Creating socket");
	else
		logging(INFO, "Socket created");

	int opt = 1;
	setsockopt(master_sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof opt);
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(portno);

	/* bind socket to port */
	if (bind(master_sockfd, (struct sockaddr *) &serv_addr, (socklen_t)sizeof(serv_addr)) == -1)
		logging(ERROR, "Binding port to socket");
	else
		logging(INFO, "Socket bound to port");

	/* listen for incoming connections */
	if ((listen(master_sockfd, BACKLOG)) == -1)
		logging(ERROR, "ERROR listen()");
	else
		logging(INFO, "Now listening for incoming connections");
		
	logging(0, "");

	/* set up the select()-based part */
	fd_set socketpool;
	FD_ZERO(&socketpool);

	/* initialize and zero out the list of connected clients */
	int i;
	for (i=0; i<MAX_ALLOWED_CLIENTS; i++)
		client[i].socket = 0;

	/* loop and manage incoming connections/requests */
	while (1) {

		/* zero the socket pool and read all the active sockets */
		FD_ZERO(&socketpool);
		FD_SET(master_sockfd, &socketpool);		// manually add the master socket for incoming connection
		for (i=0; i<MAX_ALLOWED_CLIENTS; i++)	// loop through client list and add active sockets
			if (client[i].socket > 0)
				FD_SET(client[i].socket, &socketpool);

		/* wait for activity on any of the open sockets */
		int select_res;
		if ((select_res = select(MAX_ALLOWED_CLIENTS+3, &socketpool, NULL, NULL, NULL)) > 0) {

			if (FD_ISSET(master_sockfd, &socketpool)) { // master socket has incoming connection

				/* set up data for the new connection */
				int inc_sfd;
				struct sockaddr_in inc_addr;
				socklen_t inc_addr_size;
				inc_addr_size = sizeof inc_addr;

				if ((inc_sfd = accept(master_sockfd, (struct sockaddr *)&inc_addr, &inc_addr_size)) == -1)
					logging(WARNING, "Could not accept incoming");
				else {
					/* check if the server has reached its maximum */
					for (i=0; i<MAX_ALLOWED_CLIENTS; i++) {
						/* server is full */
						if ((i+1) == MAX_ALLOWED_CLIENTS) {
							sprintf(logbuf, "Connection refused (%s on socket %d)\n", inet_ntoa(inc_addr.sin_addr), inc_sfd);
							logging(INFO, logbuf);
							send(inc_sfd, "HTTP/1.0 503 Service Unavailable\n", 35, 0);
							close(inc_sfd);
							break;
						}
						/* room for one more */
						else if (client[i].socket == 0) {
							/* log the incoming connection */
							sprintf(logbuf, "Incoming connection (%s on socket %d)", inet_ntoa(inc_addr.sin_addr), inc_sfd);
							logging(INFO, logbuf);

							/* set up the incoming connection */
							client[i].time_of_connection = time(0);
							client[i].socket = inc_sfd;
							client[i].addr = inc_addr;
							break;
						}
					}
				}

			}

			/* if any of the clients flagged for attention, recieve whatever they're sending */
			for (i=0; i<MAX_ALLOWED_CLIENTS; i++) {
				if (FD_ISSET(client[i].socket, &socketpool)) {

					/* send the waiting client socket into web handling */
					web(&client[i]);

				}

			}
		}


	}

	// exit (will never happen since the main-loop goes forever)
	close(master_sockfd);
	logging(INFO, "Server close");
	return 0;
}

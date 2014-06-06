#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/stat.h>	/* open */
#include <fcntl.h>	/* O_RDWR, O_CREAT, O_TRUNC, O_WRONLY */
#include <unistd.h>	/* close */

#define MAXLINE 5000 /*max text line length*/
#define SERV_PORT 3000 /*port*/
#define ERROR_READ -1
#define ERROR_CLOSING_FILE -2
#define ERROR_WRITE -4
#define ERROR_READ_SOCKET -3
#define LISTENQ 8

int read_file(char* filename, int sockfd) {
	char buffer[MAXLINE];
	int file_fd, rc;
	int read_bytes;	
	
	file_fd = open (filename, O_RDWR | O_CREAT, 0644);	
	if (file_fd < 0) {
		printf("Error opening file\n");
		return ERROR_READ;
	}	

	while (1) {
		read_bytes = recv(sockfd, buffer, MAXLINE,0);
		if (read_bytes == 0) 
			break;
		else if (read_bytes == -1) {
			printf("Error reciving data\n");
			return ERROR_READ_SOCKET;
		}
		rc = write(file_fd, buffer, read_bytes);
		if (rc < 0) {
			printf("Error writing to file\n");
			return ERROR_WRITE;
		}		
	}

	 rc = close(file_fd);
	 if (rc < 0) {
		printf("Error closing file\n");
		return ERROR_CLOSING_FILE;
	 }      

	return 0;
}

int main (int argc, char** argv)
{
	int listenfd, connfd, n;
	socklen_t clilen;
	char buf[MAXLINE];
	struct sockaddr_in cliaddr, servaddr;
	
	//creation of the socket
	listenfd = socket (AF_INET, SOCK_STREAM, 0);
	
	//preparation of the socket address 
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(SERV_PORT);
	
	bind(listenfd, (struct sockaddr *) &servaddr, sizeof(servaddr));
	
	listen(listenfd, LISTENQ);
	
	printf("%s\n","Server running...waiting for connections.");
	
	for ( ; ; ) {		
		clilen = sizeof(cliaddr);
		connfd = accept(listenfd, (struct sockaddr *) &cliaddr, &clilen);
		printf("\n %s \n","Received request...");
   
  		if (argc == 2) {			
			while ( (n = recv(connfd, buf, MAXLINE,0)) > 0)  {
				buf[n] = '\0';
				printf("%s %s\n","String received from client:", buf);
		  	}			
			 if (n < 0) {
				 perror("Read error"); 
				 exit(1);
			 }
  		}
		else { 
			read_file("test", connfd);
		}
		 if (shutdown(connfd, 2)) {
			printf("Error closing connection\n");
			exit(-1);
		 }
	 }
	//close listening socket
	close(listenfd); 
}

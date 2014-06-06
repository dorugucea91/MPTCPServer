#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>	/* open */
#include <fcntl.h>	/* O_RDWR, O_CREAT, O_TRUNC, O_WRONLY */

#define MAXLINE 4099 /*max text line length*/
#define SERV_PORT 3000 /*port*/
#define LISTENQ 8 /*maximum number of client connections */
#define ERROR_READ -1
#define ERROR_CLOSING_FILE -2
#define ERROR_READ_SOCKET -3
#define ERROR_WRITE -4

int write_to_file(char* filename, int sockfd) {
	char buffer[MAXLINE];
	int file_fd, rc;	
	
	file_fd = open (filename, O_RDWR | O_CREAT, 0644);	
	if (file_fd < 0) {
		printf("Error opening file\n");
		return ERROR_READ;
	}	

	while (1) {
		// Read data into buffer.  We may not have enough to fill up buffer, so we
		// store how many bytes were actually read in bytes_read.
		int bytes_read = read(file_fd, buffer, sizeof(buffer));
		if (bytes_read == 0) // We're done reading from the file
		    break;

		if (bytes_read < 0) {
		    printf("Error sending file");
		    break;
		}

		// You need a loop for the write, because not all of the data may be written
		// in one call; write will return how many bytes were written. p keeps
		// track of where in the buffer we are, while we decrement bytes_read
		// to keep track of how many bytes are left to write.
		void *p = buffer;
		while (bytes_read > 0) {
			int bytes_written = send(sockfd, p, bytes_read, 0);
		    	if (bytes_written <= 0) {
				printf("Error sending file. \n");
				return -1;
			}
			bytes_read -= bytes_written;
			p += bytes_written;
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
			recv(connfd, buf, 1, 0);
  			write_to_file("test", connfd);
   		}
 
	 	if (shutdown(connfd, 2)) {
			printf("Error closing connection\n");
			exit(-1);
		 }
 	}
	 //close listening socket
	 close(listenfd); 
}


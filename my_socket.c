#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "tlg.h"
#include "util.h"

#include "polarssl/config.h"

#include "polarssl/net.h"
#include "polarssl/aes.h"
#include "polarssl/dhm.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/md5.h"

#define MD5_SIZE 16
#define ALIGN_SIZE 8
#define TOTAL_SIZE 8
#define CRC_SIZE 16
#define HEADER_SIZE 32

#define CORRECT_CRC 100
#define WRONG_CRC 200

/* list with sockets for all connections */
TLG sock_list = NULL;

/* information for a single connection */
typedef struct { 
	int sockfd; 
	unsigned char* dhm_key; 
	int buffered_size;
	unsigned char* buf;
	int buf_size;
	unsigned char* p;	
	int crc;
} TSocket;

/* debugging purpose */
void display_sock_list(TLG a) {
	while (a != NULL) {	
		TSocket* sock = (TSocket*)(a->info);
		printf("[%i %s]\n", sock->sockfd, sock->dhm_key);
    	a = a->urm;
	}
  	return;
}

/* compare socket filedescriptors */
int Comp (void *p1) { 
	int fd = ((TSocket*)(p1))->sockfd;
  	return fd;
}

int roundUp(int numToRound, int multiple) { 
	if(multiple == 0) { 
  		return numToRound; 
 	} 

 	int remainder = numToRound % multiple;
 	if (remainder == 0)
  		return numToRound;
 	return numToRound + multiple - remainder;
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	printf("\n --- LD_PRELOAD accept --- \n");
	int connfd, ret;
	FILE *f;
   	size_t n, length;

        unsigned char buf[2048];
        const char *pers = "dh_server";
	
    	entropy_context entropy;
    	ctr_drbg_context ctr_drbg;
	dhm_context dhm;
	
	unsigned char md5sum[16];
	
	ssize_t (*original_recv)(int, const void *, size_t, int);	
	original_recv = dlsym(RTLD_NEXT, "recv");
	ssize_t (*original_send)(int, const void *, size_t, int);	
	original_send = dlsym(RTLD_NEXT, "send");
	
	ssize_t (*original_accept)(int, struct sockaddr*, socklen_t*);	
	original_accept = dlsym(RTLD_NEXT, "accept");
	connfd = (*original_accept)(sockfd, addr, addrlen);
	if (connfd < 0) {
		return connfd;
	}
	
	/*
    	 * 1. Setup the RNG
    	 */
   	 printf( "\n . Seeding the random number generator" );
   	 fflush( stdout );
	
	 entropy_init( &entropy );
	 if( ( ret = ctr_drbg_init( &ctr_drbg, entropy_func, &entropy,
		     			(const unsigned char *) pers,
					strlen( pers ) ) ) != 0 )
	 {	
		ret = RAND_GEN_ERROR;
	       	printf( " failed\n  ! ctr_drbg_init returned %d\n", ret );
		entropy_free( &entropy );
		return ret;
	 }
	/*
    	 * 2b. Get the DHM modulus and generator
    	 */
   	 printf( "\n . Reading DH parameters from dh_prime.txt" );
   	 fflush( stdout );

         if( ( f = fopen( "dh_prime.txt", "rb" ) ) == NULL )
   	 {
        	printf( " failed\n  ! Could not open dh_prime.txt\n" \
                "  ! Please run dh_genprime first\n\n" );
		ret = DH_PARAMS_FILE_ERROR;
        	entropy_free( &entropy );
		return ret;
   	 }

   	 if( mpi_read_file( &dhm.P, 16, f ) != 0 ||
        	 mpi_read_file( &dhm.G, 16, f ) != 0 )
    	 {
        	printf( " failed\n  ! Invalid DH parameter file\n\n" );
		fclose(f);
		ret = DH_PARAMS_FILE_ERROR;
       		dhm_free( &dhm );
    		entropy_free( &entropy );
		return ret;
    	 }
		
    	fclose( f );
	
	 /*
     	* 4. Setup the DH parameters (P,G,Ys)
     	*/
    	printf( "\n . Setting Y DH parameter" );
    	fflush( stdout );

   	memset( buf, 0, sizeof( buf ) );

    	if( ( ret = dhm_make_params( &dhm, (int) mpi_size( &dhm.P ), buf, &n,
                                 ctr_drbg_random, &ctr_drbg ) ) != 0 )
    	{
        	printf( " failed\n  ! dhm_make_params returned %d\n\n", ret );
        	dhm_free( &dhm );
    		entropy_free( &entropy );
		return ret;
 	}		
	
	printf("\n . Sending P parameter: ");
	length = 1024;
	if (mpi_write_string(&dhm.P, 16, (char*)buf, &length) == 0) {
		printf( "\n . Sent P parameter" );
	}
	else 
		printf("mpi_write_string error, %i\n", length);
	fflush(stdout);
	
	ret = (*original_send)(connfd, buf, length, 0);
	if (ret < 0) {
		dhm_free( &dhm );
    		entropy_free( &entropy );
		return ret;
	}
	
	printf("\n . Sending G parameter: ");
	length = 1024;
	if (mpi_write_string(&dhm.G, 16, (char*)buf, &length) == 0) {
		printf( "\n . Sent G  parameter" );
	}
	else 
		printf("mpi_write_string error, %i\n", length);
	fflush(stdout);	

	ret = original_send(connfd, buf, length, 0);
	if (ret < 0) {
		dhm_free( &dhm );
    		entropy_free( &entropy );
		return ret;
	}

	printf("\n . Sending GX parameter: ");
	length = 1024;
	if (mpi_write_string(&dhm.GX, 16, (char*)buf, &length) == 0) {
		printf( "\n . Sent X parameter" );
	}
	else 
		printf("mpi_write_string error, %i\n", length);
	fflush(stdout);
	
	ret = original_send(connfd, buf, length, 0);
	if (ret < 0) {
		dhm_free( &dhm );
    		entropy_free( &entropy );
		return ret;
	}

	printf( "\n . Receiving the client's public value" );
	memset( buf, 0, sizeof( buf ) );
	n = 512;
	ret = (*original_recv)(connfd, buf, n, 0);
	
	if (ret < 0) {
		dhm_free( &dhm );
    		entropy_free( &entropy );
		return ret;
	}

	mpi_read_string( &dhm.GY, 16, (char*)buf);

	/*
	 * 7. Derive the shared secret: K = Ys ^ Xc mod P
     	*/
    	printf( "\n . Shared secret: " );
    	fflush( stdout );

    	if( ( ret = dhm_calc_secret( &dhm, buf, &n,
                                 ctr_drbg_random, &ctr_drbg ) ) != 0 )
    	{
        	printf( " failed\n  ! dhm_calc_secret returned %d\n\n", ret );
        	dhm_free( &dhm );
    		entropy_free( &entropy );
		return ret;
    	}

	/* allocate memory for a new connection structure */	
	TSocket* new_sock = (TSocket*)malloc(sizeof(TSocket));
	if (!new_sock) {
		ret = MEMORY_ERROR;
		dhm_free( &dhm );
    		entropy_free( &entropy );
		return ret;
	}
	new_sock->sockfd = connfd;
	new_sock->dhm_key = calloc(n, sizeof(char));
	if (!new_sock->dhm_key) {
		free (new_sock);
		ret = MEMORY_ERROR;
		dhm_free( &dhm );
    		entropy_free( &entropy );
		return ret;
	}
	memcpy(new_sock->dhm_key, buf, n);
	new_sock->buf = NULL;
	new_sock->buf_size = 0;
	InsLgP(&sock_list, new_sock);
	
	md5( new_sock->dhm_key, 256, md5sum );
	printf( "\n . MD5 on DH key: " );
	for( n = 0; n < 16; n++ )
        	printf( "%02x", md5sum[n] );	
	
	printf( "\n\n" );
	fflush(stdout);
    	
	dhm_free( &dhm );
    	entropy_free( &entropy );
	
	return connfd;
} 

int check_control_sum(unsigned char* calc, unsigned char* received) {
	int i;
	for (i = 0; i < CRC_SIZE; i++) {
		if (calc[i] != received[i])
			return WRONG_CRC;
	}
	return CORRECT_CRC;
}

int read(int fildes, void *buf, size_t nbyte) {
	printf("\n--- LD_PRELOAD read --- \n");
	ALG a_sock = CautaLG(&sock_list, Comp, fildes);
	if (*a_sock) {	
		return recv(fildes, buf, nbyte, 0);
	}

	int (*original_read)(int, void*, size_t);	
	original_read = dlsym(RTLD_NEXT, "read");	
	return (original_read)(fildes, buf, nbyte);
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
	printf("\n --- LD_PRELOAD recv --- \n");
	int ret, total_size, align_size;	
	unsigned char md5sum[16];
	int buffered_size, buf_size;
	unsigned char temp_buf[HEADER_SIZE];
	unsigned char crc[CRC_SIZE];
	TSocket* t_sock;
	unsigned char *p;
	aes_context aes;
	int n;	

	ssize_t (*original_recv)(int, void *, size_t, int);	
	original_recv = dlsym(RTLD_NEXT, "recv");	
	ALG a_sock = CautaLG(&sock_list, Comp, sockfd);
	if (*a_sock) {		
		t_sock = ((TSocket*)(*a_sock)->info);
		if (t_sock->crc == WRONG_CRC)
			return -1;		

		buffered_size = (t_sock->buffered_size);		
		buf_size = (t_sock->buf_size);
		if (!buffered_size) {
			memset(temp_buf, 0, HEADER_SIZE);
			ret = (*original_recv)(sockfd, temp_buf, HEADER_SIZE, flags);
			if (!ret) {
				memset(buf, 0, len);
				return 0;
			}
			sscanf((char*)temp_buf, "%i %i", &total_size, &align_size);	
			if ((!buf_size) || (buf_size < total_size)) {
				if (buf_size && (buf_size < total_size)) {
					free(t_sock->buf);
				}
				
				t_sock->buf = malloc(total_size * sizeof(char));	
				if (!t_sock->buf) {
					printf("\n Memory error! \n");
					return -1;
				}	
			}
			(t_sock->buf_size) = total_size;
			(t_sock->p) = (t_sock->buf);	
			(t_sock->buffered_size) = 0;
				
			p = (t_sock->buf);
			while (total_size > 0) {
				ret = (*original_recv)(sockfd, p, total_size, flags);
				if (ret <= 0) {
					printf("\n Error receiving data: %i \n", ret);
					t_sock->crc = WRONG_CRC;
					return -1;
				}
				total_size -= ret;	
				p += ret;
			}

			aes_setkey_dec( &aes, t_sock->dhm_key, 256 );
			md5(t_sock->dhm_key, 256, md5sum );
			aes_crypt_cbc( &aes, AES_DECRYPT, t_sock->buf_size, 
				md5sum, t_sock->buf, t_sock->buf);
			
			md5(t_sock->buf, t_sock->buf_size, crc);
			for (n = 0; n < 16; n++) {
				printf("%02x", crc[n]);
			}			
			
			if (check_control_sum(crc, temp_buf + TOTAL_SIZE + ALIGN_SIZE) 
									== WRONG_CRC) {
				t_sock->crc = WRONG_CRC;
				printf("WRONG CRC");
				return -1;
			}
		
			t_sock->buffered_size = (t_sock->buf_size) - (align_size);
		}					
	}	
	else {
		printf("Dhm key for socket %i not found\n", sockfd);
		return -1;
	}	
	if ((t_sock->buffered_size) > len) {
		memcpy(buf, t_sock->p, len);
		(t_sock->p) += len;
		(t_sock->buffered_size) -= len;
		ret = len;	
	}
	else {
		memcpy(buf, t_sock->p, t_sock->buffered_size);
		ret = (t_sock->buffered_size);
		(t_sock->buffered_size) = 0;		
	}		
		
	return ret;	
}

int write(int fildes, const void *buf, size_t nbyte) {
	printf("\n--- LD_PRELOAD write --- \n");
	ALG a_sock = CautaLG(&sock_list, Comp, fildes);
	if (*a_sock) {	
		return send(fildes, buf, nbyte, 0);
	}

	int (*original_write)(int, const void*, size_t);	
	original_write = dlsym(RTLD_NEXT, "write");	
	return (original_write)(fildes, buf, nbyte);
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
	printf("\n --- LD_PRELOAD send --- \n");
	int ret, newSize, align_size, total_size;;
	aes_context aes;
	unsigned char md5sum[16];
	unsigned char* newBuff;
	void *p;
	TSocket* t_sock;	
	int n;	

	ssize_t (*original_send)(int, const void *, size_t, int);	
	original_send = dlsym(RTLD_NEXT, "send");	
	
	ALG a_sock = CautaLG(&sock_list, Comp, sockfd);
	if (*a_sock) {	
		t_sock = ((TSocket*)(*a_sock)->info);
		if (len % 16) {
			newSize = roundUp(len, 16);		
			align_size = newSize - len;
		}
		else {
			newSize = len;
			align_size = 0;	
		}
		total_size = newSize + TOTAL_SIZE + ALIGN_SIZE + MD5_SIZE;
	
		if (!(t_sock->buf_size) || (t_sock->buf_size < total_size)) {
			if (t_sock->buf_size < total_size)			
				free(t_sock->buf);
			t_sock->buf = (unsigned char*)malloc(
							total_size * sizeof(char));
			if (!(t_sock->buf))
				return -1;
			t_sock->buf_size = total_size;
		}
		newBuff = t_sock->buf;		
		
		memset(newBuff, 0, total_size);	
		memcpy(newBuff + TOTAL_SIZE + ALIGN_SIZE + MD5_SIZE, 
						(unsigned char*)buf, len);
		
		md5(newBuff + TOTAL_SIZE + ALIGN_SIZE + MD5_SIZE, newSize, 
				newBuff + TOTAL_SIZE + ALIGN_SIZE);
	
		printf("\n Data decoded:\n");		
		for( n = 32; n < total_size; n++ )
        		printf( "%02x", newBuff[n] );	
		
		md5( ((TSocket*)(*a_sock)->info)->dhm_key, 256, md5sum );
		aes_setkey_enc( &aes, t_sock->dhm_key, 256 );			
		aes_crypt_cbc( &aes, AES_ENCRYPT, newSize, md5sum, 
			(unsigned char*)newBuff + TOTAL_SIZE + ALIGN_SIZE + MD5_SIZE, 
			(unsigned char*)newBuff + TOTAL_SIZE + ALIGN_SIZE + MD5_SIZE);
		
		memset(newBuff, 0, 16);	
		sprintf((char*)(newBuff), "%i %i ", newSize, align_size);

		p = newBuff;
		while (total_size > 0) {
			ret = (*original_send)(sockfd, p, (size_t)(total_size), flags);
			if (ret <= 0) {
				printf("\n Error sending %i\n", ret);
				free(newBuff);
				return ret;
			}	
			total_size -= ret;
			p += ret;
		}
	}
	else {
		printf("Original send\n");
		fflush(stdout);
		ret = original_send(sockfd, buf, len, flags);
		return ret;
	}
	return len;
}

int close (int filedes) {
	printf("\n--- LD_PRELOAD close --- \n");
	ALG a_sock = CautaLG(&sock_list, Comp, filedes);
	if (*a_sock) {	
		return shutdown(filedes, 2);
	}

	int (*original_close)(int);	
	original_close = dlsym(RTLD_NEXT, "close");	
	return (original_close)(filedes);
}

int shutdown(int socket, int how) {
	printf("\n--- LD_PRELOAD shutdown ---");
	unsigned char* buf;
	ALG a_sock = CautaLG(&sock_list, Comp, socket);
	if (*a_sock) {
		printf("\nFreeing resources for socketfd: %i\n", socket);
		free(((TSocket*)(*a_sock)->info)->dhm_key);	
		buf = ((TSocket*)(*a_sock)->info)->buf;
		if (buf)	
			free(buf);	
	
		ElimLgE(a_sock);	
	}
	else {
		printf("\nError freeing resources for socketfd: %i\n", socket);	
	}
	
	ssize_t (*original_shutdown)(int socket, int how);	
	original_shutdown = dlsym(RTLD_NEXT, "shutdown");
	return (*original_shutdown)(socket, how);
}

#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

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
#define ALIGN_SIZE 2
#define PAYLOAD_SIZE 5
#define HEADER_SIZE 32
#define FLAG_SIZE 1
#define HEADER_CLEAN_SIZE (FLAG_SIZE + MD5_SIZE)
#define MD5_OFFSET_M (FLAG_SIZE + PAYLOAD_SIZE + ALIGN_SIZE + MD5_SIZE)

#define CORRECT_MD5 100
#define WRONG_MD5 200

/* list with sockets for all connections */
TLG sock_list = NULL;

/* information for a single connection */
typedef struct { 
	int sockfd; 
	aes_context aes;
	unsigned char md5sum[16];
	unsigned char* dhm_key; 
	unsigned char* buf;
	int buf_size;
	int buffered_size;
	unsigned char* p;	
	int payload_size, align_size;
	int flag;
	int smaller_buf;
	int crc;
	double encrypt_time;
	double original_send_time;
	double md5_time;
} TSocket;

ssize_t (*original_send)(int, const void *, size_t, int);
ssize_t (*original_recv)(int, void *, size_t, int);			

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
	int connfd, ret;
	FILE *f;
   	size_t n, length;

    unsigned char buf[2048];
    const char *pers = "dh_server";	

    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
	dhm_context dhm;
	memset( &dhm, 0, sizeof( dhm ) );
		
	original_send = dlsym(RTLD_NEXT, "send");	
	original_recv = dlsym(RTLD_NEXT, "recv");	

	ssize_t (*original_accept)(int, struct sockaddr*, socklen_t*);	
	original_accept = dlsym(RTLD_NEXT, "accept");
	connfd = (*original_accept)(sockfd, addr, addrlen);
	if (connfd < 0) {
		return connfd;
	}
	
	/*
    * 1. Setup the RNG
    */
 
	entropy_init(&entropy);
	if((ret = ctr_drbg_init(&ctr_drbg, entropy_func, &entropy,
		(const unsigned char *) pers, strlen(pers))) != 0)
	{	
		ret = RAND_GEN_ERROR;
	    printf(" failed\n  ! ctr_drbg_init returned %d\n", ret);
		entropy_free(&entropy);
		return ret;
	}
	/*
	* 2b. Get the DHM modulus and generator
   	*/

	if((f = fopen( "dh_prime.txt", "rb" )) == NULL)
   	{
		printf(" failed\n  ! Could not open dh_prime.txt\n" \
			"  ! Please run dh_genprime first\n\n");
		fflush(stdout);
		ret = DH_PARAMS_FILE_ERROR;
       	entropy_free(&entropy);
		return ret;
   	}

   	if(mpi_read_file(&dhm.P, 16, f) != 0 || mpi_read_file(&dhm.G, 16, f) != 0)
    {
		printf( "failed\n  ! Invalid DH parameter file\n\n");
		fclose(f);
		ret = DH_PARAMS_FILE_ERROR;
       	dhm_free(&dhm);
    	entropy_free(&entropy);
		return ret;
	}
		
    fclose(f);
	
	/*
    * 4. Setup the DH parameters (P,G,Ys)
    */

   	memset(buf, 0, sizeof(buf));

    if((ret = dhm_make_params( &dhm, (int) mpi_size(&dhm.P), buf, &n,
                                 ctr_drbg_random, &ctr_drbg)) != 0)
    {
		printf(" failed\n  ! dhm_make_params returned %d\n\n", ret);
        dhm_free(&dhm);
    	entropy_free(&entropy);
		return ret;
 	}		
	
	length = 1024;
	mpi_write_string(&dhm.P, 16, (char*)buf, &length);
	
	ret = (*original_send)(connfd, buf, length, 0);
	if (ret < 0) {
		dhm_free( &dhm );
    	entropy_free( &entropy );
		return ret;
	}
	
	length = 1024;
	mpi_write_string(&dhm.G, 16, (char*)buf, &length);
	ret = original_send(connfd, buf, length, 0);
	if (ret < 0) {
		dhm_free( &dhm );
    	entropy_free( &entropy );
		return ret;
	}

	length = 1024;
	mpi_write_string(&dhm.GX, 16, (char*)buf, &length);	
	ret = original_send(connfd, buf, length, 0);
	if (ret < 0) {
		dhm_free( &dhm );
    	entropy_free( &entropy );
		return ret;
	}

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
  
	if( (ret = dhm_calc_secret(&dhm, buf, &n, ctr_drbg_random, &ctr_drbg)) != 0)
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
	new_sock->buffered_size = 0;
	new_sock->p = NULL;
	new_sock->flag = 1;
	new_sock->encrypt_time = 0;
	new_sock->original_send_time = 0;
	new_sock->md5_time = 0;
	md5(new_sock->dhm_key, 256, new_sock->md5sum );
	aes_setkey_enc( &(new_sock->aes), new_sock->dhm_key, 256 );	
	InsLgP(&sock_list, new_sock);
	
	printf( "\n . MD5 on DH key: " );
	for( n = 0; n < 16; n++ )
    	printf( "%02x", (new_sock->md5sum)[n] );	

	printf( "\n\n" );
	fflush(stdout);
    	
	dhm_free( &dhm );
    	entropy_free( &entropy );
	
	return connfd;
} 

int check_control_sum(unsigned char* calc, unsigned char* received) {
	int i;
	for (i = 0; i < MD5_SIZE; i++) {
		if (calc[i] != received[i]) {
			printf("WRONG_CRC");
			return WRONG_MD5;
		}
	}
	return CORRECT_MD5;
}

int read(int fildes, void *buf, size_t nbyte) {
	ALG a_sock = CautaLG(&sock_list, Comp, fildes);
	if (*a_sock) {	
		return recv(fildes, buf, nbyte, 0);
	}

	int (*original_read)(int, void*, size_t);	
	original_read = dlsym(RTLD_NEXT, "read");	
	return (original_read)(fildes, buf, nbyte);
}

int read_all(int sockfd, int flags, unsigned char* buf, int off, int total_size,
															 int check_last) {
	int ret = 0, received = 0;
	unsigned char* p = buf + off;	
	int real_size = 0;
	int smaller_buf = 0;	

	while (ret != total_size) {
		received = (*original_recv)(sockfd, p, total_size - ret, flags);
		if (!received) { 
			if (!ret)
				return 0;
			else
				return ret;
		}
		if (received < 0) 
			return received;
		ret += received;
		p += received;		
		if (check_last && (ret > (FLAG_SIZE + PAYLOAD_SIZE))) {
			if (buf[0] == 0x31) {
				sscanf((char*)(buf + FLAG_SIZE), "%i", &real_size);
				real_size += MD5_OFFSET_M;
				if (real_size < total_size)
					smaller_buf = 1;
				check_last = 0;
			}
		}
		if (smaller_buf && (real_size == ret)) {
			(*original_send)(sockfd, buf, 1, 0);		
			return ret;
		}	
	}
	return ret;
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
	int ret, remaining_size, old_size;	
	unsigned char md5header[16], md5sum[16];
	int buffered_size, buf_size, offset;
	TSocket* t_sock;
	aes_context aes;
	unsigned char headerModified[MD5_OFFSET_M];

	ALG a_sock = CautaLG(&sock_list, Comp, sockfd);
	if (*a_sock) {	
		t_sock = ((TSocket*)(*a_sock)->info);
		if ((t_sock->crc) == WRONG_MD5)
			return -1;		
		
		buffered_size = (t_sock->buffered_size);		
		buf_size = (t_sock->buf_size);
		if (buffered_size == 0) {
			if (buf_size == 0) {
				ret = read_all(sockfd, flags, headerModified, 0, MD5_OFFSET_M, 0);
				if (ret <= 0) 
					return ret;
				memcpy(md5header, headerModified + MD5_OFFSET_M - MD5_SIZE,
																		 MD5_SIZE);			
				sscanf((char*)(headerModified + FLAG_SIZE), "%i %i", 
									&(t_sock->payload_size), &(t_sock->align_size));
				offset = 0;
				t_sock->buf = malloc(((t_sock->payload_size) + HEADER_CLEAN_SIZE) * 
																	sizeof(char));		
				if (!(t_sock->buf)) {
					printf("\n Memory error! \n");
					return -1;
				}
				(t_sock->buf_size) = (t_sock->payload_size) + HEADER_CLEAN_SIZE;
			}						
			remaining_size = (t_sock->buf_size) - 
											(t_sock->flag) * HEADER_CLEAN_SIZE;
		
			ret = read_all(sockfd, flags, (t_sock->buf), 0, remaining_size, 1);
			if (ret <= 0)
				return ret;
			(t_sock->buffered_size) = (t_sock->payload_size) - (t_sock->align_size);
			if ((t_sock->flag) == 0) {
				offset = MD5_SIZE + FLAG_SIZE;
				if ((t_sock->buf)[0] == 0x30) {
					memcpy(md5header, (t_sock->buf) + FLAG_SIZE, MD5_SIZE);	
				}
				else {
					sscanf((char*)(t_sock->buf + FLAG_SIZE), "%i %i", 
								&(t_sock->payload_size), &(t_sock->align_size));
					remaining_size = (t_sock->payload_size)  + 
												MD5_OFFSET_M - (t_sock->buf_size);
					(t_sock->buffered_size) = (t_sock->payload_size) - 
															(t_sock->align_size);		
					old_size = (t_sock->buf_size);					
		
					if ((t_sock->buf_size) < (t_sock->payload_size + MD5_OFFSET_M)) {
						t_sock->buf = realloc(t_sock->buf, (t_sock->payload_size) + 
											MD5_OFFSET_M);				
						if (!(t_sock->buf)) {
							printf("\n Memory error! \n");
							return -1;
						}
						(t_sock->buf_size) = (t_sock->payload_size) + 
											MD5_OFFSET_M;
					}
					if (remaining_size > 0)
						ret = read_all(sockfd, flags, t_sock->buf, 
													old_size, remaining_size, 1);
					memcpy(md5header, (t_sock->buf) + MD5_OFFSET_M - MD5_SIZE,
																	MD5_SIZE);					
					offset = MD5_OFFSET_M;
				}
			}		
			(t_sock->flag) = 0;
			aes_setkey_dec( &aes, t_sock->dhm_key, 256 );
			md5(t_sock->dhm_key, 256, md5sum );
			
			aes_crypt_cbc( &aes, AES_DECRYPT, (t_sock->payload_size), 
					md5sum, (t_sock->buf) + offset, t_sock->buf);	
			(t_sock->p) = (t_sock->buf);

			md5(t_sock->buf, t_sock->payload_size, md5sum );
			if (check_control_sum(md5sum, md5header) == WRONG_MD5)
				return -1;
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
	ALG a_sock = CautaLG(&sock_list, Comp, fildes);
	if (*a_sock) {	
		return send(fildes, buf, nbyte, 0);
	}

	int (*original_write)(int, const void*, size_t);	
	original_write = dlsym(RTLD_NEXT, "write");	
	return (original_write)(fildes, buf, nbyte);
}

int get_payload_size (int total_size) {
	return (total_size - FLAG_SIZE - PAYLOAD_SIZE - ALIGN_SIZE - MD5_SIZE);
}	

int n = 0;
ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
	int ret, newSize, align_size, total_size;
	unsigned char md5sum[16];
	unsigned char* newBuff;
	void *p;
	TSocket* t_sock;
	int modified_len, offset, send_size;
	int new_buffered_size;
	struct timeval  tv1, tv2;
	
	ALG a_sock = CautaLG(&sock_list, Comp, sockfd);
	if (*a_sock) {	
		modified_len = 0;
		t_sock = ((TSocket*)(*a_sock)->info);
		t_sock->smaller_buf = 0;
		if (len % 16) {
			newSize = roundUp(len, 16);		
			align_size = newSize - len;
		}
		else {
			newSize = len;
			align_size = 0;	
		}
		new_buffered_size = newSize - align_size;
		
		if (!(t_sock->buf_size) || ((t_sock->buffered_size) != new_buffered_size)) {
			modified_len = 1;		
			if ((t_sock->buf_size) && (new_buffered_size < (t_sock->buffered_size))) 
				(t_sock->smaller_buf) = 1;
			total_size = FLAG_SIZE + PAYLOAD_SIZE + ALIGN_SIZE + MD5_SIZE + newSize;	
			if (t_sock->buf)
				free(t_sock->buf);
			t_sock->buf = (unsigned char*)malloc(
							total_size * sizeof(char));
			if (!(t_sock->buf))
				return -1;
			t_sock->buf_size = total_size;
			t_sock->buffered_size = new_buffered_size;					
		}
	
		total_size = t_sock->buf_size;
		newBuff = t_sock->buf;
		memset(newBuff, t_sock->buf_size, 0);		
		memcpy(md5sum, t_sock->md5sum, 16);	
		if (!modified_len) {
			offset = FLAG_SIZE + MD5_SIZE;
			sprintf((char*)(newBuff), "%i", 0);
			send_size = total_size - PAYLOAD_SIZE - ALIGN_SIZE;
		}
		else {
			offset = FLAG_SIZE + PAYLOAD_SIZE + ALIGN_SIZE + MD5_SIZE;
			sprintf((char*)(newBuff), "%i%i", 1, newSize);
			sprintf((char*)(newBuff + FLAG_SIZE + PAYLOAD_SIZE), "%i", align_size);
			send_size = total_size;
		}
		memcpy(newBuff + offset, (unsigned char*)buf, len);
		gettimeofday(&tv1, NULL);
		md5(newBuff + offset, newSize, newBuff + offset - MD5_SIZE);
		gettimeofday(&tv2, NULL);
		(t_sock->md5_time) += ((double) (tv2.tv_usec - tv1.tv_usec) / 1000000 +
         		(double) (tv2.tv_sec - tv1.tv_sec));
		gettimeofday(&tv1, NULL);		
		aes_crypt_cbc( &(t_sock->aes), AES_ENCRYPT, newSize, md5sum, 
					(unsigned char*)newBuff + offset, 
					(unsigned char*)newBuff + offset);
		gettimeofday(&tv2, NULL);
		(t_sock->encrypt_time) += ((double) (tv2.tv_usec - tv1.tv_usec) / 1000000 +
         		(double) (tv2.tv_sec - tv1.tv_sec));
		p = newBuff;

		gettimeofday(&tv1, NULL);
		//printf("\n %i %i %i\n", send_size, len, n++);
		while (send_size > 0) {
			ret = (*original_send)(sockfd, p, (size_t)(send_size), flags);
			if (ret <= 0) {
				printf("\n Error sending %i\n", ret);
				free(newBuff);
				return ret;
			}	
			send_size -= ret;
			p += ret;
		}
		//if ((t_sock->smaller_buf) == 1) 
			//(*original_recv)(sockfd, md5sum, 1, 0);
		gettimeofday(&tv2, NULL);
		(t_sock->original_send_time) += ((double) (tv2.tv_usec - tv1.tv_usec) / 1000000 +
         		(double) (tv2.tv_sec - tv1.tv_sec));
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

static double encr = 0;
static double md = 0;
static int rep = 1;

int shutdown(int socket, int how) {
	printf("\n--- LD_PRELOAD shutdown ---");
	unsigned char* buf;
	ALG a_sock = CautaLG(&sock_list, Comp, socket);
	if (*a_sock) {
		/*printf ("\nEncryption time = %f seconds", ((TSocket*)(*a_sock)->info)->encrypt_time);
		printf ("\nOriginal send time = %f seconds", 
				((TSocket*)(*a_sock)->info)->original_send_time); 
		printf ("\nMd5 time = %f seconds\n", 
				((TSocket*)(*a_sock)->info)->md5_time);*/
		encr +=  (((TSocket*)(*a_sock)->info)->encrypt_time);
		md += (((TSocket*)(*a_sock)->info)->md5_time);
		
		printf("/n Encr %f", encr/(rep));	
		printf("/n Md5 %f", md/(rep));		
		rep++;

		printf("\nFreeing resources for socketfd: %i\n", socket);
		free(((TSocket*)(*a_sock)->info)->dhm_key);	
		buf = ((TSocket*)(*a_sock)->info)->buf;
		if (buf) {	
			free(buf);	
			buf = NULL;
		}
		ElimLgE(a_sock);	
	}
	else {
		printf("\nError freeing resources for socketfd: %i\n", socket);	
	}
	
	ssize_t (*original_shutdown)(int socket, int how);	
	original_shutdown = dlsym(RTLD_NEXT, "shutdown");
	return (*original_shutdown)(socket, how);
}

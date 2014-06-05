CC = gcc
CFLAGS = -Wall -Ilist/ -I./polarssl-1.3.4/include
LDFLAGS = -L./polarssl-1.3.4/library -L. -Wl,-whole-archive  -llist -lpolarssl -Wl,-no-whole-archive 

all: server

server: server.o my_socket.so 
	$(CC) server.o -o server	

server.o: server.c
	$(CC) $(CFLAGS) -g -c server.c -o server.o 

my_socket.so: my_socket.c liblist.a
	$(CC) $(CFLAGS) $(LDFLAGS)  -fPIC -shared -o my_socket.so my_socket.c -ldl 

liblist.a: funcLGP.o
	ar rc liblist.a funcLGP.o

funcLGP.o: ./list/funcLGP.c
	$(CC) $(CFLAGS) -fPIC -c ./list/funcLGP.c -o funcLGP.o 

my_socket.o: my_socket.c
	$(CC) $(CFLAGS) $(LDFLAGS) -g -c my_socket.c -o my_socket.o -ldl
	
clean: 
	rm -f *.o *.so *.a server

run: 
	LD_PRELOAD=./my_socket.so ./server

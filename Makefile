PG=enc_dec_example

all: $(PG) client server authserver

$(PG): $(PG).c aes_func.o
	gcc -g -o $(PG) $(PG).c aes_func.o -lcrypto

client: client.c aes_func.o
	gcc -g -o client client.c aes_func.o -lcrypto

server: server.c aes_func.o
	gcc -g -o server server.c aes_func.o -lcrypto

authserver: authserver.c aes_func.o
	gcc -g -o authserver authserver.c aes_func.o -lcrypto

aes_func.o: aes_func.c
	gcc -g -c aes_func.c

clean:
	rm client server authserver enc_dec_example aes_func.o

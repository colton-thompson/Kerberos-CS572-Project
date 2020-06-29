#include <stdio.h>      /* for printf() and fprintf() */
#include <sys/socket.h> /* for socket() and bind() */
#include <arpa/inet.h>  /* for sockaddr_in and inet_ntoa() */
#include <stdlib.h>     /* for atoi() and exit() */
#include <string.h>     /* for memset() */
#include <unistd.h>     /* for close() */
#include "packet_header.h"

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define MAX_STRING 255    /* Longest string  */
#define KEY_LENGTH 32       

void DieWithError(char *errorMessage)  /* External error handling function */
{
    perror(errorMessage);
    exit(1);
}

int main(int argc, char *argv[])
{
    int sock;                           /* Socket */
    //unsigned short echoServPort;        /* autherver port */
    int recvMsgSize;                    /* Size of received message */
    struct sockaddr_in authservAddr;    /* Local address */
    struct sockaddr_in clientAddr;      /* Client address */
    unsigned int cliAddrLen;            /* Length of incoming message */
    unsigned short authserverPort;      /* authserverPort port */
    char *clientID;
    char *serverID;
    char *clientKey; //memset(&clientKey, 0, KEY_LENGTH);
    memset(&clientKey, 0, KEY_LENGTH);
    char *serverKey; 
    memset(&serverKey, 0, KEY_LENGTH);
    char sharedSecret[32];//gen_random_key(sharedSecret, KEY_LENGTH);
    memcpy(sharedSecret, "abcdefghijklmnopqrstuvwxyz012345", KEY_LENGTH);

    //printf("sharedkey: %li\n", strlen(sharedSecret));

    /* A 128 bit IV */
    unsigned char iv[16];
    memset(iv, 0, 16);

    /* Temporary structs, may not use */
    struct as_req *temp_as_req = malloc(sizeof(struct as_req));

    if (argc != 6)      /* Test for correct number of parameters */
    {
        fprintf(stderr,"Usage:  %s <authserverport> <clientID> <clientkey> <serverID> <serverkey>\n", argv[0]);
        exit(1);
    }

    /* Handle arguments */
    authserverPort = atoi(argv[1]);
    clientID = argv[2];
    clientKey = argv[3];
    serverID = argv[4];
    serverKey = argv[5];

    /* Create socket for sending/receiving datagrams */
    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        DieWithError("socket() failed");

    /* Construct authserver address structure */
    memset(&authservAddr, 0, sizeof(authservAddr)); 
    authservAddr.sin_family = AF_INET;
    authservAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    authservAddr.sin_port = htons(authserverPort);

    /* Construct authserver address structure */
  
    
    /* Bind to the authserver address */
    if (bind(sock, (struct sockaddr *) &authservAddr, sizeof(authservAddr)) < 0)
        DieWithError("bind() failed");

    cliAddrLen = sizeof(clientAddr);

    /* Handle reception of message */ 
    struct as_req req_AS;
    if((recvMsgSize = recvfrom(sock, &req_AS, sizeof(req_AS), 0, (struct sockaddr *) &clientAddr, &cliAddrLen)) < 0)
        DieWithError("recvfrom() failed");

    if (req_AS.type != AS_REQ) {
        struct as_err failure;
        failure.type = AS_ERR;
        memset(&failure.client_id, 0, 40);
        memcpy(&failure.client_id, clientID, sizeof(clientID));
        if (sendto(sock, &failure, (sizeof(failure)), 0, (struct sockaddr *) &clientAddr, sizeof(clientAddr)) != sizeof(failure))
            DieWithError("sendto() sent a different number of bytes than expected");
        DieWithError("Incorrect Packet Type");
    }
    //printf("Handling client %s\n", inet_ntoa(clientAddr.sin_addr));

    /* create ticket t1 struct */
    struct ticket t1;
    memset(&t1, 0, sizeof(t1)); 
    int t1_len;
    t1_len = sizeof(struct ticket);
    memcpy(&t1.AES_key, sharedSecret, strlen(sharedSecret+1));
    memcpy(&t1.client_id, req_AS.client_id, strlen(req_AS.client_id));
    memcpy(&t1.server_id, req_AS.server_id, strlen(req_AS.server_id));
    t1.ts2 = time(NULL);
    t1.lt = LIFETIME;
    //printf("t1\n");
    //BIO_dump_fp (stdout, (const char *) &t1, sizeof(t1));  
    //printf("\n");

    /* make key */
    unsigned char key[KEY_LENGTH];
    memset(key, 0, KEY_LENGTH);

    /* generate ciphertext for ticket */
    //printf("t1 ciphertext\n");
    unsigned char t1_cipher[STICKET];
    //printf("enc tick using server key: %s\n", serverKey);
    int ciphertext_t1_len = encrypt((unsigned char *) &t1, sizeof(struct ticket), serverKey, iv, t1_cipher);
    //printf("t1 ciphertext\n");
    //BIO_dump_fp (stdout, (const char *) t1_cipher, sizeof(t1_cipher)); printf("\n");

    /* testing decrypted ticket */
    
    struct ticket dec_tik;
    int decryptedtext_len = decrypt(t1_cipher, ciphertext_t1_len, serverKey, iv, (unsigned char *) &dec_tik);
    //printf("dec ticket\n");
    //BIO_dump_fp (stdout, (const char *) &dec_tik, sizeof(dec_tik)); printf("\n");

    /* create the credential struct */
    struct credential credAS;
    memset(&credAS, 0, sizeof(credAS)); 
    memcpy(&credAS.AES_key, sharedSecret, strlen(credAS.AES_key+1));
    memcpy(&credAS.server_id, serverID, strlen(credAS.server_id));
    credAS.ts2 = time(NULL); //this may need to be sometihng over than NULL
    credAS.lt2 = LIFETIME;
    credAS.tkt_length = ciphertext_t1_len;
    memcpy(&credAS.tkt_serv, t1_cipher, ciphertext_t1_len);
    //printf("\ncredAS\n");
    //BIO_dump_fp (stdout, (const char *) &credAS, sizeof(credAS)); printf("\n");
    
    /* encrypt credentials */
    unsigned char credAS_cipher[SCRED];
    int ciphertext_cred_len = encrypt((unsigned char *) &credAS, sizeof(struct credential), sharedSecret, iv, credAS_cipher);

    struct credential dec_cred;
    int decryptedtext_len2 = decrypt(credAS_cipher, ciphertext_cred_len, sharedSecret, iv, (unsigned char *) &dec_cred);
    //BIO_dump_fp (stdout, (const char *) &dec_cred, sizeof(dec_cred)); 

    //printf("\ncredential cipher\n");
    //BIO_dump_fp (stdout, (const char *) &credAS_cipher, sizeof(credAS_cipher)); printf("\n");

    /* create the as_rep struct */
    struct as_rep response;
    memset(&response, 0, sizeof(response));
    response.type = AS_REP;
    response.cred_length = ciphertext_cred_len;
    memcpy(&response.cred, credAS_cipher, ciphertext_cred_len);
    //printf("as_rep size: %li\n", sizeof(response));

    /* Send the response to the client*/
    if (sendto(sock, &response, (sizeof(response)), 0, (struct sockaddr *) &clientAddr, sizeof(clientAddr)) != sizeof(response))
        DieWithError("sendto() sent a different number of bytes than expected");
    //printf("sending as_rep to client\n");
        
    printf("OK\n");

}


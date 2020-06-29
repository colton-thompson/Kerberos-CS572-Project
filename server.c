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

#define MAX_STRING 255     /* Longest string to echo */
#define KEY_LENGTH 32

void DieWithError(char *errorMessage)  /* External error handling function */
{
    perror(errorMessage);
    exit(1);
}

int main(int argc, char *argv[])
{
    int sock;                        /* Socket */
    unsigned short echoServPort;     /* autherver port */
    int recvMsgSize;                 /* Size of received message */

    struct sockaddr_in servAddr;    /* Local address */
    struct sockaddr_in clientAddr;  /* Client address */
    unsigned int cliAddrLen;        /* Length of incoming message */
    unsigned short servPort;        /* authserverPort port */
    char *servKey;
    memset(&servKey, 0, KEY_LENGTH);

    /* A 128 bit IV */
    unsigned char iv[16];
    memset(iv, 0, 16);

    struct ap_req *temp_ap_req = malloc(sizeof(struct ap_req));
    struct auth *dec_auth = malloc(sizeof(struct auth));

    if (argc != 3)         /* Test for correct number of parameters */
    {
        fprintf(stderr,"Usage: %s <server port> <serverkey>\n", argv[0]);
        exit(1);
    }

    /* Handle arguments */
    servPort = atoi(argv[1]);
    servKey = argv[2];

    /* Create socket for sending/receiving datagrams */
    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        DieWithError("socket() failed");

    /* Construct local address structure */
    memset(&servAddr, 0, sizeof(servAddr));         /* Zero out structure */
    servAddr.sin_family = AF_INET;                  /* Internet address family */
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);   /* Any incoming interface */
    servAddr.sin_port = htons(servPort);            /* Local port */

    /* Bind to the local address */
    if (bind(sock, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0)
        DieWithError("bind() failed");
  
    cliAddrLen = sizeof(clientAddr);

    /* Handle reception of message */ 
    struct ap_req req;
    cliAddrLen = sizeof(clientAddr);
    if((recvMsgSize = recvfrom(sock, &req, sizeof(struct ap_req), 0, (struct sockaddr *) &clientAddr, &cliAddrLen)) < 0)
        DieWithError("recvfrom() failed");

    //printf("Handling client %s\n", inet_ntoa(clientAddr.sin_addr));


    //printf("\nap_req\n");
    //BIO_dump_fp (stdout, (const char *) &req.tkt_serv, sizeof(req.tkt_serv)); printf("\n");

    unsigned char d_ticket[STICKET];
    //iter through resp_AS.cred into dec_cred
    for (int i = 0; i < STICKET; i++){
        d_ticket[i] = req.tkt_serv[i];
    }

    
    /* decrypt ticket */
    struct ticket dec_ticket;
    memset(&dec_ticket, 0, sizeof(dec_ticket));
    int decrypted_ticket_len = decrypt(d_ticket, req.tkt_length, servKey, iv, (unsigned char *) &dec_ticket);
    //printf("original tic - decrypted\n");
    //BIO_dump_fp (stdout, (const char *)&dec_ticket, sizeof(dec_ticket)); printf("\n");
    
    /* add one to timestamp */
   // long int ts3 = (dec_ticket.ts2 + 1);
    //   printf("got here first\n");

   

    /* add one to timestamp */
    long int ts3 = (dec_ticket.ts2 + 1);

    /* encrypt the nonce  */
    unsigned char nonce_cipher[MINENC];
    memset(&nonce_cipher, 0, sizeof(long int));
    //printf("\nNonce: %s\n", nonce_cipher);
    //int nonce_ciphertext_len =    encrypt((unsigned char *) &ts3, sizeof(long int), dec_ticket.AES_key, iv, nonce_cipher);
    int nonce_ciphertext_len = encrypt((unsigned char *) &ts3, sizeof(long int), dec_ticket.AES_key, iv, nonce_cipher);
    //printf("nonce ciphertext\n");
    //BIO_dump_fp (stdout, (const char *) nonce_cipher, sizeof(nonce_cipher)); printf("\n");

    /* create the ap_rep struct */
    struct ap_rep response_AP;
    memset(&response_AP, 0, sizeof(response_AP));
    response_AP.type = AP_REP;
    response_AP.nonce_length = sizeof((dec_ticket.ts2+1));
    memcpy(&response_AP.nonce, (unsigned char *) &nonce_cipher, sizeof(nonce_cipher));
    
    //BIO_dump_fp (stdout, (const char *)&response_AP, sizeof(response_AP)); printf("\n");
    
    /* send ap_rep to client */
    if (sendto(sock, (struct ap_rep*)&response_AP, (sizeof(response_AP)), 0, (struct sockaddr *) &clientAddr, cliAddrLen) != sizeof(response_AP))
        DieWithError("sendto() sent a different number of bytes than expected");
    //printf("sent ap_rep from AP\n\n");

    /* get krb_prv->app_data_request from client */
    struct krb_prv kp1;
    memset(&kp1, 0, sizeof(kp1));
    cliAddrLen = sizeof(clientAddr);
    if((recvMsgSize = recvfrom(sock, &kp1, sizeof(struct krb_prv), 0, (struct sockaddr *) &clientAddr, &cliAddrLen)) < 0)
        DieWithError("recvfrom() failed");
    if(kp1.type != KRB_PRV) {
        DieWithError("Timestamp was not Authenticated");
    }
    //printf("got kp1 from client\n");
    //BIO_dump_fp (stdout, (const char *)&kp1, sizeof(kp1)); printf("\n");
    //printf("size of kp1: %li\n", sizeof(kp1));

    struct pdata s_pdata;
    memset(&s_pdata, 0, sizeof(s_pdata));
    int decrypted_s_pdata_len = decrypt(kp1.prv, kp1.prv_length, dec_ticket.AES_key, iv, (unsigned char *) &s_pdata);
    
    //BIO_dump_fp (stdout, (const char *)&s_pdata, sizeof(s_pdata)); printf("\n");
    

    /*
    HANDE RESPONSE
    */

    /* create pdata packet */
    struct pdata s_pdata2;
    memset(&s_pdata2, 0, sizeof(s_pdata2));
    s_pdata2.type = APP_DATA;
    s_pdata2.packet_length = strlen("Finally I got to send the data to the client. Succeed!");  //application payload length. Just consider the length of the 
                                                                                               //data stored in the pdata.data field. Discard the rest of the fields
    s_pdata2.pid = s_pdata.pid + 1;	//packet id, is a sequential number. Starts with 1.
    memcpy(s_pdata2.data, "Finally I got to send the data to the client. Succeed!", strlen("Finally I got to send the data to the client. Succeed!"));
    //BIO_dump_fp (stdout, (const char *) &s_pdata2, sizeof(s_pdata2)); printf("\n");

    /* encrypt pdata packter */
    unsigned char s_pdata2_cipher[BLOCK_SIZE];
    memset(&s_pdata2_cipher, 0, sizeof(s_pdata2_cipher));
  //int nonce_ciphertext_len =    encrypt((unsigned char *) &ts3, sizeof(long int), dec_ticket.AES_key, iv, nonce_cipher);
    int s_pdata2_ciphertext_len = encrypt((unsigned char *) &s_pdata2, sizeof(struct ticket), dec_ticket.AES_key, iv, s_pdata2_cipher);
    //printf("\npdata_cipher ciphertext\n");
    //BIO_dump_fp (stdout, (const char *) s_pdata2_cipher, s_pdata2_ciphertext_len); printf("\n");

    /* create krb_prv packet */
    struct krb_prv msg_back;
    memset(&msg_back, 0, sizeof(msg_back));
    msg_back.type = KRB_PRV;
    msg_back.prv_length = s_pdata2_ciphertext_len;                   //encrypted data length
    memcpy(msg_back.prv, s_pdata2_cipher, s_pdata2_ciphertext_len);  //encrypted data from struct pdata 
    //printf("msg back\n");
    //BIO_dump_fp (stdout, (const char *) &msg_back, sizeof(msg_back)); printf("\n");

    /* send app_data to client */
    if (sendto(sock, (struct ap_rep*)&msg_back, (sizeof(msg_back)), 0, (struct sockaddr *) &clientAddr, cliAddrLen) != sizeof(msg_back))
        DieWithError("sendto() sent a different number of bytes than expected");
    //printf("sent app_data from AP\n");

    printf("OK\n");
}
#include <stdio.h>      /* for printf() and fprintf() */
#include <sys/socket.h> /* for socket(), connect(), sendto(), and recvfrom() */
#include <arpa/inet.h>  /* for sockaddr_in and inet_addr() */
#include <stdlib.h>     /* for atoi() and exit() */
#include <string.h>     /* for memset() */
#include <unistd.h>     /* for close() */

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "packet_header.h"

#define MAX_STRING 255     /* Longest string to echo */
#define MAX_ID_STRING 40
#define KEY_LENGTH 32

void DieWithError(char *errorMessage)  /* External error handling function */
{
    perror(errorMessage);
    exit(1);
}

int main(int argc, char *argv[])
{
    int sock;                        /* Socket descriptor */
    //struct sockaddr_in echoServAddr; /* Echo server address */
    struct sockaddr_in authservAddr;
    struct sockaddr_in servAddr; 
    
    struct sockaddr_in fromAddr;     /* Source address of echo */

    //unsigned short echoServPort;     /* Echo server port */
    unsigned short authserverPort;
    unsigned short serverPort;

    unsigned int fromSize;           /* In-out of address size for recvfrom() */
    
    //char *servIP;                    /* IP address of server */
    char *authserverIP;
    char *serverIP;
    
    //char *echoString;                /* String to send to echo server */
    char *clientID;
    char *serverID;

    char *clientKey;
    memset(&clientKey, 0, KEY_LENGTH);

    //char echoBuffer[ECHOMAX+1];      /* Buffer for receiving echoed string */
    int clientStringLen;
    int servStringLen;
    int respStringLen;               /* Length of received response */
    unsigned int authAddrLen;         /* Length of incoming message from AS */
    unsigned int servAddrLen;         /* Length of incoming message from AP */
    char sharedSecret[32];//gen_random_key(sharedSecret, KEY_LENGTH);
    memcpy(sharedSecret, "abcdefghijklmnopqrstuvwxyz012345", 32);

    /* A 128 bit IV */
    unsigned char iv[16];
    memset(iv, 0, 16);

    if ((argc < 7) || (argc > 9))  /* Test for correct number of arguments */
    {
        fprintf(stderr,"Usage: %s <authservername> <authserverport> <clientkey> <server name> <server port> <clientID> <serverID>\n", argv[0]);
        exit(1);
    }

    /* Handle arguments */
    authserverIP = argv[1];     //
    //authserverPort = argv[2]; //
    clientKey = argv[3];        //
    serverIP = argv[4];         //
    //serverPort = argv[5];     //
    
    clientID = argv[6];         //
    if ((clientStringLen = strlen(clientID)) > MAX_ID_STRING)  /* Check input length */
        DieWithError("Client ID too long");
    
    serverID = argv[7];         //
    if ((servStringLen = strlen(serverID)) > MAX_ID_STRING)  /* Check input length */
        DieWithError("Server ID too long"); 
      

    //TODO validate that ports are in range
    if (argc == 8) {
        authserverPort = atoi(argv[2]);
        serverPort = atoi(argv[5]);
    } else {
        authserverPort = 9500;
        serverPort = 9501;
    }

    /* Create a datagram/UDP socket */
    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        DieWithError("socket() failed");

    /* Construct the authserver address structure */
    memset(&authservAddr, 0, sizeof(authservAddr));         /* Zero out structure */
    authservAddr.sin_family = AF_INET;                      /* Internet addr family */
    authservAddr.sin_addr.s_addr = inet_addr(authserverIP); /* Server IP address */
    authservAddr.sin_port = htons(authserverPort);          /* Server port */

    /* Construct the server address structure */
    memset(&servAddr, 0, sizeof(servAddr));             /* Zero out structure */
    servAddr.sin_family = AF_INET;                      /* Internet addr family */
    servAddr.sin_addr.s_addr = inet_addr(serverIP);     /* Server IP address */
    servAddr.sin_port = htons(serverPort);              /* Server port */

    /* Create AS_REQ struct */
    struct as_req request_AS;
    memset(&request_AS, 0, sizeof(request_AS));                   /* Zero out structure */
    request_AS.type = AS_REQ;                                  
    memcpy(&request_AS.client_id, clientID, strlen(clientID));
    memcpy(&request_AS.server_id, serverID, strlen(serverID));
    request_AS.ts1 = time(NULL); 

    /* Send the request to the authserver*/
    if (sendto(sock, (struct as_req*)&request_AS, (sizeof(request_AS)), 0, (struct sockaddr *) &authservAddr, sizeof(authservAddr)) != sizeof(request_AS))
        DieWithError("sendto() sent a different number of bytes than expected");         
    //printf("Sent AS request\n");

    /* Get response from AS */
    struct as_rep resp_AS;  /* create to handle to reception */
    authAddrLen = sizeof(authservAddr);
    if((respStringLen = recvfrom(sock, &resp_AS, sizeof(struct as_rep), 0, (struct sockaddr *) &authservAddr, &authAddrLen)) < 0)
        DieWithError("recvfrom() failed");
   
    //printf("got response from AS\n");
    if (resp_AS.type != AS_REP) {
        DieWithError("Incorrect Packet Type");
    }
    /* print output */
    //BIO_dump_fp (stdout, (const char *) &resp_AS, sizeof(resp_AS));  

    // load for decrypt rep 
    unsigned char dec_cred[SCRED];
    //iter through resp_AS.cred into dec_cred
    for (int i = 0; i < SCRED; i++){
        dec_cred[i] = resp_AS.cred[i];
    }

    //int decryptedtext_len = decrypt(resp_AS.cred, resp_AS.cred_length, sharedSecret, iv, (unsigned char *) dec_cred);
    struct credential dec_credentials;
    int decryptedtext_len = decrypt(dec_cred, resp_AS.cred_length, sharedSecret, iv, (unsigned char *) &dec_credentials);

    //printf("\nencrypted ticket from dec cred\n");
    //BIO_dump_fp (stdout, (const char *) &dec_credentials.tkt_serv, sizeof(dec_credentials.tkt_serv)); 

    struct auth Authenticator;
    memcpy(&Authenticator.client_id, clientID, clientStringLen); 
    Authenticator.ts3 = time(NULL);



    /*
     * BEGIN CONNECTION TO SERVER
     */

    /* create auth struct */
    struct auth clientAuth;
    memset(&clientAuth, 0, sizeof(clientAuth)); 
    memcpy(&clientAuth.client_id, clientID, strlen(clientID));
    clientAuth.ts3 = time(NULL);

    /* encrypt auth */
    unsigned char clientAuthCipher[SAUTH];
    memset(&clientAuthCipher, 0, strlen(clientAuthCipher));
    int ciphertext_clientAuth_len = encrypt((unsigned char *) &clientAuth, sizeof(struct auth), sharedSecret, iv, clientAuthCipher);

    /* create ap_req struct */
    struct ap_req request_AP;
    memset(&request_AP, 0, sizeof(request_AP)); 
    request_AP.type = AP_REQ;
    request_AP.tkt_length = dec_credentials.tkt_length;  
    request_AP.auth_length = sizeof(clientAuth);
    memcpy(request_AP.tkt_serv, &dec_credentials.tkt_serv, sizeof(dec_credentials.tkt_serv));        
    memcpy(request_AP.auth, clientAuthCipher, ciphertext_clientAuth_len);

    //printf("\nap_req\n");
    //BIO_dump_fp (stdout, (const char *) &request_AP, sizeof(request_AP));

    //send ap_req     
    if (sendto(sock, (struct as_rep*)&request_AP, (sizeof(request_AP)), 0, (struct sockaddr *) &servAddr, sizeof(servAddr)) != sizeof(request_AP))
        DieWithError("sendto() sent a different number of bytes than expected");  


    /* Get response from AS */
    struct ap_rep resp_AP;  /* create to handle to reception */
    memset(&resp_AP, 0, sizeof(resp_AP));
    servAddrLen = sizeof(servAddr);
    if((respStringLen = recvfrom(sock, &resp_AP, sizeof(struct as_rep), 0, (struct sockaddr *) &servAddr, &servAddrLen)) < 0)
        DieWithError("recvfrom() failed");
    //printf("got response from AP\n"); 
    //BIO_dump_fp (stdout, (const char *) &resp_AP, sizeof(resp_AP)); printf("\n");

    /* create pdata packet */
    struct pdata c_pdata;
    memset(&c_pdata, 0, sizeof(c_pdata));
    c_pdata.type = APP_DATA_REQ;
    c_pdata.packet_length = strlen("One Sentence");  //application payload length. Just consider the length of the 
                                                     //data stored in the pdata.data field. Discard the rest of the fields
    c_pdata.pid = 1;	//packet id, is a sequential number. Starts with 1.
    memcpy(c_pdata.data, "One Sentence", strlen("One Sentence"));

    /* encrypt pdata packter */
    unsigned char pdata_cipher[BLOCK_SIZE];
    memset(&pdata_cipher, 0, sizeof(pdata_cipher));
    int pdata_ciphertext_len = encrypt((unsigned char *) &c_pdata, sizeof(struct ticket), sharedSecret, iv, pdata_cipher);

    /* create krb_prv packet */
    struct krb_prv msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = KRB_PRV;
    msg.prv_length = pdata_ciphertext_len;               //encrypted data length
    memcpy(msg.prv, pdata_cipher, pdata_ciphertext_len); //encrypted data from struct pdata 
    //BIO_dump_fp (stdout, (const char *) &msg, sizeof(msg)); printf("\n");

    /* send krb_prv */
    //printf("sending krb_prv to AP\n");     
    if (sendto(sock, (struct krb_prv*)&msg, (sizeof(msg)), 0, (struct sockaddr *) &servAddr, sizeof(servAddr)) != sizeof(msg))
        DieWithError("sendto() sent a different number of bytes than expected"); 

    /* get krb_prv->app_data from server */
    struct krb_prv kp2;
    memset(&kp2, 0, sizeof(kp2));
    servAddrLen = sizeof(servAddr);
    if((respStringLen = recvfrom(sock, &kp2, sizeof(struct krb_prv), 0, (struct sockaddr *) &servAddr, &servAddrLen)) < 0)
        DieWithError("recvfrom() failed");
    printf("Encrypted message\n");
    BIO_dump_fp (stdout, (const char *) &kp2, sizeof(kp2)); printf("\n");

    //get message from server
    struct pdata c_pdata2;
    memset(&c_pdata2, 0, sizeof(c_pdata2));
    int decrypted_c_pdata2_len = decrypt(kp2.prv, kp2.prv_length, sharedSecret, iv, (unsigned char *) &c_pdata2);
    
    printf("Decrypted message\n");
    BIO_dump_fp (stdout, (const char *) &c_pdata2, sizeof(c_pdata2)); printf("\n");

    
    printf("OK\n");
    close(sock);
    exit(0);
}
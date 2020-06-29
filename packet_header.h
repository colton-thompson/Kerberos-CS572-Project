/*****************************************************************
* Header file to use in your implementation of the project.      *
* Please, do not modify any value or structure that appears here *
*								 *
* Special notations:						 *
*	- Authentication Server = AS				 *
*	- Application Server = AP			       	 *
*****************************************************************/
//https://wiki.openssl.org/images/1/17/Evp-symmetric-encrypt.c wiki code
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/des.h>
#include <time.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/utsname.h>

//packet type definitions
#define AS_REQ          1
#define AS_REP          2	
#define AS_ERR          3	
#define AP_REQ          4	
#define AP_REP          5
#define AP_ERR          6
#define KRB_PRV         7
#define APP_DATA_REQ    14
#define APP_DATA        15

//variables
#define ERR             -1
#define LIFETIME        3600	//lifetime of the session key in 5 minutes units
#define STICKET         144	//size of ticket struct encrypted, in bytes
#define SCRED           240	//size of credential struct encrypted, in bytes
#define SAUTH           64	//size of auth struct encrypted, in bytes
#define MINENC          16	//size of nonce encrypted, in bytes
#define MAXENC          976	//size of application data packet encrypted, in bytes
#define BLOCK_SIZE      960	//size of data block for application data packet, in bytes

//Ticket generated by the AS for the Server
struct ticket
{
	unsigned char AES_key[32];      //session key
        unsigned char client_id[40];	//client identification (Is just a string of chars, e.g. "ALICE")
        unsigned char server_id[40];	//AP identification (Is just a string of chars, e.g. "BOB")
        time_t ts2;			//timestamp - ticket creation. The datatype is just a requirement of the function time()
        int lt;				//lifetime of ticket in seconds (LIFETIME = 3600 = 1hr) 
};

//Contains the session key and related information, 
//passed from the AS to the client
struct credential
{
	unsigned char AES_key[32];      //session key
        unsigned char server_id[40];	//AP identification (Is just a string of chars, e.g. "BOB")
        time_t ts2;			//timestamp - ticket creation. The datatype is just a requirement of the function time()
        int lt2;			//lifetime of session key in seconds (LIFETIME = 3600 = 1hr)
        int tkt_length;			//length of encrypted ticket generated by the AS to the AP
        unsigned char tkt_serv[STICKET];//The encrypted ticket.
};

//message used for the client to request a session key to the AS
struct as_req
{
        short type;			// packet type
        unsigned char client_id[40];	//client identification (Is just a string of chars, e.g. "ALICE")
        unsigned char server_id[40];	//AP identification (Is just a string of chars, e.g. "BOB")
        time_t ts1;
};

//reply from the AS with session key to client and ticket to AP
struct as_rep
{
        short type;			// packet type
        short cred_length;		// length of encrypte struct credential
        unsigned char cred[SCRED];	// The encrypted struct credential
};

//If the client sends a wrong client_ID or server_ID to the AS, the AS will return an AS_ERR message
struct as_err
{
	short type;			//packet type
	unsigned char client_id[40];	//client identification (Is just a string of chars, e.g. "ALICE")
};

//used for the client to authenticate to the AP
struct auth
{
        unsigned char client_id[40];		//client identification (Is just a string of chars, e.g. "ALICE")
        time_t ts3;				//timestamp - The datatype is just a requirement of the function time()
};

//This message is sent from the client to the AP and contains the ticket and authenticator
struct ap_req
{
        short type;				//packet type
        short tkt_length;			//ticket length
        short auth_length;			//struct auth length
        unsigned char tkt_serv[STICKET];	//encrypted ticket
        unsigned char auth[SAUTH];		//encrypted struct auth
};

//authenticates the AP to client
struct ap_rep
{
        short type;			//type of packet
        short nonce_length;		//size of nonce encrypted
        unsigned char nonce[MINENC];	//nonce encrypted
};

//AP_ERR message is sent by either the client (to the AP) or the AP (to the client) in two situations:
//1. If the client received a wrong AP_REP message from the AP, it will return a AP_ERR to the AP.
//Recall that the AP_REP message contains the value (timestamp3 + 1), where timestamp3 was initially
//sent from the client to the AP (Refer to lab3 handout).
//2. If the AP receive a client id from the Authenticator (Refer to hand out) that 
//do not match with the client id that were sent with the ticket by the AS
struct ap_err
{
	short type;			//packet type
	unsigned char client_id[40];
};

//packet used to send encrypted application data
struct krb_prv
{
        short type;			//packet type
        short prv_length;		//encrypted data length
        unsigned char prv[MAXENC];	//encrypted data from struct pdata 
};

//The following structure goes  encrypted in the KRB_PRV packet. It contains the application data block
struct pdata
{
        short     type;			//application packet type
        short     packet_length;		//application payload length. Just consider the length of the 
					//data stored in the pdata.data field. Discard the rest of the fields
        short     pid;			//packet id, is a sequential number. Starts with 1.
        unsigned char    data[BLOCK_SIZE];	//application data
};

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);


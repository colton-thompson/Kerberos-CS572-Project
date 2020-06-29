#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include "packet_header.h"

void try_encrypt_struct()
{
    /*
     * Set up the key and iv. Do not hard code these in a * real application :-)
     */

    /* A 256 bit key */
    unsigned char key[32];
    memset(key, 0, 32);
    strcpy(key, "0123456789012345678901234567890");

    /* A 128 bit IV */
    unsigned char iv[16];
    memset(iv, 0, 16);

    int decryptedtext_len, ciphertext_len;

    
    struct ticket t1, t2;
    memset(&t1, 0, sizeof(t1)); //added by Fei
    strcpy(t1.AES_key, "abc");
    strcpy(t1.client_id, "client");
    strcpy(t1.server_id, "server");
    t1.ts2 = time(NULL);
    t1.lt = LIFETIME;

    printf("\nPlaintext is: (length=%ld)\n", sizeof(struct ticket));
    printf("key=%s, client=%s, server=%s, time=%ld, lt=%d\n\n", 
            t1.AES_key, t1.client_id, t1.server_id, t1.ts2, t1.lt);
    BIO_dump_fp (stdout, (const char *)&t1, sizeof(struct ticket));

    unsigned char t1_cipher[1024];
    /* Encrypt the plaintext */
    ciphertext_len = encrypt ((unsigned char *) &t1, sizeof(struct ticket), key, iv, t1_cipher);

    /* Do something useful with the ciphertext here */
    printf("\nCiphertext is: (length=%d)\n", ciphertext_len);
    BIO_dump_fp (stdout, (const char *)t1_cipher, ciphertext_len);

    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt(t1_cipher, ciphertext_len, key, iv, (unsigned char *) &t2);

    printf("\nDecrypted is: (length=%d)\n", decryptedtext_len);
    printf("key=%s, client=%s, server=%s, time=%ld, lt=%d\n\n", 
            t2.AES_key, t2.client_id, t2.server_id, t2.ts2, t2.lt);
    BIO_dump_fp (stdout, (const char *)&t2, sizeof(struct ticket));
}

int main (void)
{
    try_encrypt_struct();
    printf("\nsize of time_t=%ld\n", sizeof(time_t));
}

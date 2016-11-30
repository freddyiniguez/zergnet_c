#ifndef ZERGNET_H_
#define ZERGNET_H_
#include <openssl/rsa.h>

RSA * createRSA(unsigned char * key, int public);
void printLastError(char *msg);
int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted);
int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted);
int private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted);
int public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted);
int encryption_with_public_key(char* msg);
int decryption_with_private_key(char* msg);

#endif // ZERGNET_H_

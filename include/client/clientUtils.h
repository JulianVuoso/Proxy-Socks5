#ifndef __PROTOS_CLIENT_UTIL__
#define __PROTOS_CLIENT_UTIL__

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>

#define ADD_USER "add-user"
#define ADD_USER_NO 1
#define DEL_USER "del-user"
#define DEL_USER_NO 2
#define LIST_USER "list-user"
#define LIST_USERS_NO 3
#define GET_METRIC "get-metric"
#define GET_METRIC_NO 4
#define GET_CONFIG "get-config"
#define GET_CONFIG_NO 5
#define SET_CONFIG "set-config"
#define SET_CONFIG_NO 6

#define MAX_DATA_LEN 514
#define READBUFFER_LEN 257



void validateArgv(int argc,char *const*argv);
int getNextCommand(int argc,char * const*argv,int cmdStartIndex,uint8_t *data,int *datalen);
int handleResponse(int sockfd,int cmd, uint8_t *readBuffer);

#endif
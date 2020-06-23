#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <netdb.h>

#include "client/clientUtils.h"

#define AUTH_MSG_LEN 513
#define MAX_COMMANDS 10

#define PROTO_VERSION 0X01

#define DEFAULT_PORT 8080
#define DEFAULT_HOST "127.0.0.1"


int main(int argc, char * const *argv) {
    //checkear que todos los comandos esten al final
    if (!valid_args(argc, argv)) {
        printf("%s Wrong arg format error. Commands should go last\n", cError);
        return -1;
    }
    
    //declare variables
    int sockfd = 0;
    long int port = DEFAULT_PORT;
    char *host = DEFAULT_HOST;
    char *userpass = NULL;
    struct sockaddr_in addr;
    int opt;

    //parse argument
    while ((opt = getopt(argc, argv, "u:p:l:")) > 0) {
        switch (opt) {
        case 'p':
            if (optarg != NULL) port = strtol(optarg, NULL, 10);
            break;
        case 'u':
            userpass = optarg;
            break;
        case 'l':
            if (optarg != NULL) host = optarg;
            break;
        }
    }
    
    //start of commands
    int cmdStartIndex = optind;

    //check for userpass
    if (userpass == NULL) {
        printf("%s Missing user credentials\n", cError);
        return -1;
    }

    //make authentication
    int authlen = 0;
    uint8_t auth[AUTH_MSG_LEN];
    int ulen = 0, plen = 0;
    auth[0] = PROTO_VERSION;

    for (int i = 0, pass = 0; userpass[i] != 0 && i < AUTH_MSG_LEN - 2; i++) {
        if (userpass[i] == ':') {
            if (pass) {
                printf("%s User should be -u user:pass\n", cError);
                return -1;
            }
            pass = 1;
        } else {
            if (!pass) {
                auth[i + 2] = userpass[i];
                ulen++;
            } else {
                auth[i + 2] = userpass[i];
                plen++;
            }
        }
    }

    //check there actually is a user and password
    if (ulen > 255 || plen > 255) {
        printf("%s User/password cant be longer than 255 chararcters\n", cError);
        return -1;
    }
    auth[1] = ulen;
    auth[ulen + 2] = plen;
    authlen = 2 + ulen + 1 + plen;
    int datalen = 0;
    uint8_t data[MAX_DATA_LEN];

    //open socket for sctp
    if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)) < 0) {
        printf("%s Error creating socket\n", cError);
        return -1;
    }

    //set addr
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    //convert ip from string to byte
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        printf("%s Invalid Host IP (%s)\n", cError, host);
        close(sockfd);
        return -1;
    }
    //connect
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("%s Error connecting proxy\n", cError);
        close(sockfd);
        return -1;
    }

    //authenticate
    send(sockfd, auth, authlen, 0);
    uint8_t readBuffer[READBUFFER_LEN];
    recv_wrapper(sockfd, readBuffer, 2, 0);
    if (readBuffer[0] != 0x01) {
        printf("%s Invalid protocol version\n", sError);
        close(sockfd);
        return -1;
    }

    if (readBuffer[1] != 0x00) {
        printf("%s Bad authentication\n", sError);
        close(sockfd);
        return -1;
    }


    //at this point it is authenticated
    int cmd[MAX_COMMANDS];
    int amtCmds = 0;
    //send all commands received
    uint8_t cmd_fail = 0;
    for (int i = 0; i < MAX_COMMANDS && argc > cmdStartIndex && !cmd_fail; i++) {
        //get next command
        cmd[i] = get_next_command(argc, argv, &cmdStartIndex, data, &datalen);
        if(cmd[i] >= 0) {
            //send it
            if(send(sockfd, data, datalen, 0) == datalen)
                amtCmds++;
            else {
                cmd_fail = 1;
                printf("%s Error sending request. Stopped sending\n", cError);
            }
        } else cmd_fail = 1;
    }
    if (amtCmds > 0) printf("\n\033[0;34m---------------\tStart Server Responses\t---------------\033[0m\n\n");
    // handle all commands send
    int8_t resp_fail = 0;
    for (int i = 0; i < amtCmds && resp_fail >= 0; i++) {
        recv_wrapper(sockfd, readBuffer, 2, 0);

        //handle response
        resp_fail = handle_response(sockfd, cmd[i], readBuffer);
    }
    if (amtCmds > 0) printf("\n\033[0;34m---------------\tEnd Server Responses\t---------------\033[0m\n\n");
    if (cmd_fail) printf("%s Some commands where not sent due to bad format\n", cError);
    if (resp_fail == -1) printf("%s Server closed connection due to bad request\n\n", cError);
    //close connection and exit
    close(sockfd);
    return 0;
}



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

int main(int argc, char *const *argv)
{
    //checkear que todos los comandos esten al final
    validateArgv(argc,argv);
    //declare variables
    int sockfd = 0;
    long int port = DEFAULT_PORT;
    char *host = DEFAULT_HOST;
    char *userpass = NULL;
    struct sockaddr_in addr;
    int opt;
    //parse argument
    while ((opt = getopt(argc, argv, "u:p:l:")) > 0)
    {
        switch (opt)
        {
        case 'p':
            if (optarg != NULL)
            {
                port = strtol(optarg, NULL, 10);
            }
            break;
        case 'u':
            userpass = optarg;
            break;
        case 'l':
            if (optarg != NULL)
            {
                host = optarg;
            }
            break;
        }
    }
    
    //start of commands
    int cmdStartIndex = optind;


    //check theres a command
    if (argc <= cmdStartIndex)
    {
        printf("Falta comando\n");
        return -1;
    }

    //check for userpass
    if (userpass == NULL)
    {
        printf("Falta usuario:contraseña\n");
        return -1;
    }

    //make authentication
    int authlen = 0;
    uint8_t auth[AUTH_MSG_LEN];
    int ulen = 0, plen = 0;
    auth[0] = PROTO_VERSION;
    for (int i = 0, pass = 0; userpass[i] != 0 && i < AUTH_MSG_LEN - 2; i++)
    {
        if (userpass[i] == ':')
        {
            if (pass)
            {
                printf("Error de formato, el formato de -u deberia ser user:pass\n");
                return -1;
            }
            pass = 1;
        }
        else
        {
            if (!pass)
            {
                auth[i + 2] = userpass[i];
                ulen++;
            }
            else
            {
                auth[i + 2] = userpass[i];
                plen++;
            }
        }
    }
    //check there actually is a user and password
    if (ulen <= 0 || ulen > 255 || plen > 255 || plen <= 0)
    {
        printf("Error de formato, el formato de -u deberia ser user:pass con ambos una longitud entre 1 y 255\n");
        return -1;
    }
    auth[1] = ulen;
    auth[ulen + 2] = plen;
    authlen = 2 + ulen + 1 + plen;
    int datalen = 0;
    uint8_t data[MAX_DATA_LEN];

    //open socket for sctp
    if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)) < 0)
    {
        printf("Error al crear el socket\n");
        return -1;
    }

    //set addr
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    //convert ip from string to byte
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0)
    {
        printf("IP del host invalida:%s\n", host);
        close(sockfd);
        return -1;
    }
    //connect
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        printf("Error en la conexion\n");
        close(sockfd);
        return -1;
    }
    //authenticate
    send(sockfd, auth, authlen, 0);
    uint8_t readBuffer[READBUFFER_LEN];
    recvWrapper(sockfd, readBuffer, 2, 0);
    if (readBuffer[0] != 0x01)
    {
        printf("El servidor usa una version distinta del protocolo\n");
        close(sockfd);
        return -1;
    }
    if (readBuffer[1] != 0)
    {
        printf("Hubo un error en la autenticacion\n");
        close(sockfd);
        return -1;
    }


    //at this point it is authenticated
    int cmd[MAX_COMMANDS];
    int amtCmds = 0;
    //send all commands received
    for (int i = 0,fail = 0; i<MAX_COMMANDS && argc>cmdStartIndex && !fail; i++)
    {
        //get next command
        cmd[i] = getNextCommand(argc,argv,&cmdStartIndex,data,&datalen);
        if(cmd[i] < 0){
            fail = i + 1;
        }else{
            //send it
            if(send(sockfd, data, datalen, 0) != 0){
                amtCmds++;
                printf("---------- Sent data ---------- \n");
                for (uint64_t i = 0; i < datalen; i++) printf("0x%02X ", data[i]);
                printf("\n---------- End of data ----------\n\n");
            }else{
                fail = i + 1;
            }
        }
    }
    // handle all commands send
    for (int i = 0; i < amtCmds; i++)
    {
        recvWrapper(sockfd, readBuffer, 2, 0);
        if (readBuffer[0] != cmd[i])
        {
            printf("La respuesta no matchea el comando pedido\n");
        }
        else{
            //handle response
            int res = handleResponse(sockfd,cmd[i], readBuffer);
            if(res<0){
                close(sockfd);
                return -1;
            }    
        }
    }
    
    //close connection and exit
    close(sockfd);
    return 0;
}

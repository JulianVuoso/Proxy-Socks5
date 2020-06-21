#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>

#define AUTH_MSG_LEN 513
#define MAX_DATA_LEN 514
#define READBUFFER_LEN 257

#define DEFAULT_PORT 8080
#define DEFAULT_HOST "127.0.0.1"

#define ADD_USER "add-user"
#define ADD_USER_NO 1
#define DEL_USER "del-user"
#define DEL_USER_NO 2
#define LIST_USER "list-users"
#define LIST_USERS_NO 3
#define GET_METRIC "get-metric"
#define GET_METRIC_NO 4
#define GET_CONFIG "get-config"
#define GET_CONFIG_NO 5
#define SET_CONFIG "set-config"
#define SET_CONFIG_NO 6

int main(int argc, char *const *argv)
{
    //declare variables
    int sockfd = 0;
    long int port = DEFAULT_PORT;
    char *host = "127.0.0.1";
    char *userpass = NULL;
    struct sockaddr_in addr;
    int opt;
    int cmd;
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
                port = strtol(optarg, NULL, 10);
            }
            break;
        }
    }

    //check theres a command
    if (argc <= optind)
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
    auth[0] = 0x01;
    for (int i = 0, pass = 0; userpass[i] != 0 && i < AUTH_MSG_LEN - 2; i++)
    {
        if (userpass[i] == ':')
        {
            if (pass)
            {
                printf("Error de formato, el formato de -u deberia ser user:pass");
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
        printf("Error de formato, el formato de -u deberia ser user:pass con ambos una longitud entre 1 y 255");
        return -1;
    }
    auth[1] = ulen;
    auth[ulen + 2] = plen;
    authlen = 2 + ulen + 1 + plen;
    int datalen = 0;
    uint8_t data[MAX_DATA_LEN];

    //check command
    if (strcmp(argv[optind], "add-user") == 0)
    {
        cmd = ADD_USER_NO;
        if (argc <= optind + 1)
        {
            printf("Falta usuario:password a agregar\n");
            return -1;
        }
        char *nuser = argv[optind + 1];
        int nulen = 0, nplen = 0;
        //ADD USER
        data[0] = ADD_USER_NO;
        for (int i = 0, pass = 0; nuser[i] != 0 && i < MAX_DATA_LEN - 2; i++)
        {
            if (nuser[i] == ':')
            {
                if (pass)
                {
                    printf("Error de formato, el formato del parametro de add-user deberia ser user:pass");
                    return -1;
                }
                pass = 1;
            }
            else
            {
                if (!pass)
                {
                    nulen++;
                    data[i + 3] = nuser[i];
                }
                else
                {
                    nplen++;
                    data[i + 3] = nuser[i];
                }
            }
        }
        if (nulen <= 0 || nulen > 255 || nplen <= 0 || nplen > 255)
        {
            printf("Error de formato, el formato de add-user deberia ser user:pass con ambos una longitud entre 1 y 255");
            return -1;
        }
        data[2] = nulen;
        data[3 + nulen] = nplen;
        if (argc <= optind + 2)
        {
            data[1] = 0;
        }
        else
        {
            char *ntype = argv[optind + 2];
            if (ntype[0] == '0')
            {
                data[1] = 0;
            }
            else if (ntype[0] == '1')
            {
                data[1] = 1;
            }
            else
            {
                printf("El tipo de usuario debe ser 0 (cliente) o 1 (admin)\n");
                return -1;
            }
        }
        //cmd|ulen|username|plen|password
        datalen = 2 + nulen + 1 + nplen + 1;
    }
    else if (strcmp(argv[optind], "del-user") == 0)
    {
        cmd = DEL_USER_NO;
        data[0] = DEL_USER_NO;
        if (argc <= optind + 1)
        {
            printf("Falta usuario a borrar\n");
            return -1;
        }
        char *deluser = argv[optind + 1];
        datalen = 2;
        for (int i = 0; deluser[i] != 0 && i < MAX_DATA_LEN; i++)
        {
            data[i + 2] = deluser[i];
            datalen++;
        }
        if (datalen <= 0 || datalen > 255)
        {
            printf("Error de formato, el formato de del-user deberia ser user con longitud entre 1 y 255");
            return -1;
        }
        data[1] = datalen - 2;
    }
    else if (strcmp(argv[optind], "list-users") == 0)
    {
        cmd = LIST_USERS_NO;
        data[0] = LIST_USERS_NO;
        datalen = 1;
    }
    else if (strcmp(argv[optind], "get-metric") == 0)
    {
        cmd = GET_METRIC_NO;
        data[0] = GET_METRIC_NO;
        if (argc <= optind + 1)
        {
            printf("Falta metrica\n");
            return -1;
        }
        char *metric = argv[optind + 1];
        if (metric[0] >= '0' && metric[0] <= '2')
        {
            data[1] = metric[0] - '0';
        }
        else
        {
            printf("Error en el formato de la metrica. Debe ser 0,1 o 2\n");
            return -1;
        }
        datalen = 2;
    }
    else if (strcmp(argv[optind], "get-config") == 0)
    {
        cmd = GET_CONFIG_NO;
        data[0] = GET_CONFIG_NO;
        if (argc <= optind + 1)
        {
            printf("Falta configuracion\n");
            return -1;
        }
        char *config = argv[optind + 1];
        if (config[0] >= '0' && config[0] <= '3')
        {
            data[1] = config[0] - '0';
        }
        else
        {
            printf("Error en el formato de la configuracion. Debe ser 0,1,2 o 3\n");
            return -1;
        }
        datalen = 2;
    }
    else if (strcmp(argv[optind], "set-config") == 0)
    {
        cmd = SET_CONFIG_NO;
        data[0] = SET_CONFIG_NO;
        if (argc <= optind + 1)
        {
            printf("Falta configuracion\n");
            return -1;
        }
        char *config = argv[optind + 1];
        if (config[0] >= '0' && config[0] <= '3')
        {
            data[1] = config[0] - '0';
        }
        else
        {
            printf("Error en el formato de la configuracion. Debe ser 0,1,2 o 3\n");
            return -1;
        }
        if (argc <= optind + 2)
        {
            printf("Falta configuracion\n");
            return -1;
        }
        char *nval = argv[optind + 2];
        unsigned long ulnval = strtoul(nval, NULL, 10);
        data[2] = sizeof(ulnval);
        *((unsigned long *)(data + 2)) = ulnval;
        datalen = data[2] + 2;
    }
    else
    {
        printf("Comando invalido\n");
        return -1;
    }

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
        printf("IP del host invalida:%s\n", host);list-user
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
    recv(sockfd, readBuffer, 2, 0);
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
    send(sockfd, data, datalen, 0);
    recv(sockfd, readBuffer, 2, 0);
    if (readBuffer[0] != cmd)
    {
        printf("La respuesta no matchea el comando pedido\n");
        close(sockfd);
        return -1;
    }
    if (readBuffer[1] == 0x01)
    {
        printf("Comando invalido\n");
        close(sockfd);
        return -1;
    }
    if (readBuffer[1] == 0xFF)
    {
        printf("Fallo general del servidor\n");
        close(sockfd);
        return -1;
    }

    switch (cmd)
    {
    case ADD_USER_NO:
        if (readBuffer[1] == 0)
        {
            printf("usuario creado\n");
        }
        else if (readBuffer[1] == 0x02)
        {
            printf("Longitud de usuario invalida\n");
            close(sockfd);
            return -1;
        }else if (readBuffer[1] == 0x03)
        {
            printf("Tipo de usuario invalido\n");
            close(sockfd);
            return -1;
        }
        break;
    case DEL_USER_NO:
        if (readBuffer[1] == 0)
        {
            printf("usuario borrado\n");
        }
        break;
    case LIST_USERS_NO:
        if (readBuffer[1] == 0)
        {
            recv(sockfd, readBuffer, 2, 0);
            uint16_t nusers = (((uint16_t)readBuffer[0] << 8) & 0xFF00) + readBuffer[1];
            printf("usario tipo\n");
            fflush(stdout);
            for (int i = 0,nulen = 0,utype=0; i < nusers; i++)
            {
                recv(sockfd, readBuffer, 2, 0);
                utype = readBuffer[0];
                nulen = readBuffer[1];
                recv(sockfd, readBuffer, nulen, 0);
                write(STDOUT_FILENO, readBuffer, nulen);
                printf(" %d\n", utype);
            }
        }
        break;
    case GET_METRIC_NO:
        if (readBuffer[1] == 0)
        {
            recv(sockfd, readBuffer, READBUFFER_LEN, 0);
            if(readBuffer[1] > sizeof(unsigned long)){
                printf("El numero de bytes de respuesta es muy grande para este cliente \n");
                close(sockfd);
                return -1;
            }
            unsigned long metricVal = 0;
            for (int i = 0; i < readBuffer[1]; i++)
            {
                metricVal = (metricVal<<8) + readBuffer[i+2];
            }
            
            switch (readBuffer[0])
            {
            case 0:
                printf("Conexiones historicas:%lu",metricVal);
                break;
            case 1:
                printf("Conexiones concurrentes:%lu",metricVal);
                break;
            case 2:
                printf("Transferencia de bytes historica:%lu",metricVal);
                break;
            default:
                printf("Metrica desconocida:%lu",metricVal);
                break;
            }
        }else if (readBuffer[1] == 0x04)
        {
            printf("Metrica invalida\n");
            close(sockfd);
            return -1;
        }
        break;
    case GET_CONFIG_NO:
        if (readBuffer[1] == 0)
        {
            recv(sockfd, readBuffer, READBUFFER_LEN, 0);
            if(readBuffer[1] > sizeof(unsigned long)){
                printf("El numero de bytes de respuesta es muy grande para este cliente \n");
                close(sockfd);
                return -1;
            }
            unsigned long configVal = 0;
            for (int i = 0; i < readBuffer[1]; i++)
            {
                configVal = (configVal<<8) + readBuffer[i+2];
            }
            
            switch (readBuffer[0])
            {
            case 0:
                printf("Tamaño de ambos buffers:%lu",configVal);
                break;
            case 1:
                printf("Tamaño de buffer de lectura:%lu",configVal);
                break;
            case 2:
                printf("Tamaño de buffer de escritura:%lu",configVal);
                break;
            case 3:
                printf("Timeout del select:%lu",configVal);
                break;
            default:
                printf("Configuracion desconocida:%lu",configVal);
                break;
            }
        }else if (readBuffer[1] == 0x05)
        {
            printf("Configuracion invalida\n");
            close(sockfd);
            return -1;
        }
        break;
    case SET_CONFIG_NO:
        if (readBuffer[1] == 0)
        {
            printf("Configuracion seteada\n");
        }else if (readBuffer[1] == 0x05)
        {
            printf("Configuracion invalida\n");
            close(sockfd);
            return -1;
        }else if (readBuffer[1] == 0x06)
        {
            printf("Valor de configuracion invalido\n");
            close(sockfd);
            return -1;
        }
        break;
    default:
        printf("Hubo un problema\n");
        close(sockfd);
        return -1;
        break;
    }
    //close connection and exit
    close(sockfd);
    return 0;
}

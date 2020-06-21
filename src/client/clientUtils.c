#include "client/clientUtils.h"


//chekear que todos los comandos esten al final
void validateArgv(int argc,char * const*argv){
    for (int i = 1,optEnd = 0, optArg = 0; i < argc; i++)
    {
           if(!optArg){
               if(argv[i][0]=='-'){
                   if(optEnd){
                       printf("Formato erroneo, los comandos deben ir al final\n");
                       exit(-1);
                   }
                   optArg = 1;
               }else{
                   optEnd = 1;
               }
           }else{
               optArg = 0;
           }
    }
}

//get next command
int getNextCommand(int argc,char * const*argv,int *cmdStartIndex,uint8_t *data,int *datalen){
    int cmd;
    if (strcmp(argv[(*cmdStartIndex)], "add-user") == 0)
    {
        cmd = ADD_USER_NO;
        if (argc <= (*cmdStartIndex) + 1)
        {
            printf("Falta usuario:password a agregar\n");
            return -1;
        }
        char *nuser = argv[(*cmdStartIndex) + 1];
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
        if (argc <= (*cmdStartIndex) + 2)
        {
            data[1] = 0;
        }
        else
        {
            char *ntype = argv[(*cmdStartIndex) + 2];
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
        *datalen = 2 + nulen + 1 + nplen + 1;
        *cmdStartIndex += 2;
    }
    else if (strcmp(argv[(*cmdStartIndex)], "del-user") == 0)
    {
        cmd = DEL_USER_NO;
        data[0] = DEL_USER_NO;
        if (argc <= (*cmdStartIndex) + 1)
        {
            printf("Falta usuario a borrar\n");
            return -1;
        }
        char *deluser = argv[(*cmdStartIndex) + 1];
        *datalen = 2;
        for (int i = 0; deluser[i] != 0 && i < MAX_DATA_LEN; i++)
        {
            data[i + 2] = deluser[i];
            (*datalen)++;
        }
        if (*datalen <= 0 || *datalen > 255)
        {
            printf("Error de formato, el formato de del-user deberia ser user con longitud entre 1 y 255");
            return -1;
        }
        data[1] = *datalen - 2;
        *cmdStartIndex += 2;
    }
    else if (strcmp(argv[(*cmdStartIndex)], "list-users") == 0)
    {
        cmd = LIST_USERS_NO;
        data[0] = LIST_USERS_NO;
        *datalen = 1;
        *cmdStartIndex += 1;
    }
    else if (strcmp(argv[(*cmdStartIndex)], "get-metric") == 0)
    {
        cmd = GET_METRIC_NO;
        data[0] = GET_METRIC_NO;
        if (argc <= (*cmdStartIndex) + 1)
        {
            printf("Falta metrica\n");
            return -1;
        }
        char *metric = argv[(*cmdStartIndex) + 1];
        if (metric[0] >= '0' && metric[0] <= '2')
        {
            data[1] = metric[0] - '0';
        }
        else
        {
            printf("Error en el formato de la metrica. Debe ser 0,1 o 2\n");
            return -1;
        }
        *datalen = 2;
        *cmdStartIndex += 2;
    }
    else if (strcmp(argv[(*cmdStartIndex)], "get-config") == 0)
    {
        cmd = GET_CONFIG_NO;
        data[0] = GET_CONFIG_NO;
        if (argc <= (*cmdStartIndex) + 1)
        {
            printf("Falta configuracion\n");
            return -1;
        }
        char *config = argv[(*cmdStartIndex) + 1];
        if (config[0] >= '0' && config[0] <= '3')
        {
            data[1] = config[0] - '0';
        }
        else
        {
            printf("Error en el formato de la configuracion. Debe ser 0,1,2 o 3\n");
            return -1;
        }
        *datalen = 2;
        *cmdStartIndex += 2;
    }
    else if (strcmp(argv[(*cmdStartIndex)], "set-config") == 0)
    {
        cmd = SET_CONFIG_NO;
        data[0] = SET_CONFIG_NO;
        if (argc <= (*cmdStartIndex) + 1)
        {
            printf("Falta configuracion\n");
            return -1;
        }
        char *config = argv[(*cmdStartIndex) + 1];
        if (config[0] >= '0' && config[0] <= '3')
        {
            data[1] = config[0] - '0';
        }
        else
        {
            printf("Error en el formato de la configuracion. Debe ser 0,1,2 o 3\n");
            return -1;
        }
        if (argc <= (*cmdStartIndex) + 2)
        {
            printf("Falta configuracion\n");
            return -1;
        }
        char *nval = argv[(*cmdStartIndex) + 2];
        unsigned long ulnval = strtoul(nval, NULL, 10);
        data[2] = sizeof(ulnval);
        *((unsigned long *)(data + 2)) = ulnval;
        *datalen = data[2] + 2;
        *cmdStartIndex += 3;
    }
    else
    {
        printf("Comando invalido\n");
        return -1;
    }

    return cmd;
}


//handle response
int handleResponse(int sockfd,int cmd, uint8_t *readBuffer){
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
            for (int i = 0,nulen = 0; i < nusers; i++)
            {
                recv(sockfd, readBuffer, 1, 0);
                nulen = readBuffer[0];
                recv(sockfd, readBuffer, nulen+1, 0);
                write(STDOUT_FILENO, readBuffer, nulen);
                printf(" %u\n", readBuffer[nulen]);
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
    return 0;
}
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
        int utypeSpecified = 0;
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
                    printf("Error de formato, el formato del parametro de add-user deberia ser user:pass\n");
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
            printf("Error de formato, el formato de add-user deberia ser user:pass con ambos una longitud entre 1 y 255\n");
            return -1;
        }
        data[2] = nulen;
        data[3 + nulen] = nplen;
        if (argc <= (*cmdStartIndex) + 2 || (argv[(*cmdStartIndex) + 2][0] != '0' && argv[(*cmdStartIndex) + 2][0] != '1'))
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
            utypeSpecified = 1;
        }
        //cmd|ulen|username|plen|password
        *datalen = 2 + nulen + 1 + nplen + 1;
        *cmdStartIndex += 2 + (utypeSpecified?1:0);
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
            printf("Error de formato, el formato de del-user deberia ser user con longitud entre 1 y 255\n");
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
        if (config[0] >= '0' && config[0] <= '2')
        {
            data[1] = config[0] - '0';
        }
        else
        {
            printf("Error en el formato de la configuracion. Debe ser 0,1 o 2\n");
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
        if (config[0] >= '0' && config[0] <= '2')
        {
            data[1] = config[0] - '0';
        }
        else
        {
            printf("Error en el formato de la configuracion. Debe ser 0,1 o 2\n");
            return -1;
        }
        if (argc <= (*cmdStartIndex) + 2)
        {
            printf("Falta configuracion\n");
            return -1;
        }
        char *nval = argv[(*cmdStartIndex) + 2];
        int vlen = 0;
        for (int i = 0;nval[i]!=0 && i<255; i++,vlen++)
        {
            if(nval[i]>='0' && nval[i]<= '9'){
                data[i+3] = nval[i]-'0';
            }else{
                printf("Error en el formato del valor de configuracion. Debe ser un numero de menos de 255 digitos\n");
                return -1;
            }
        }
        data[2] = vlen;
        *datalen = data[2] + 3;
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
            return -1;
        }else if (readBuffer[1] == 0x03)
        {
            printf("Tipo de usuario invalido\n");
            return -1;
        }
        else if(readBuffer[1]== 0x07){
            printf("Cantidad de usuarios llena\n");
            return -1;
        }else if (readBuffer[1] == 0x01)
        {
            printf("Comando invalido\n");
            return -1;
        }
        else if (readBuffer[1] == 0xFF)
        {
            printf("Fallo general del servidor\n");
            return -1;
        }else{
            printf("Error inesperado al crear el usuario\n");
            return -1;
        }
        break;
    case DEL_USER_NO:
        if (readBuffer[1] == 0)
        {
            printf("usuario borrado\n");
        }else if (readBuffer[1] == 0x01)
        {
            printf("Comando invalido\n");
            return -1;
        }
        else if (readBuffer[1] == 0xFF)
        {
            printf("Fallo general del servidor\n");
            return -1;
        }else{
            printf("Error inesperado al borrar el usuario\n");
            return -1;
        }
        break;
    case LIST_USERS_NO:
        if (readBuffer[1] == 0)
        {   
            recvWrapper(sockfd,readBuffer,1,0);
            unsigned int nuserslen = readBuffer[0];
            if(nuserslen > sizeof(unsigned long)){
                printf("El numero de bytes de respuesta es muy grande para este cliente \n");
                return -1;
            }
            recvWrapper(sockfd, readBuffer, nuserslen, 0);
            unsigned long nusers = 0;
            for (unsigned int  i = 0; i < nuserslen; i++)
            {
                nusers = ((nusers << 8) & 0xFF00) + readBuffer[i];
            }
            printf("usuario    contraseña    tipo\n");
            fflush(stdout);
            for (unsigned int i = 0,nulen = 0,utype=0,plen = 0; i < nusers; i++)
            {
                recvWrapper(sockfd, readBuffer, 2, 0);
                utype = readBuffer[0];
                nulen = readBuffer[1];
                recvWrapper(sockfd, readBuffer, nulen, 0);
                write(STDOUT_FILENO, readBuffer, nulen);
                write(STDOUT_FILENO,"    ",4);
                recvWrapper(sockfd, readBuffer, 1, 0);
                plen = readBuffer[0];
                recvWrapper(sockfd, readBuffer, plen, 0);
                write(STDOUT_FILENO, readBuffer, plen);
                printf("    %d\n", utype);
            }
        }else if (readBuffer[1] == 0x01)
        {
            printf("Comando invalido\n");
            return -1;
        }
        else if (readBuffer[1] == 0xFF)
        {
            printf("Fallo general del servidor\n");
            return -1;
        }else{
            printf("Error inesperado al listar usuarios\n");
            return -1;
        }
        break;
    case GET_METRIC_NO:
        if (readBuffer[1] == 0)
        {
            recvWrapper(sockfd, readBuffer, 2, 0);
            int metric = readBuffer[0];
            int metricLen = readBuffer[1];
            if(readBuffer[1] > 18){
                printf("El numero de bytes de respuesta es muy grande para este cliente \n");
                return -1;
            }
            unsigned long metricVal = 0;
            for (int i = 0; i < metricLen; i++)
            {
                metricVal = (metricVal*10) + readBuffer[i];
            }
            
            switch (metric)
            {
            case 0:
                printf("Conexiones historicas:%lu\n",metricVal);
                break;
            case 1:
                printf("Conexiones concurrentes:%lu\n",metricVal);
                break;
            case 2:
                printf("Transferencia de bytes historica:%lu\n",metricVal);
                break;
            default:
                printf("Metrica desconocida:%lu\n",metricVal);
                break;
            }
        }else if (readBuffer[1] == 0x04)
        {
            printf("Metrica invalida\n");
            return -1;
        }else if (readBuffer[1] == 0x01)
        {
            printf("Comando invalido\n");
            return -1;
        }
        else if (readBuffer[1] == 0xFF)
        {
            printf("Fallo general del servidor\n");
            return -1;
        }else{
            printf("Error inesperado al obtener metricas\n");
            return -1;
        }
        break;
    case GET_CONFIG_NO:
        if (readBuffer[1] == 0)
        {
            recvWrapper(sockfd, readBuffer, 2, 0);
            int config = readBuffer[0];
            int configLen = readBuffer[1];
            if(configLen > 18){
                printf("El numero de bytes de respuesta es muy grande para este cliente \n");
                return -1;
            }
            recvWrapper(sockfd, readBuffer, configLen, 0);
            unsigned long configVal = 0;
            for (int i = 0; i < configLen; i++)
            {
                configVal = (configVal*10) + readBuffer[i];
            }
            
            switch (config)
            {
            case 0:
                printf("Tamaño de buffer de lectura:%lu\n",configVal);
                break;
            case 1:
                printf("Tamaño de buffer de escritura:%lu\n",configVal);
                break;
            case 2:
                printf("Timeout del select:%lu\n",configVal);
                break;
            default:
                printf("Configuracion desconocida:%lu\n",configVal);
                break;
            }
        }else if (readBuffer[1] == 0x05)
        {
            printf("Configuracion invalida\n");
            return -1;
        }else if (readBuffer[1] == 0x01)
        {
            printf("Comando invalido\n");
            return -1;
        }
        else if (readBuffer[1] == 0xFF)
        {
            printf("Fallo general del servidor\n");
            return -1;
        }else{
            printf("Error inesperado al obtener configuracion\n");
            return -1;
        }
        break;
    case SET_CONFIG_NO:
        if (readBuffer[1] == 0)
        {
            printf("Configuracion seteada\n");
        }else{
            if (readBuffer[1] == 0x05)
            {
                printf("Configuracion invalida\n");
                
            }else if (readBuffer[1] == 0x06)
            {
                printf("Valor de configuracion invalido\n");
                
            }else if (readBuffer[1] == 0x01)
            {
                printf("Comando invalido\n");
                
            }
            else if (readBuffer[1] == 0xFF)
            {
                printf("Fallo general del servidor\n");
                
            }else{
                printf("Error inesperado al setear configuracion\n");
                
            }
            recvWrapper(sockfd,readBuffer,2,0);
            unsigned int mlen = readBuffer[1];
            if(mlen>0){
                recvWrapper(sockfd,readBuffer,mlen,0);
                printf("mensaje del servidor:");
                fflush(stdout);
                write(STDOUT_FILENO,readBuffer,mlen);
                printf("\n");
            }
            return -1;
        }
        break;
    default:
        printf("Hubo un problema\n");
        return -1;
        break;
    }
    return 0;
}

void recvWrapper(int sockfd,void *buffer, size_t len, int flags){
    int res = recv(sockfd,buffer,len,flags);
    if(res == 0 && len != 0){
        printf("Cerrando conexion\n");
        close(sockfd);
        exit(-1);
    }else if(res < 0){
        printf("Error en la conexion\n");
        close(sockfd);
        exit(-1);
    }
}
#include "clientUtils.h"

#define MAX_VAL_UINT64  0xFFFFFFFFFFFFFFFF
#define BITS_P_BYTE             8
#define VAL_SIZE_MAX    sizeof(uint64_t)

static uint8_t 
ulong_to_byte_array(uint64_t value, uint8_t * data);
static uint8_t
strint_to_ulong(uint64_t * value, const char * data);
static uint8_t 
print_user_list(int sockfd, uint8_t *readBuffer);
static uint8_t
get_value_from_answer(uint64_t * value, uint8_t * option, int sockfd, uint8_t *readBuffer);
static void
print_string_from_answer(int sockfd, uint8_t *readBuffer);



// Checks for valid arguments position
uint8_t 
valid_args(int argc, char * const *argv){
    for (int i = 1, optEnd = 0, optArg = 0; i < argc; i++) {
        if(!optArg) {
            if(argv[i][0] == '-') {
                if(optEnd) return 0;
                optArg = 1;
            } else optEnd = 1;
        } else optArg = 0;
    }
    return 1;
}

//get next command
int 
get_next_command(int argc, char * const *argv, int * cmdStartIndex, uint8_t * data, int * datalen) {
    int cmd;
    if (strcmp(argv[(*cmdStartIndex)], "+add-user") == 0) {
        cmd = command_add_user;
        data[0] = command_add_user;
        int utypeSpecified = 0;
        if (argc <= (*cmdStartIndex) + 1 || *argv[(*cmdStartIndex) + 1] == '+') {
            printf("\n%s Missing user:pass\n", cError);
            return -1;
        }
        char *nuser = argv[(*cmdStartIndex) + 1];
        int nulen = 0, nplen = 0;
        //ADD USER
        
        for (int i = 0, pass = 0; nuser[i] != 0 && i < MAX_DATA_LEN - 2; i++) {
            if (nuser[i] == ':') {
                if (pass) {
                    printf("\n%s add-user should be user:pass\n", cError);
                    return -1;
                }
                pass = 1;
            } else {
                if (!pass) {
                    nulen++;
                    data[i + 3] = nuser[i];
                } else {
                    nplen++;
                    data[i + 3] = nuser[i];
                }
            }
        }

        if (nulen > 255 || nplen > 255) {
            printf("\n%s User/password cant be longer than 255 chararcters\n", cError);
            return -1;
        }
        data[2] = nulen;
        data[3 + nulen] = nplen;
        if (argc <= (*cmdStartIndex) + 2 || *argv[(*cmdStartIndex) + 2] == '+') {
            data[1] = 0;
        } else {
            uint64_t num;
            if (!strint_to_ulong(&num, argv[(*cmdStartIndex) + 2]) || num > 255) {
                printf("\n%s Value should be a positive number less than 256\n", cError);
                return -1;
            }

            data[1] = (uint8_t) num;
            utypeSpecified = 1;
        }
        //cmd|ulen|username|plen|password
        *datalen = 2 + nulen + 1 + nplen + 1;
        *cmdStartIndex += 2 + utypeSpecified;

    } else if (strcmp(argv[(*cmdStartIndex)], "+del-user") == 0) {

        cmd = command_del_user;
        data[0] = command_del_user;
        int userSpecified = 0;

        *datalen = 2;
        if (!(argc <= (*cmdStartIndex) + 1) && *argv[(*cmdStartIndex) + 1] != '+') {
            char *deluser = argv[(*cmdStartIndex) + 1];    
            for (int i = 0; deluser[i] != 0 && i < MAX_DATA_LEN; i++) {
                data[i + 2] = deluser[i];
                (*datalen)++;
            }
            userSpecified = 1;
        }

        if (*datalen - 2 > 255) {
            printf("\n%s User cant be longer than 255 chararcters\n", cError);
            return -1;
        }
        data[1] = *datalen - 2;
        *cmdStartIndex += 1 + userSpecified;

    } else if (strcmp(argv[(*cmdStartIndex)], "+list-users") == 0) {

        cmd = command_list_user;
        data[0] = command_list_user;
        *datalen = 1;
        *cmdStartIndex += 1;

    } else if (strcmp(argv[(*cmdStartIndex)], "+get-metric") == 0) {

        cmd = command_get_metric;
        data[0] = command_get_metric;
        if (argc <= (*cmdStartIndex) + 1 || *argv[(*cmdStartIndex) + 1] == '+') {
            printf("\n%s Missing metric\n", cError);
            return -1;
        }

        uint64_t num;
        if (!strint_to_ulong(&num, argv[(*cmdStartIndex) + 1]) || num > 255) {
            printf("\n%s Metric should be a positive number less than 256\n", cError);
            return -1;
        }
        data[1] = (uint8_t) num;

        *datalen = 2;
        *cmdStartIndex += 2;

    } else if (strcmp(argv[(*cmdStartIndex)], "+get-config") == 0) {

        cmd = command_get_config;
        data[0] = command_get_config;
        if (argc <= (*cmdStartIndex) + 1 || *argv[(*cmdStartIndex) + 1] == '+') {
            printf("\n%s Missing configuration\n", cError);
            return -1;
        }

        uint64_t num;
        if (!strint_to_ulong(&num, argv[(*cmdStartIndex) + 1]) || num > 255) {
            printf("\n%s Config should be a positive number less than 256\n", cError);
            return -1;
        }
        data[1] = (uint8_t) num;

        *datalen = 2;
        *cmdStartIndex += 2;
    
    } else if (strcmp(argv[(*cmdStartIndex)], "+set-config") == 0) {
        
        cmd = command_set_config;
        data[0] = command_set_config;
        int valueSpecified = 0;
        if (argc <= (*cmdStartIndex) + 1 || *argv[(*cmdStartIndex) + 1] == '+') {
            printf("\n%s Missing configuration\n", cError);
            return -1;
        }
        
        uint64_t num;
        if (!strint_to_ulong(&num, argv[(*cmdStartIndex) + 1]) || num > 255) {
            printf("\n%s Config should be a positive number less than 256\n", cError);
            return -1;
        }
        
        data[1] = (uint8_t) num;

        if (!(argc <= (*cmdStartIndex) + 2) && *argv[(*cmdStartIndex) + 2] != '+') {
            if (!strint_to_ulong(&num, argv[(*cmdStartIndex) + 2])) {
                printf("\n%s Config should be a positive representable number\n", cError);
                return -1;
            }
            valueSpecified = 1;
        }

        data[2] = ulong_to_byte_array(num, data + 3);
        *datalen = data[2] + 3;
        *cmdStartIndex += 2 + valueSpecified;

    } else {
        printf("\n%s Invalid command\n", cError);
        return -1;
    }

    return cmd;
}


//handle response
int 
handle_response(int sockfd, int cmd, uint8_t *readBuffer) {

    

    if (cmd != readBuffer[0]) {
        printf("%s Bad formatted server answer. Not sent command\n", cError); 
        return -2;
    }

    switch (readBuffer[1]) {
        case error_inv_command: printf("%s Invalid command\n", sError); return -1;
        case error_server_fail: printf("%s Server general failure\n", sError); return -1;
    }

    uint64_t value;
    uint8_t option;

    switch (cmd) {
        case command_add_user:
            switch(readBuffer[1]) {
                case error_none: printf("%s User created/updated successfully\n", sOk); break;

                case error_inv_ulen: printf("%s Invalid user length\n", sError); return -1;
                case error_inv_plen: printf("%s Invalid password length\n", sError); return -1;
                case error_inv_utype: printf("%s Invalid user type\n", sError); return -1;
                case error_max_ucount: printf("%s User capacity full\n", sRecError); break;
                default: printf("%s Bad formatted server answer. Invalid received status\n", cError); return -2;
            }
            break;

        case command_del_user:
            switch (readBuffer[1]) {
                case error_none: printf("%s User successfully deleted\n", sOk); break;
                default: printf("%s Bad formatted server answer. Invalid received status\n", cError); return -2;

            }
            break;

        case command_list_user:
            switch (readBuffer[1]) {
                case error_none: 
                    if(!print_user_list(sockfd, readBuffer)) return -1; 
                    break;
                default: printf("%s Bad formatted server answer. Invalid received status\n", cError); return -2;
            }
            break;

        case command_get_metric:
            switch (readBuffer[1]) {
                case error_none: 
                    
                    if (!get_value_from_answer(&value, &option, sockfd, readBuffer)) return -1;
                    switch (option) {
                        case metric_hist_conn: printf("%s Historical connections: %lu\n", sOk, value); break;
                        case metric_conc_conn: printf("%s Concurrent connections: %lu\n", sOk, value); break;
                        case metric_hist_btransf: printf("%s Historical byte transfer: %lu bytes\n", sOk, value); break;
                        default: printf("%s Bad formatted server answer. Invalid received metric\n", cError); return -2;
                    }
                    break;

                case error_inv_metric: printf("%s Invalid metric\n", sError); return -1;
                default: printf("%s Bad formatted server answer. Invalid received status\n", cError); return -2;
            }
            break;

        case command_get_config:
            switch (readBuffer[1]) {
                case error_none:
                    if (!get_value_from_answer(&value, &option, sockfd, readBuffer)) return -1;
                    switch (option) {
                        case config_buff_read_size: printf("%s Read buffer size: %lu bytes\n", sOk, value); break;
                        case config_buff_write_size: printf("%s Write buffer size: %lu bytes\n", sOk, value); break;
                        case config_gen_tout: printf("%s General timeout: %lu s\n", sOk, value); break;
                        case config_con_tout: printf("%s Connection timeout: %lu s\n", sOk, value); break;
                        default: printf("%s Bad formatted server answer. Invalid received configuration\n", cError); return -2; 
                    }
                    break;
                
                case error_inv_config: printf("%s Invalid configuration\n", sError); return -1;
                default: printf("%s Bad formatted server answer. Invalid received status\n", cError); return -2;
            }
            break;

        case command_set_config:
            switch (readBuffer[1]) {
                case error_none: printf("%s Configuracion seteada\n", sOk); break;
                
                case error_inv_value: print_string_from_answer(sockfd, readBuffer); break;
                default: printf("%s Bad formatted server answer. Invalid received status\n", cError); return -2;
            }
            break;
        
        default: printf("%s Error. Big time\n", cError); return -2;
    }
    return 1;
}

void 
recv_wrapper(int sockfd, void *buffer, size_t len, int flags){
    int res = recv(sockfd, buffer, len, flags);
    
    if(res == 0 && len != 0) {
        printf("%s Closing connection\n", cLog);
        close(sockfd);
        exit(-1);
    } else if(res < 0){
        printf("%s Error on connection\n", cError);
        close(sockfd);
        exit(-1);
    }
}

/** Auxiliary functions */

static uint8_t 
ulong_to_byte_array(uint64_t value, uint8_t * data) {
    uint8_t zeros = 1;
    uint8_t aux, len = 0;
    for (int8_t i = VAL_SIZE_MAX * (BITS_P_BYTE - 1); i >= 0; i -= BITS_P_BYTE ) {
        aux = value >> i;
        if (zeros) {
            if (aux != 0) {
                zeros = 0;
                data[len++] = aux;
            }
        } else data[len++] = aux;
    }
   return len;
}


static uint8_t
strint_to_ulong(uint64_t * value, const char * data) {
    *value = 0;
    for (int i = 0; data[i] != 0; i++) {
        if(*value < (MAX_VAL_UINT64 / 10) && data[i] >= '0' && data[i] <= '9')
            *value = *value * 10 + data[i] - '0';
        else return 0;
    }
    return 1;
}

static uint8_t 
print_user_list(int sockfd, uint8_t *readBuffer) {
    recv_wrapper(sockfd, readBuffer, 1,0);
    uint64_t nuserslen = readBuffer[0];
    if(nuserslen > MAX_VAL_BYTES) {
        printf("%s Error. Answer length too big\n", cError);
        return 0;
    }
    recv_wrapper(sockfd, readBuffer, nuserslen, 0);
    unsigned long nusers = 0;
    for (unsigned int  i = 0; i < nuserslen; i++)
        nusers = ((nusers << 8) & 0xFF00) + readBuffer[i];

    printf("%s\033[1m\tN\tName\tPass\t Type\n\033[0m", sOk);
    for (unsigned int i = 0, nulen = 0, utype=0,plen = 0; i < nusers; i++) {
        recv_wrapper(sockfd, readBuffer, 2, 0);
        utype = readBuffer[0];
        nulen = readBuffer[1];
        recv_wrapper(sockfd, readBuffer, nulen, 0);
        printf("\t\t%d\t%*.*s\t", i+1, nulen, nulen, readBuffer);
        recv_wrapper(sockfd, readBuffer, 1, 0);
        plen = readBuffer[0];
        recv_wrapper(sockfd, readBuffer, plen, 0);
        printf("%*.*s\t", plen, plen, readBuffer);
        printf("%s\n", (utype == 0)? "client" : "admin");
    }
    return 1;
}

static uint8_t
get_value_from_answer(uint64_t * value, uint8_t * option, int sockfd, uint8_t *readBuffer) {
    recv_wrapper(sockfd, readBuffer, 2, 0);
    *option = readBuffer[0];
    uint8_t length = readBuffer[1];
   
    if(length > MAX_VAL_BYTES){
        printf("%s Error. Answer value too big\n", cError);
        return 0;
    }
    if (length != 0) recv_wrapper(sockfd, readBuffer, length, 0);
    
    *value = 0;
    for (int i = 0; i < length; i++) *value = (*value << 8) + readBuffer[i];
    return 1;
}

static void
print_string_from_answer(int sockfd, uint8_t *readBuffer) {
   recv_wrapper(sockfd, readBuffer, 2,0);
    uint8_t mlen = readBuffer[1];
    if(mlen>0){
        recv_wrapper(sockfd,readBuffer,mlen,0);
        printf("%s %*.*s\n", sRecError, mlen, mlen, readBuffer);
    }
}



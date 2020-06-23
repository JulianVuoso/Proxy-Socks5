#include "client/clientUtils.h"

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
    if (strcmp(argv[(*cmdStartIndex)], "add-user") == 0) {
        cmd = ADD_USER_NO;
        int utypeSpecified = 0;
        if (argc <= (*cmdStartIndex) + 1) {
            printf("Error. Missing user:pass\n");
            return -1;
        }
        char *nuser = argv[(*cmdStartIndex) + 1];
        int nulen = 0, nplen = 0;
        //ADD USER
        data[0] = ADD_USER_NO;
        for (int i = 0, pass = 0; nuser[i] != 0 && i < MAX_DATA_LEN - 2; i++) {
            if (nuser[i] == ':') {
                if (pass) {
                    printf("Error. add-user should be user:pass\n");
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
            printf("Error. User/password cant be longer than 255 chararcters\n");
            return -1;
        }
        data[2] = nulen;
        data[3 + nulen] = nplen;
        if (argc <= (*cmdStartIndex) + 2) {
            data[1] = 0;
        } else {
            uint64_t num;
            if (!strint_to_ulong(&num, argv[(*cmdStartIndex) + 2]) || num > 255) {
                printf("Error. Value should be a positive number less than 256\n");
                return -1;
            }

            data[1] = (uint8_t) num;
            utypeSpecified = 1;
        }
        //cmd|ulen|username|plen|password
        *datalen = 2 + nulen + 1 + nplen + 1;
        *cmdStartIndex += 2 + utypeSpecified;

    } else if (strcmp(argv[(*cmdStartIndex)], "del-user") == 0) {

        cmd = DEL_USER_NO;
        data[0] = DEL_USER_NO;
        int userSpecified = 0;

        *datalen = 2;
        if (!(argc <= (*cmdStartIndex) + 1)) {
            char *deluser = argv[(*cmdStartIndex) + 1];    
            for (int i = 0; deluser[i] != 0 && i < MAX_DATA_LEN; i++) {
                data[i + 2] = deluser[i];
                (*datalen)++;
            }
            userSpecified = 1;
        }

        if (*datalen - 2 > 255) {
            printf("Error. User cant be longer than 255 chararcters\n");
            return -1;
        }
        data[1] = *datalen - 2;
        *cmdStartIndex += 1 + userSpecified;

    } else if (strcmp(argv[(*cmdStartIndex)], "list-users") == 0) {

        cmd = LIST_USERS_NO;
        data[0] = LIST_USERS_NO;
        *datalen = 1;
        *cmdStartIndex += 1;

    } else if (strcmp(argv[(*cmdStartIndex)], "get-metric") == 0) {

        cmd = GET_METRIC_NO;
        data[0] = GET_METRIC_NO;
        if (argc <= (*cmdStartIndex) + 1) {
            printf("Error. Missing metric\n");
            return -1;
        }

        uint64_t num;
        if (!strint_to_ulong(&num, argv[(*cmdStartIndex) + 1]) || num > 255) {
            printf("Error. Metric should be a positive number less than 256\n");
            return -1;
        }
        data[1] = (uint8_t) num;

        *datalen = 2;
        *cmdStartIndex += 2;

    } else if (strcmp(argv[(*cmdStartIndex)], "get-config") == 0) {

        cmd = GET_CONFIG_NO;
        data[0] = GET_CONFIG_NO;
        if (argc <= (*cmdStartIndex) + 1) {
            printf("Error. Missing configuration\n");
            return -1;
        }

        uint64_t num;
        if (!strint_to_ulong(&num, argv[(*cmdStartIndex) + 1]) || num > 255) {
            printf("Error. Config should be a positive number less than 256\n");
            return -1;
        }
        data[1] = (uint8_t) num;

        *datalen = 2;
        *cmdStartIndex += 2;
    
    } else if (strcmp(argv[(*cmdStartIndex)], "set-config") == 0) {
        
        cmd = SET_CONFIG_NO;
        data[0] = SET_CONFIG_NO;
        int valueSpecified = 0;
        if (argc <= (*cmdStartIndex) + 1) {
            printf("Error. Missing configuration\n");
            return -1;
        }
        
        uint64_t num;
        if (!strint_to_ulong(&num, argv[(*cmdStartIndex) + 1]) || num > 255) {
            printf("Error. Config should be a positive number less than 256\n");
            return -1;
        }
        data[1] = (uint8_t) num;

        if (!(argc <= (*cmdStartIndex) + 2)) {
            uint64_t num;
            if (!strint_to_ulong(&num, argv[(*cmdStartIndex) + 2])) {
                printf("Error. Config should be a positive representable number\n");
                return -1;
            }
            valueSpecified = 1;
        }

        data[2] = ulong_to_byte_array(num, data + 3);
        *datalen = data[2] + 3;
        *cmdStartIndex += 2 + valueSpecified;

    } else {
        printf("Error. Invalid command\n");
        return -1;
    }

    return cmd;
}


//handle response
int 
handle_response(int sockfd, int cmd, uint8_t *readBuffer) {

    if (cmd != readBuffer[0]) {
        printf("Bad formatted answer. Not sent command\n"); 
        return -1;
    }

    switch (readBuffer[1]) {
        case error_inv_config: printf("Invalid configuration\n"); return -1;
        case error_inv_command: printf("Invalid command\n"); return -1;
        case error_server_fail: printf("Server general failure\n"); return -1;
    }

    uint64_t value;
    uint8_t option;

    switch (cmd) {
        case ADD_USER_NO:
            switch(readBuffer[1]) {
                case error_none: printf("User created/updated successfully\n"); break;

                case error_inv_ulen: printf("Invalid user length\n"); return -1;
                case error_inv_plen: printf("Invalid password length\n"); return -1;
                case error_inv_utype: printf("Invalid user type\n"); return -1;
                case error_max_ucount: printf("User capacity full\n"); return -1;
                default: printf("Bad formatted answer. Invalid received status\n"); return -1;
            }
            break;

        case DEL_USER_NO:
            switch (readBuffer[1]) {
                case error_none: printf("User successfully deleted\n"); break;
                default: printf("Bad formatted answer. Invalid received status\n"); return -1;

            }
            break;

        case LIST_USERS_NO:
            switch (readBuffer[1]) {
                case error_none: 
                    if(!print_user_list(sockfd, readBuffer)) return -1; 
                    break;
                default: printf("Bad formatted answer. Invalid received status\n"); return -1;
            }
            break;

        case GET_METRIC_NO:
            switch (readBuffer[1]) {
                case error_none: 
                    
                    if (!get_value_from_answer(&value, &option, sockfd, readBuffer)) return -1;
                    switch (option) {
                        case metric_hist_conn: printf("Historical connections: %lu\n", value); break;
                        case metric_conc_conn: printf("Concurrent connections: %lu\n", value); break;
                        case metric_hist_btransf: printf("Historical byte transfer: %lu bytes\n", value); break;
                        default: printf("Bad formatted answer. Invalid received metric\n"); return -1;
                    }
                    break;

                case error_inv_metric: printf("Invalid metric\n"); return -1;
                default: printf("Bad formatted answer. Invalid received status\n"); return -1;
            }
            break;

        case GET_CONFIG_NO:
            switch (readBuffer[1]) {
                case error_none:
                    if (!get_value_from_answer(&value, &option, sockfd, readBuffer)) return -1;
                    switch (option) {
                        case config_buff_read_size: printf("Read buffer size: %lu bytes\n", value); break;
                        case config_buff_write_size: printf("Write buffer size: %lu bytes\n", value); break;
                        case config_gen_tout: printf("General timeout: %lu s\n", value); break;
                        case config_con_tout: printf("Connection timeout: %lu s\n", value); break;
                        default: printf("Bad formatted answer. Invalid received configuration\n"); return -1; 
                    }
                    break;
                
                case error_inv_config: printf("Invalid configuration\n"); return -1;
                default: printf("Bad formatted answer. Invalid received status\n"); return -1;
            }
            break;

        case SET_CONFIG_NO:
            switch (readBuffer[1]) {
                case error_none: printf("Configuracion seteada\n"); break;
                
                case error_inv_value: print_string_from_answer(sockfd, readBuffer); break;
                default: printf("Bad formatted answer. Invalid received status\n"); return -1;
            }
            break;
        
        default: printf("Error. Big time\n"); return -1;
    }
    return 0;
}

void 
recv_wrapper(int sockfd, void *buffer, size_t len, int flags){
    int res = recv(sockfd, buffer, len, flags);
    
    if(res == 0 && len != 0) {
        printf("Closing connection\n");
        close(sockfd);
        exit(-1);
    } else if(res < 0){
        printf("Error on connection\n");
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
        printf("Error. Answer length too big\n");
        return 0;
    }
    recv_wrapper(sockfd, readBuffer, nuserslen, 0);
    unsigned long nusers = 0;
    for (unsigned int  i = 0; i < nuserslen; i++)
        nusers = ((nusers << 8) & 0xFF00) + readBuffer[i];

    printf("N\tame\tPass\t Type\n");
    for (unsigned int i = 0, nulen = 0, utype=0,plen = 0; i < nusers; i++) {
        recv_wrapper(sockfd, readBuffer, 2, 0);
        utype = readBuffer[0];
        nulen = readBuffer[1];
        recv_wrapper(sockfd, readBuffer, nulen, 0);
        printf("%d\t%*.*s\t", i+1, nulen, nulen, readBuffer);
        recv_wrapper(sockfd, readBuffer, 1, 0);
        plen = readBuffer[0];
        recv_wrapper(sockfd, readBuffer, plen, 0);
        printf("%*.*s\t", plen, plen, readBuffer);
        printf("%s\n", (utype == 0)? "cliente" : "admin");
    }
    return 1;
}

static uint8_t
get_value_from_answer(uint64_t * value, uint8_t * option, int sockfd, uint8_t *readBuffer) {
    recv_wrapper(sockfd, readBuffer, 2, 0);
    *option = readBuffer[0];
    uint8_t length = readBuffer[1];
   
    if(length > MAX_VAL_BYTES){
        printf("Error. Answer value too big\n");
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
        printf("Server message: ");
        printf("%*.*s\n", mlen, mlen, readBuffer);
    }
}
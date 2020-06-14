#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "users.h"

#define MAX_LINE_LENGTH     514     // UNAME (255) + : + PASS (255) + : + n + \0

/** TODO: PROBLEMA --> fopen, fgets, fclose --> BLOQUEANTES  */
/** TODO: AGREGAR VALIDACION DE ERRORES */

static int init_users_list();
static int add_user_to_list(uint8_t * user, uint8_t * pwd, user_level lvl);
static void print_users();

static struct UserList * ulist;

void read_users_file(char * filename){

    init_users_list();

    fprintf(stdout, "Opening **%s**\n", filename);   // ** will help checking for the presence of white spaces.
    int fd = open(filename, O_NONBLOCK);
    if (fd < 0) {
        return;
    }
    FILE *file = fdopen(fd, "r");

    uint8_t * user, * pass, * token;
    char line[MAX_LINE_LENGTH];
    int i = 0, level;
    while(fgets(line, sizeof(line), file) != NULL)
    {
        token = (uint8_t *)strtok(line, ":");    
        while(token)
        {
            switch (i)
            {
                case 0: user = malloc(sizeof(token));
                        strcpy((char *)user, (char *)token); 
                        i++; 
                        break;
                case 1: pass = malloc(sizeof(token));
                        strcpy((char *)pass, (char *)token); 
                        i++; 
                        break;
                case 2: level = atoi((char *)token); 
                        add_user_to_list(user, pass, level);
                        i = 0; 
                        break;
                default: break;
            }
            token = (uint8_t *)strtok(NULL, ":");
        }
    }

    print_users();

    fclose(file);
    return;
}

static int init_users_list(){
    ulist = (struct UserList *) malloc(sizeof(struct UserList));
    if(ulist == NULL) return 0;       /** TODO: como resolver error, same para todo el manejo de la lista */
    ulist->header = NULL; 
    ulist->tail = NULL;
    return 1;
}

static int add_user_to_list(uint8_t * user, uint8_t * pwd, user_level lvl){

    struct UserNode * node = (struct UserNode *) malloc(sizeof(struct UserNode));
    node->user.username = user;
    node->user.password = pwd;
    node->user.level = lvl;
    node->next = NULL;

    if(ulist->header == NULL){
        ulist->header = node;
        ulist->tail = node;
        return 1;
    }

    ulist->tail->next = node;
    ulist->tail = node; 
    return 1;
}

static void print_users(){
    struct UserNode * node = ulist->header;
    while(node != NULL){
        printf("User: %s\t Pass: %s\t Level: %d\n", node->user.username, node->user.password, node->user.level);
        node = node->next;
    }
}

void free_users_list() {
    if (ulist == NULL) {
        return;
    }
    struct UserNode * node = ulist->header;
    struct UserNode * aux;
    while (node != NULL) {
        aux = node;
        node = node->next;
        free(aux->user.username);
        free(aux->user.password);
        free(aux);
    }
    free(ulist);
}

uint8_t authenticate(uint8_t * user, uint8_t * pwd){
    struct UserNode * node = ulist->header;
    while (node != NULL){
        //printf("\n%s - %s y %s - %s\n", (char*)node->user.username, (char*)user, (char*)node->user.password, (char*)pwd);
        if(strcmp((char*)node->user.username, (char*)user)==0 && strcmp((char*)node->user.password, (char*)pwd)==0){
            return NEGOT_RESPONSE_SUCCESS;
        }
        node = node->next;
    }
    return NEGOT_RESPONSE_ERROR;    
}
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "users.h"

#define MAX_LINE_LENGTH     514     // UNAME (255) + : + PASS (255) + : + n + \0
#define FILE_SEPARATOR ":"

/** TODO: PROBLEMA --> fopen, fgets, fclose --> BLOQUEANTES  */

static enum file_errors init_users_list();
// static enum file_errors add_user_to_list(uint8_t * user, uint8_t * pwd, user_level lvl);
// static void delete_user_from_list(uint8_t * user);
static void print_users();
static struct UserNode * search_user(uint8_t * user, uint8_t * pwd);
static struct UserList * ulist;

enum file_errors read_users_file(char * filename){

    int state = init_users_list();
    if(state > 0) return state;

    fprintf(stdout, "Opening **%s**\n", filename);
    
    int fd = open(filename, O_NONBLOCK);
    if (fd < 0) return opening_file;

    FILE *file = fdopen(fd, "r");
    if(file == NULL) return reading_file;

    uint8_t * user, * pass, * token;
    char line[MAX_LINE_LENGTH];
    int i = 0, level;
    while(fgets(line, sizeof(line), file) != NULL)
    {
        token = (uint8_t *)strtok(line, FILE_SEPARATOR);    
        while(token)
        {
            switch (i)
            {
                case 0: user = malloc(sizeof(token));
                        if (user == NULL) return memory_heap;
                        strcpy((char *)user, (char *)token); 
                        i++; 
                        break;
                case 1: pass = malloc(sizeof(token));
                        if(pass == NULL) return memory_heap;
                        strcpy((char *)pass, (char *)token); 
                        i++; 
                        break;
                case 2: level = atoi((char *)token); 
                        add_user_to_list(user, pass, level);
                        i = 0; 
                        break;
                default: break;
            }
            token = (uint8_t *)strtok(NULL, FILE_SEPARATOR);
        }
    }

    print_users();

    /*************** TESTEO DE USER CONFIG **************/
    
/*  printf("#users: %d\n",ulist->size);
    puts("\n---- cambio pass a peter por parker ----");
    uint8_t * useraux = malloc(sizeof("peter"));        // SIN MANEJO DE ERRORES PORQUE ERA PARA TESTEAR
    uint8_t * passaux = malloc(sizeof("parker"));
    strcpy((char*)useraux, "peter");
    strcpy((char*)passaux, "parker");
    add_user_to_list(useraux, passaux, 0);
    print_users();
    printf("#users: %d\n",list_users()->size);

    puts("\n---- borro a peter ----");
    delete_user_from_list(useraux);
    print_users();
    printf("#users: %d\n",list_users()->size);

    puts("\n---- borro a beto_ ----");
    uint8_t * useraux2 = malloc(sizeof("beto_"));        // SIN MANEJO DE ERRORES PORQUE ERA PARA TESTEAR
    strcpy((char*)useraux2, "beto_");
    delete_user_from_list(useraux2);
    print_users();
    printf("#users: %d\n",list_users()->size);
 */
    
    state = fclose(file);
    if(state != 0) return closing_file;

    return file_no_error;
}

static enum file_errors init_users_list(){
    ulist = (struct UserList *) malloc(sizeof(struct UserList));
    if(ulist == NULL) return memory_heap;       /** TODO: como resolver error, same para todo el manejo de la lista */
    ulist->header = NULL; 
    ulist->tail = NULL;
    ulist->size = 0;
    return file_no_error;
}

enum file_errors add_user_to_list(uint8_t * user, uint8_t * pwd, user_level lvl){
    if(user == NULL || pwd == NULL) return wrong_arg;
    struct UserNode * result = search_user(user, pwd);
    if(result == NULL){
        ulist->size++;
        struct UserNode * node = (struct UserNode *) malloc(sizeof(struct UserNode));
        if(node == NULL) return memory_heap;
        node->user.username = user;
        node->user.password = pwd;
        node->user.level = lvl;
        node->next = NULL;

        if(ulist->header == NULL){
            ulist->header = node;
            ulist->tail = node;
            return file_no_error;
        }

        ulist->tail->next = node;
        ulist->tail = node; 
        return file_no_error;
    }else{
        strcpy((char*)result->user.password, (char*)pwd);
        result->user.level = lvl;
        return file_no_error;
    }
}

void delete_user_from_list(uint8_t * user){
    if(user == NULL) return;
    struct UserNode * node = ulist->header;
    if(strcmp((char*)node->user.username,(char*)user)==0){
        ulist->header = node->next;
        free(node);
        ulist->size--;
        return;
    }    
    while (node->next != NULL){
        if(strcmp((char*)node->next->user.username,(char*)user)==0){
            struct UserNode * aux = node->next;
            node->next = node->next->next;
            ulist->size--;
            free(aux);
            return;
        }
        node = node->next;
    }
    return;
}

struct UserList * list_users(){
    // if(ulist == NULL) return NULL;
    return ulist;
}

static void print_users(){
    struct UserNode * node = ulist->header;
    while(node != NULL){
        printf("User: %s\t Pass: %s\t Level: %d\n", node->user.username, node->user.password, node->user.level);
        node = node->next;
    }
}

void free_users_list() {
    if (ulist == NULL)
        return;
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
    if (user == NULL || pwd == NULL) {
        return NEGOT_RESPONSE_ERROR;
    }
    
    struct UserNode * node = ulist->header;
    while (node != NULL){
        if(strcmp((char*)node->user.username, (char*)user)==0 && strcmp((char*)node->user.password, (char*)pwd)==0)
            return NEGOT_RESPONSE_SUCCESS;
        node = node->next;
    }
    return NEGOT_RESPONSE_ERROR;    
}

static struct UserNode * search_user(uint8_t * user, uint8_t * pwd){
    struct UserNode * node = ulist->header;
    while (node != NULL){
        if(strcmp((char*)node->user.username, (char*)user)==0)
            return node;
        node = node->next;
    }
    return NULL;
}
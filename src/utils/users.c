#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "users.h"

static enum file_errors init_users_list();
static struct UserNode * search_user(uint8_t * user, uint8_t * pwd);
static struct UserList * ulist;

enum file_errors read_users_file(char * filename){

    int state;
    if(ulist == NULL){
        state = init_users_list();
        if(state > 0) return state;
    }

    fprintf(stdout, "Opening **%s**\n", filename);
    
    int fd = open(filename, O_NONBLOCK);
    if (fd < 0) return opening_file;

    FILE *file = fdopen(fd, "r");
    if(file == NULL) {
        close(fd);
        return reading_file;
    }

    uint8_t * user, * pass, * token;
    char line[MAX_LINE_LENGTH];
    int i = 0, level;
    while(fgets(line, sizeof(line), file) != NULL)
    {
        token = (uint8_t *)strtok(line, SEPARATOR);    
        while(token)
        {
            switch (i)
            {
                case 0: user = malloc(sizeof(token));
                        if (user == NULL) {
                            close(fd);
                            return memory_heap;
                        }
                        strcpy((char *)user, (char *)token); 
                        i++; 
                        break;
                case 1: pass = malloc(sizeof(token));
                        if(pass == NULL) {
                            close(fd);
                            return memory_heap;
                        }
                        strcpy((char *)pass, (char *)token); 
                        i++; 
                        break;
                case 2: level = atoi((char *)token);
                        enum file_errors err;
                        if ((err = add_user_to_list(user, pass, level)) != file_no_error) {
                            close(fd);
                            return err;
                        }
                        i = 0; 
                        break;
                default: break;
            }
            token = (uint8_t *)strtok(NULL, SEPARATOR);
        }
    }

    // print_users();

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
    if(ulist == NULL) return memory_heap;
    ulist->header = NULL; 
    ulist->tail = NULL;
    ulist->size = 0;
    return file_no_error;
}

enum file_errors add_user_to_list(uint8_t * user, uint8_t * pwd, user_level lvl){
    if(ulist == NULL) init_users_list();
    
    if(ulist->size == MAX_USERS) return max_users_reached;
    
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
        free(pwd);
        free(user);
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

void print_users(){
    if(ulist == NULL) return;
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

uint8_t authenticate(uint8_t * user, uint8_t * pwd, user_level level){
    if (user == NULL || pwd == NULL) {
        return NEGOT_RESPONSE_ERROR;
    }
    
    struct UserNode * node = ulist->header;
    while (node != NULL){
        if(strcmp((char*)node->user.username, (char*)user)==0 && strcmp((char*)node->user.password, (char*)pwd)==0) {
            if (node->user.level >= level)
                return NEGOT_RESPONSE_SUCCESS;
            else
                return NEGOT_RESPONSE_ERROR;
        }
        node = node->next;
    }
    return NEGOT_RESPONSE_ERROR;    
}

static struct UserNode * search_user(uint8_t * user, uint8_t * pwd){
    if(ulist == NULL) return NULL;
    struct UserNode * node = ulist->header;
    while (node != NULL){
        if(strcmp((char*)node->user.username, (char*)user)==0)
            return node;
        node = node->next;
    }
    return NULL;
}

enum file_errors update_users_file(char * filename){

    // fprintf(stdout, "Reopening **%s**\n", filename);

    FILE * file = fopen(filename,"w");
    if(file == NULL) {
        if(fclose(file) != 0)
            return closing_file;
        return writing_file;
    }

    if(ulist == NULL) return file_no_error;
    struct UserNode * node = ulist->header;
    while(node != NULL){
        fprintf(file, "%s:%s:%d\n", node->user.username, node->user.password, node->user.level);
        node = node->next;
    }

    if(fclose(file) != 0) 
        return closing_file;

    return file_no_error;
}

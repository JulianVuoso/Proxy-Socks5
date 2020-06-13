#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "users.h"

void readUsers(){

    initUsers();

    FILE *file;
    char * filename = "users.txt";
    fprintf(stdout, "Opening **%s**\n", filename);   // ** will help checking for the presence of white spaces.
    file = fopen(filename, "r");

    uint8_t * user, * pass, * token;
    char line[100];
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
                        addUser(user, pass, level);
                        i = 0; 
                        break;
                default: break;
            }
            token = (uint8_t *)strtok(NULL, ":");
        }
    }

    printUsers();

    fclose(file);
    return;
}

int initUsers(){
    ulist = (struct UserList *) malloc(sizeof(struct UserList));
    if(ulist == NULL) return 0;       /** TODO: como resolver error, same para todo el manejo de la lista */
    ulist->header = NULL; 
    ulist->tail = NULL;
    return 1;
}

int addUser(uint8_t * user, uint8_t * pwd, user_level lvl){

    struct UserNode * node = (struct UserNode *) malloc(sizeof(struct UserNode));
    node->user.username = malloc(sizeof(user));
    strcpy((char *)node->user.username, (char *)user);
    node->user.password = malloc(sizeof(pwd));
    strcpy((char *)node->user.password, (char *)pwd);    
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

void printUsers(){
    struct UserNode * node = ulist->header;
    while(node != NULL){
        printf("User: %s\t Pass: %s\t Level: %d\n", node->user.username, node->user.password, node->user.level);
        node = node->next;
    }
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
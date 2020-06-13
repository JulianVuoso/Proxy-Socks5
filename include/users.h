#ifndef USERS_H
#define USERS_H

#include <stdint.h>
#include "negotiation.h"

typedef enum user_level {CLIENT, ADMIN} user_level;

struct User{
    uint8_t * username;
    uint8_t * password;
    user_level level;
};

struct UserNode{
    struct User user;
    struct UserNode * next;
};

struct UserList{
    struct UserNode * header;
    struct UserNode * tail;
};

struct UserList * ulist;

int initUsers();

void readUsers();

int addUser(uint8_t * user, uint8_t * pwd, user_level lvl);

void printUsers();

uint8_t authenticate(uint8_t* user, uint8_t * pwd);

#endif
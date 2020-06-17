#ifndef USERS_H
#define USERS_H

#include <stdint.h>
#include "negotiation.h"

typedef enum user_level {CLIENT, ADMIN} user_level;

enum file_errors { file_no_error, opening_file, reading_file, closing_file, memory_heap};

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
    uint32_t size;
};

enum file_errors read_users_file();

uint8_t authenticate(uint8_t* user, uint8_t * pwd);

void free_users_list();

#endif
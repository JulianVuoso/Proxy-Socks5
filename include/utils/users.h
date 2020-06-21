#ifndef USERS_H
#define USERS_H

#include <stdint.h>
#include "negotiation.h"

#define SEPARATOR ":"


/* Possible user typed */
typedef enum user_level {
    user_client = 0x00,
    user_admin = 0x01,

    user_none = 0xFF,
} user_level;

enum file_errors { file_no_error = 0x00, opening_file, reading_file, closing_file, wrong_arg, memory_heap };

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
enum file_errors add_user_to_list(uint8_t * user, uint8_t * pwd, user_level lvl);
void delete_user_from_list(uint8_t * user);
struct UserList * list_users();

uint8_t authenticate(uint8_t* user, uint8_t * pwd, user_level level);

void free_users_list();

void print_users();

#endif
#ifndef USERS_H
#define USERS_H

#include <stdint.h>
#include "negotiation.h"

#define SEPARATOR ":"

typedef enum user_level { CLIENT = 0, ADMIN } user_level;

enum file_errors { file_no_error, opening_file, reading_file, writing_file, closing_file, wrong_arg, memory_heap };

struct User{
    uint8_t * username;
    uint8_t * password;
    enum user_level level;
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

/** users file handling **/
enum file_errors read_users_file(char * filename);
enum file_errors update_users_file(char * filename);

/** users list handling **/
enum file_errors add_user_to_list(uint8_t * user, uint8_t * pwd, user_level lvl);
void delete_user_from_list(uint8_t * user);
struct UserList * list_users();
void free_users_list();

/** check if user belongs to list **/
uint8_t authenticate(uint8_t* user, uint8_t * pwd, user_level level);

/** listing user + pass + level util **/
void print_users();

#endif
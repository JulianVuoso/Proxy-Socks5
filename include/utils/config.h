#ifndef CONFIG_H_19f0b153be5728feffa7b7fa77734dd81693b7bb
#define CONFIG_H_19f0b153be5728feffa7b7fa77734dd81693b7bb

/* Unit: Bytes */
#define INITIAL_BUF_SIZE    32768
#define MAX_BUF_SIZE        524288
#define MIN_BUF_SIZE        2048

/* Unit: Seconds */
#define INIT_GEN_TIMEOUT    1800
#define MAX_GEN_TIMEOUT     3600
#define MIN_GEN_TIMEOUT     60

#define INIT_CON_TIMEOUT    30
#define MAX_CON_TIMEOUT     600
#define MIN_CON_TIMEOUT     5

/* Config getters and setters */
time_t get_timeout_gen();
void set_timeout_gen(time_t time);
time_t get_timeout_con();
void set_timeout_con(time_t time);

#endif
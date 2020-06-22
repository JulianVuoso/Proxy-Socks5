#ifndef CONFIG_H_19f0b153be5728feffa7b7fa77734dd81693b7bb
#define CONFIG_H_19f0b153be5728feffa7b7fa77734dd81693b7bb

/* Unit: Bytes */
#define INITIAL_BUF_SIZE    32768
#define MAX_BUF_SIZE        524288
#define MIN_BUF_SIZE        2048

/* Unit: Seconds */
#define INIT_GEN_TIMEOUT    1800    // 30 minutos
#define MAX_GEN_TIMEOUT     3600    // 60 minutos
#define MIN_GEN_TIMEOUT     300     // 5  minutos

#define INIT_CON_TIMEOUT    30      // 30   segundos
#define MAX_CON_TIMEOUT     240     // 240  segundos
#define MIN_CON_TIMEOUT     5       // 5    segundos

/* Config getters and setters */
time_t get_timeout_gen();
void set_timeout_gen(time_t time);
time_t get_timeout_con();
void set_timeout_con(time_t time);

#endif
#ifndef DOH_SERVER_STRUCT_H_643e42c74b0bac86c0703df3e6acfba59393dc84
#define DOH_SERVER_STRUCT_H_643e42c74b0bac86c0703df3e6acfba59393dc84

struct doh {
    char           *host;
    char           *ip;
    int             ip_family;
    unsigned short  port;
    char           *path;
    char           *query;
};

enum connect_options { doh_ipv4, doh_ipv6, default_function };

void set_doh_info(struct doh info);

#endif
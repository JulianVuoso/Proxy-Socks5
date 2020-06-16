cmake_minimum_required(VERSION 2.8)
include_directories(../include)
add_executable(socks5  main.c
                       users.c
                       hello.c
                       negotiation.c
                       base64.c
                       ettercap.c
                       parser.c
                       parser_utils.c
                       request.c
                       buffer.c
                       selector.c
                       stm.c
                       socks5.c
                       logger.c
                       netutils.c
                       sm_hello_state.c
                       sm_negot_state.c
                       sm_request_state.c
                       sm_copy_state.c
                       sm_before_error_state.c
                       socks5mt.c)
target_link_libraries(socks5 pthread)

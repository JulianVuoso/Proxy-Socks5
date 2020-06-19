cmake_minimum_required(VERSION 2.8)
include_directories(../include)
add_executable(socks5d main.c
                       utils/users.c
                       parsers/hello.c
                       parsers/negotiation.c
                       utils/args.c
                       utils/base64.c
                       parsers/ettercap.c
                       utils/parser.c
                       utils/parser_utils.c
                       parsers/request.c
                       utils/buffer.c
                       utils/selector.c
                       utils/stm.c
                       socks5.c
                       utils/logger.c
                       utils/netutils.c
                       sm/sm_hello_state.c
                       sm/sm_negot_state.c
                       sm/sm_request_state.c
                       sm/sm_copy_state.c
                       doh/dohParser.c
                       doh/dohclient.c
                       sm/sm_before_error_state.c
                       sm/socks5mt.c)
target_link_libraries(socks5d pthread)

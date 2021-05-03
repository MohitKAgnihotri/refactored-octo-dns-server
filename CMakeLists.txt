cmake_minimum_required(VERSION 3.20)
project(DnsServer C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "-g3 -Werror -Wall -Wpedantic")
link_libraries(pthread)

add_executable(DnsServer main.c dns.c helper1.c)
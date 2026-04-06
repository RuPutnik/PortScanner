cmake_minimum_required(VERSION 3.16)

project(TcpHeaderTest)
include(GoogleTest)

add_executable(TcpHeaderTest tcp_header_test.cpp tcp_header_test.h)
target_link_libraries(TcpHeaderTest PRIVATE gtest gmock)
target_link_libraries(TcpHeaderTest PRIVATE ArNet)

gtest_discover_tests(TcpHeaderTest)

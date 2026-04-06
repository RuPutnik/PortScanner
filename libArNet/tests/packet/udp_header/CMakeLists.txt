cmake_minimum_required(VERSION 3.16)

project(UdpHeaderTest)
include(GoogleTest)

add_executable(UdpHeaderTest udp_header_test.cpp udp_header_test.h)
target_link_libraries(UdpHeaderTest PRIVATE gtest gmock)
target_link_libraries(UdpHeaderTest PRIVATE ArNet)

gtest_discover_tests(UdpHeaderTest)

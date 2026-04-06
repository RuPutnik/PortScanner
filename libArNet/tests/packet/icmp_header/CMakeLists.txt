cmake_minimum_required(VERSION 3.16)

project(IcmpHeaderTest)
include(GoogleTest)

add_executable(IcmpHeaderTest icmp_header_test.cpp icmp_header_test.h)
target_link_libraries(IcmpHeaderTest PRIVATE gtest gmock)
target_link_libraries(IcmpHeaderTest PRIVATE ArNet)

gtest_discover_tests(IcmpHeaderTest)

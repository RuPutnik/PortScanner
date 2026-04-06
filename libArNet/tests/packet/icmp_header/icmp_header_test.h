#pragma once

#include <gtest/gtest.h>

#include <vector>

#include <packet/icmp_header.h>
#include <packet/net_packet.h>

class IcmpHeaderTest : public testing::TestWithParam<std::tuple<network::NetPacket,
                                                                std::vector<unsigned char>>>
{};


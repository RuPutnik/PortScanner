#pragma once

#include <gtest/gtest.h>

#include <vector>

#include <packet/udp_header.h>
#include <packet/net_packet.h>

class UdpHeaderTest : public testing::TestWithParam<std::tuple<network::NetPacket,
                                                               std::vector<unsigned char>>>
{};

#pragma once

#include <gtest/gtest.h>

#include <vector>

#include <packet/tcp_header.h>
#include <packet/net_packet.h>

class TcpHeaderTest : public testing::TestWithParam<std::tuple<network::NetPacket,
                                                               std::vector<unsigned char>>>
{};

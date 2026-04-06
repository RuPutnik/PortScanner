#include "tcp_header_test.h"

INSTANTIATE_TEST_SUITE_P(Test_1, TcpHeaderTest, testing::Values(
                                                             std::tuple{
                                                                 []{
                                                                     auto tcpHeader = std::make_shared<network::TcpHeader>("10.0.2.15", "202.181.230.36");
                                                                     tcpHeader->setSrcPort(48000);
                                                                     tcpHeader->setDstPort(80);
                                                                     tcpHeader->setSeqNumber(0);
                                                                     tcpHeader->setFlags(network::TcpHeader::SYN);
                                                                     return network::NetPacket(tcpHeader, "info");
                                                                 }(),
                                                                 std::vector<unsigned char>{0xbb, 0x80, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                                                            0x50, 0x02, 0xff, 0xff, 0x67, 0x46, 0x00, 0x00, 0x69, 0x6e, 0x66, 0x6f, 0x00}
                                                             }));

INSTANTIATE_TEST_SUITE_P(Test_2, TcpHeaderTest, testing::Values(
                                                             std::tuple{
                                                                 []{
                                                                     auto tcpHeader = std::make_shared<network::TcpHeader>("10.0.2.15", "202.181.230.36");
                                                                     tcpHeader->setSrcPort(443);
                                                                     tcpHeader->setDstPort(443);
                                                                     tcpHeader->setSeqNumber(555);
                                                                     tcpHeader->setUrgent(7878);
                                                                     tcpHeader->setFlags(network::TcpHeader::RST | network::TcpHeader::ACK);
                                                                     return network::NetPacket(tcpHeader);
                                                                 }(),
                                                                 std::vector<unsigned char>{0x01, 0xbb, 0x01, 0xbb, 0x00, 0x00, 0x02, 0x2b, 0x00, 0x00,
                                                                                            0x00, 0x00, 0x50, 0x14, 0xff, 0xff, 0xce, 0x80, 0x1e, 0xc6}
                                                             }));

INSTANTIATE_TEST_SUITE_P(Test_3, TcpHeaderTest, testing::Values(
                                                             std::tuple{
                                                                 []{
                                                                     auto tcpHeader = std::make_shared<network::TcpHeader>("10.0.2.15", "202.181.230.36");
                                                                     tcpHeader->setSrcPort(0);
                                                                     tcpHeader->setDstPort(0);
                                                                     tcpHeader->setSeqNumber(0);
                                                                     tcpHeader->setAckNumber(20000);
                                                                     tcpHeader->setWindowSize(228);
                                                                     tcpHeader->setFlags(network::TcpHeader::FIN | network::TcpHeader::URG);
                                                                     return network::NetPacket(tcpHeader);
                                                                 }(),
                                                                 std::vector<unsigned char>{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                                                                            0x4e, 0x20, 0x50, 0x21, 0x00, 0xe4, 0xa3, 0xd6, 0x00, 0x00}
                                                             }));

INSTANTIATE_TEST_SUITE_P(Test_4, TcpHeaderTest, testing::Values(
                                                             std::tuple{
                                                                 []{
                                                                     auto tcpHeader = std::make_shared<network::TcpHeader>("10.0.2.15", "202.181.230.36");
                                                                     tcpHeader->setSrcPort(0);
                                                                     tcpHeader->setDstPort(150);
                                                                     tcpHeader->setSeqNumber(1);
                                                                     tcpHeader->setWindowSize(65535);
                                                                     tcpHeader->setUrgent(65535);
                                                                     tcpHeader->addOption(network::TcpHeader::Options::MSS, {{network::TcpHeader::OptionValue::UINT16, 1460}});
                                                                     tcpHeader->addOption(network::TcpHeader::Options::SACK_Permitted);
                                                                     tcpHeader->addOption(network::TcpHeader::Options::WindowScaling, {{network::TcpHeader::OptionValue::UINT8, 7}});
                                                                     return network::NetPacket(tcpHeader);
                                                                 }(),
                                                                 std::vector<unsigned char>{0x00, 0x00, 0x00, 0x96, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                                                                                            0x00, 0x00, 0x80, 0x00, 0xff, 0xff, 0xab, 0x99, 0xff, 0xff,
                                                                                            0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x01, 0x01, 0x03, 0x03,
                                                                                            0x07, 0x01}
                                                             }));

TEST_P(TcpHeaderTest, TcpHeaderDataTest){
    auto packet = std::get<0>(GetParam());
    const auto pData = packet.getData();
    const auto expectedData = std::get<1>(GetParam());

    ASSERT_EQ(pData, expectedData);
}


int main(int argc, char** argv)
{
    testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
}

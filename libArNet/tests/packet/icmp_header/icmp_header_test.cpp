#include "icmp_header_test.h"

INSTANTIATE_TEST_SUITE_P(IcmpHeaderTest_1, IcmpHeaderTest, testing::Values(
                                                             std::tuple{
                                                                 []{
                                                                     auto icmpHeader1 = std::make_shared<network::IcmpHeader>(network::IcmpHeader::Type::RouteRedirection);
                                                                     icmpHeader1->setIdentifier(0);
                                                                     icmpHeader1->setCode(ICMP_REDIR_NETTOS);
                                                                     return network::NetPacket(icmpHeader1, "www.youtube.com");
                                                                 }(),
                                                                 std::vector<unsigned char>{0x05, 0x02, 0x72, 0x73, 0x00, 0x00, 0x00, 0x00,
                                                                                            0x77, 0x77, 0x77, 0x2e, 0x79, 0x6f, 0x75, 0x74, 0x75, 0x62, 0x65, 0x2e,
                                                                                            0x63, 0x6f, 0x6d, 0x00}
                                                             }));

INSTANTIATE_TEST_SUITE_P(IcmpHeaderTest_2, IcmpHeaderTest, testing::Values(
                                                             std::tuple{
                                                                 []{
                                                                     auto icmpHeader2 = std::make_shared<network::IcmpHeader>(network::IcmpHeader::Type::EchoReply);
                                                                     icmpHeader2->setIdentifier(100);
                                                                     icmpHeader2->setSeqNumber(555);
                                                                     return network::NetPacket(icmpHeader2);
                                                                 }(),
                                                                 std::vector<unsigned char>{0x00, 0x00, 0xfd, 0x70, 0x00, 0x64, 0x02, 0x2b}
                                                             }));


TEST_P(IcmpHeaderTest, IcmpHeaderTest){
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

#include "udp_header_test.h"


INSTANTIATE_TEST_SUITE_P(UdpHeaderTest_1, UdpHeaderTest, testing::Values(
                                                        std::tuple{
                                                            []{
                                                                auto udpHeader1 = std::make_shared<network::UdpHeader>("10.0.2.15", "202.181.230.36");
                                                                udpHeader1->setSrcPort(48000);
                                                                udpHeader1->setDstPort(80);
                                                                return network::NetPacket(udpHeader1, "www.youtube.com");
                                                            }(),
                                                            std::vector<unsigned char>{0xbb, 0x80, 0x00, 0x50, 0x00, 0x00, 0xfe, 0x91, 0x77, 0x77, 0x77, 0x2e,
                                                                                       0x79, 0x6f, 0x75, 0x74, 0x75, 0x62, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00}
                                                        }));

INSTANTIATE_TEST_SUITE_P(UdpHeaderTest_2, UdpHeaderTest, testing::Values(
                                                        std::tuple{
                                                            []{
                                                                auto udpHeader2 = std::make_shared<network::UdpHeader>("10.0.2.15", "202.181.230.36");
                                                                udpHeader2->setSrcPort(48000);
                                                                udpHeader2->setDstPort(80);
                                                                return network::NetPacket(udpHeader2);
                                                            }(),
                                                            std::vector<unsigned char>{0xbb, 0x80, 0x00, 0x50, 0x00, 0x00, 0x87, 0x2c}
                                                        }));


TEST_P(UdpHeaderTest, UdpHeaderTest){
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

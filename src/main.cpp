#include <QApplication>

#include <thread>

#include <packet/tcp_header.h>
#include <packet/udp_header.h>
#include <packet/net_packet.h>
#include <packet/icmp_header.h>
#include <sr.h>

#include "scanner_window.h"

using namespace network;

const std::string sourceIP = network::getCurrentIpAddress();//"10.0.2.15";
//constexpr const char* destIP = "202.181.230.36"; //http://www.hiking.com.hk
const std::string destIP = network::resolveHostname("www.hiking.com.hk").front();
//constexpr const char* destIP = "185.15.59.224"; //ya.ru

class PacketAnalyzer final : public IPacketHandler
{
public:
    void handlePacket(const NetPacket& incomingNetPacket) override
    {
        //incomingNetData.debugHex();

        const auto header = incomingNetPacket.getHeader();

        qDebug() << "Proto ID:  " << header->getProtoId();
        qDebug() << "Proto name:  " << header->getProtoName();
        qDebug() << "Source IP: " << header->getSourceIP();
        qDebug() << "Target IP: " << header->getTargetIP();

        switch (static_cast<PACKET_TYPE>(header->getProtoId())) {
        case PACKET_TYPE::TCP:{
            const auto tcpHeader = std::dynamic_pointer_cast<const TcpHeader>(header);

            qDebug() << "Source Port" << tcpHeader->getSrcPort();
            qDebug() << "Target Port" << tcpHeader->getDstPort();

            qDebug() << "URG" << tcpHeader->isUrg();
            qDebug() << "ACK" << tcpHeader->isAck();
            qDebug() << "PSH" << tcpHeader->isPsh();
            qDebug() << "RST" << tcpHeader->isRst();
            qDebug() << "SYN" << tcpHeader->isSyn();
            qDebug() << "FIN" << tcpHeader->isFin();
            break;
        }
        case PACKET_TYPE::ICMP:{
            const auto icmpHeader = std::dynamic_pointer_cast<const IcmpHeader>(header);

            icmpHeader->debugHex();
            break;
        }
        default:
            qDebug() << "Unknown proto!!";
            break;
        }
    }
};

void rawListener()
{
    qDebug() << "Запущен поток слушателя";

    const auto printerRawData = [](const std::vector<unsigned char>& vec){
        qDebug() << "Получено байт: " << vec.size();
        QString word;

        for(std::size_t i = 0; i < vec.size(); i++){
            word += QString::number(vec[i], 16).rightJustified(2, '0');
            if((i+1) % 4 == 0) {
                qDebug().noquote() << "0x" + word;
                word.clear();
            }
        }
        qDebug() << "\n";
    };

    std::atomic<bool> b = true;
    [[maybe_unused]] uint32_t errCode = network::blockingReadPackets(Socket{PACKET_TYPE::TCP}, new PacketAnalyzer, b);
}

int main(int argc, char** argv)
{
    QApplication a(argc, argv);

    ScannerWindow win;

    win.show();

//   in_addr sourceAddress, targetAddress;
//   if(inet_pton(AF_INET, destIP.data(), &targetAddress.s_addr) < 0){
//       perror("Error format IPv4 address");
//       return errno;
//   }

//   if(inet_pton(AF_INET, sourceIP.data(), &sourceAddress.s_addr) < 0){
//       perror("Error format IPv4 address");
//       return errno;
//   }

//   std::string sourceIpAddress = inet_ntoa(in_addr{sourceAddress});
//   std::string targetIpAddress = inet_ntoa(in_addr{targetAddress});

//    qDebug() << targetAddress.s_addr;
//    qDebug() << sourceIpAddress.data();
//    qDebug() << targetIpAddress.data();

   // if(inet_pton(AF_INET, sourceIP, &sourceAddress.s_addr) < 0){
   //     perror("Error format IPv4 address");
   //     return errno;
   // }
/*
    std::shared_ptr<TcpHeader> tcpHeader = std::make_shared<TcpHeader>(sourceIP, destIP);
    tcpHeader->setSrcPort(0);
    tcpHeader->setDstPort(150);
    tcpHeader->setSeqNumber(1);
    tcpHeader->setWindowSize(65535);
    tcpHeader->setUrgent(65535);
    tcpHeader->addOption(network::TcpHeader::Options::MSS, {{network::TcpHeader::OptionValue::UINT16, 1460}});
    tcpHeader->addOption(network::TcpHeader::Options::SACK_Permitted);
  //  tcpHeader->addOption(TcpHeader::Options::MSS, {{TcpHeader::OptionValue::UINT16, 1460}});
    //tcpHeader->addOption(TcpHeader::Options::SACK_Permitted);
    //tcpHeader->addOption(TcpHeader::Options::Timestamps, {{TcpHeader::OptionValue::UINT32, 1000000}, {TcpHeader::OptionValue::UINT32, 0}});
    tcpHeader->addOption(TcpHeader::Options::WindowScaling, {{TcpHeader::OptionValue::UINT8, 7}});

    qDebug().noquote() << tcpHeader->getOptionsAsText();
    //tcpHeader->debugHex();
    //tcpHeader->debugBin();

    qDebug() << "URG" << tcpHeader->isUrg();
    qDebug() << "ACK" << tcpHeader->isAck();
    qDebug() << "PSH" << tcpHeader->isPsh();
    qDebug() << "RST" << tcpHeader->isRst();
    qDebug() << "SYN" << tcpHeader->isSyn();
    qDebug() << "FIN" << tcpHeader->isFin();

    network::NetPacket tcpPack{tcpHeader, "info"};
    const auto tcpPackData = tcpPack.getData();

    tcpPack.debugHex();

    std::jthread listenThread{&rawListener};

    std::shared_ptr<UdpHeader> udpHead = std::make_shared<UdpHeader>(sourceIP, destIP);
    udpHead->setSrcPort(48000);
    udpHead->setDstPort(80);
    //udpHead->setPayloadBytesLength(0);

    //udpHead->debugHex();

    network::NetPacket udpPack{std::move(udpHead), "www.youtube.com"};

    //udpPack.debugHex();

    std::shared_ptr<IcmpHeader> icmpHeader = std::make_shared<IcmpHeader>(IcmpHeader::Type::RouteRedirection);
    icmpHeader->setIdentifier(0);
    icmpHeader->setCode(ICMP_REDIR_NETTOS);
    network::NetPacket icmpPack{icmpHeader, "www.youtube.com"};
    const auto icmpPackData = icmpPack.getData();

    //icmpPack.debugBin();

    sleep(1);
    qDebug().noquote() << "Подготовка пакета завершена, выполняем отправку...";
    while(true) {
        sleep(3);
        if(!network::sendPacketTo(Socket{PACKET_TYPE::TCP}, tcpPackData, destIP)){
            perror("packet send error:");
        }
       // if(!network::sendPacketTo(Socket{PACKET_TYPE::UDP}, udpPack, destIP)){
       //     perror("packet send error:");
       // }

       // if(!network::sendPacketTo(Socket{PACKET_TYPE::ICMP}, icmpPackData, destIP)){
       //     perror("packet send error:");
       // }
    }


    return 0;
    */

    return a.exec();
}


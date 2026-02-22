#include <QCoreApplication>

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <thread>
#include <iostream>

#include "packet/tcp_header.h"
#include "packet/udp_header.h"
#include "packet/net_packet.h"
#include "packet/icmp_header.h"

#include "sr.h"

using namespace network;

constexpr const char* sourceIP = "10.0.2.15";//"10.0.2.15";
//constexpr const char* destIP = "202.181.230.36";
constexpr const char* destIP = "202.181.230.36"; //http://www.hiking.com.hk
//constexpr const char* destIP = "185.15.59.224"; //ya.ru

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
    [[maybe_unused]] uint32_t errCode = network::blockingReadPackets(Socket{PACKET_TYPE::TCP}, printerRawData, b);
}
/*
void fakeListener()
{
    const int fdListener = socket(AF_INET, SOCK_STREAM, 0);
    if(fdListener < 0){
        perror("Error create stream socket");
        return;
    }

    qDebug() << "Создание Stream Socket успешно выполнено";
    sockaddr_in incomingAddr;
    incomingAddr.sin_family = AF_INET;
    incomingAddr.sin_port = htons(48000);
    incomingAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    memset(incomingAddr.sin_zero, 0, sizeof(incomingAddr.sin_zero));

    if(bind(fdListener, reinterpret_cast<sockaddr*>(&incomingAddr), sizeof(incomingAddr)) < 0)
    {
        perror("bind");
        exit(errno);
    }
    qDebug() << "Bind Stream Socket успешно выполнено";
    if(listen(fdListener, 1000000) < 0){
        perror("listen");
        exit(errno);
    }
    qDebug() << "Listen Stream Socket успешно выполнено";
    socklen_t len;

    while(true)
    {
        const int fdServer = accept(fdListener, 0, 0);
        if(fdServer < 0)
        {
            perror("accept");
            exit(errno);
        }

        qDebug() << "accepted";

        while(true)
        {
            const auto amountBytes = recvfrom(fdListener, buff, sizeMsg, 0, reinterpret_cast<sockaddr*>(&incAddr), &len);
            if(amountBytes <= 0){
                qDebug() << "amountBytes = " << amountBytes;
                break;
            }

            qDebug() << incAddr.sin_addr.s_addr << ":" << incAddr.sin_port;
            qDebug() << "Получено байт: " << amountBytes;

                for(int i = 0; i < amountBytes; i++){
                std::cout << QString::number(buff[i], 16).toStdString();
                std::cout.flush();
                if(i % 4 == 0) {
                    std::cout << "    ";
                }
                std::cout.flush();
            }
            std::cout << "\n";
        }

        usleep(10 * 1000);
    }
}
*/

int main(int argc, char** argv)
{
    std::string currIp = network::getCurrentIpAddress();
    //QCoreApplication a(argc, argv);
//
//    in_addr sourceAddress, targetAddress;
//    if(inet_pton(AF_INET, destIP, &targetAddress.s_addr) < 0){
//        perror("Error format IPv4 address");
//        return errno;
//    }
//
//    if(inet_pton(AF_INET, sourceIP, &sourceAddress.s_addr) < 0){
//        perror("Error format IPv4 address");
//        return errno;
//    }
//
//    TcpHeader tcpHeader{sourceAddress.s_addr, targetAddress.s_addr};
//    tcpHeader.setSrcPort(48000);
//    tcpHeader.setDstPort(80);
//    tcpHeader.setFlags(TcpHeader::SYN);
//    tcpHeader.addOption(TcpHeader::Options::MSS, {{TcpHeader::OptionValue::UINT16, 1460}});
// //   tcpHeader.addOption(TcpHeader::Options::SACK_Permitted);
////    tcpHeader.addOption(TcpHeader::Options::Timestamps, {{TcpHeader::OptionValue::UINT32, 1000000}, {TcpHeader::OptionValue::UINT32, 0}});
////    tcpHeader.addOption(TcpHeader::Options::WindowScaling, {{TcpHeader::OptionValue::UINT8, 7}});
//
//    qDebug().noquote() << tcpHeader.getOptionsAsText();
//    //tcpHeader.debugHex();
//    //tcpHeader.debugBin();
//
//    qDebug() << "URG" << tcpHeader.isUrg();
//    qDebug() << "ACK" << tcpHeader.isAck();
//    qDebug() << "PSH" << tcpHeader.isPsh();
//    qDebug() << "RST" << tcpHeader.isRst();
//    qDebug() << "SYN" << tcpHeader.isSyn();
//    qDebug() << "FIN" << tcpHeader.isFin();
//
//    network::NetPacket<TcpHeader> tcpPack{std::move(tcpHeader)};
//    std::jthread listenThread{&rawListener};
//
//    UdpHeader udpHead{sourceAddress.s_addr, targetAddress.s_addr};
//    udpHead.setSrcPort(48000);
//    udpHead.setDstPort(80);
//    udpHead.setPayloadBytesLength(0);
//
//    //udpHead.debugHex();
//
//    network::NetPacket<UdpHeader> udpPack{std::move(udpHead)};
//
//    //udpPack.debugHex();
//
//    IcmpHeader icmpHeader{IcmpHeader::Type::EchoRequest};
//
//    network::NetPacket<IcmpHeader> icmpPack{std::move(icmpHeader)};
//    icmpPack.setPayload(std::string{"www.youtube.com"});
//
//    icmpPack.debugBin();
//
//    sleep(1);
//    qDebug().noquote() << "Подготовка пакета завершена, выполняем отправку...";
//    while(true) {
//        sleep(3);
//       // if(!network::sendPacketTo(Socket{PACKET_TYPE::TCP}, tcpPack, destIP).first){
//       //     perror("packet send error:");
//       // }
//       // if(!network::sendPacketTo(Socket{PACKET_TYPE::UDP}, udpPack, destIP).first){
//       //     perror("packet send error:");
//       // }
//
//        if(!network::sendPacketTo(Socket{PACKET_TYPE::ICMP}, icmpPack, destIP).first){
//            perror("packet send error:");
//        }
//    }
//
//
//    return 0;//a.exec();
}


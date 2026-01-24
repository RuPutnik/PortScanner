#include <QCoreApplication>

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "packet/tcp_header.h"
#include "packet/tcp_packet.h"

using namespace network;

constexpr const char* destIP = "127.0.0.1";

int main(int argc, char** argv)
{
    //QCoreApplication a(argc, argv);

    const int fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(fd < 0){
        perror("Error create raw socket");
        return errno;
    }

    qDebug() << "Создание Raw Socket успешно выполнено";

    in_addr targetAddress;
    if(inet_pton(AF_INET, destIP, &targetAddress.s_addr) < 0){
        perror("Error format IPv4 address");
        return errno;
    }

    sockaddr_in destAddr{AF_INET, 0, targetAddress, {0}};

    memset(destAddr.sin_zero, 0, sizeof(destAddr.sin_zero));

    TcpHeader tcpHeader{targetAddress.s_addr, targetAddress.s_addr};
    tcpHeader.setSrcPort(33333);
    tcpHeader.setDstPort(44444);
    tcpHeader.setFlags(TcpHeader::SYN);
    tcpHeader.addOption(TcpHeader::Options::MSS, {{TcpHeader::OptionValue::UINT16, 1460}});
    tcpHeader.addOption(TcpHeader::Options::SACK_Permitted);
    tcpHeader.addOption(TcpHeader::Options::Timestamps, {{TcpHeader::OptionValue::UINT32, 1000000}, {TcpHeader::OptionValue::UINT32, 0}});
    tcpHeader.addOption(TcpHeader::Options::WindowScaling, {{TcpHeader::OptionValue::UINT8, 7}});

    qDebug().noquote() << tcpHeader.getOptionsAsText();
    tcpHeader.debugHex();
    tcpHeader.debugBin();

    qDebug() << "URG" << tcpHeader.isUrg();
    qDebug() << "ACK" << tcpHeader.isAck();
    qDebug() << "PSH" << tcpHeader.isPsh();
    qDebug() << "RST" << tcpHeader.isRst();
    qDebug() << "SYN" << tcpHeader.isSyn();
    qDebug() << "FIN" << tcpHeader.isFin();

    network::TcpPacket tcpPack{tcpHeader};
    const auto headerData = tcpPack.getData();
   // const auto headerData = tcpHeader.generateCompleteHeader({}, 0);
    qDebug().noquote() << "Подготовка пакета завершена, выполняем отправку...";
    while(true) {
        sleep(1);
        // Наш TCP пакет пока что будет состоять только из заголовка (возможно, с опциями), без данных
        if (sendto(fd, headerData.get(), tcpPack.getBytesLength(), 0, reinterpret_cast<sockaddr*>(&destAddr), sizeof(destAddr)) < 0)
            perror("packet send error:");
    }


    return 0;//a.exec();
}


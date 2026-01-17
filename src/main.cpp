#include <QCoreApplication>

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "tcp_header.h"

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
        return -1;
    }

    sockaddr_in destAddr{AF_INET, 0, targetAddress};

    memset(destAddr.sin_zero, 0, sizeof(destAddr.sin_zero));

    TcpHeader tcpHeader; //TODO Надо бы по хорошему тогда добавить и класс TcpPacket...
    tcpHeader.setSrcPort(33333);
    tcpHeader.setDstPort(44444);
    tcpHeader.setFlags(TcpHeader::PSH | TcpHeader::RST);
    tcpHeader.resetFlags();
    tcpHeader.debugHex();
    qDebug() << "Flags" << QString::number(tcpHeader.getFlags(), 2).rightJustified(6, '0');
   // tcpHeader.debugBin();

    qDebug() << "URG" << tcpHeader.isUrg();
    qDebug() << "ACK" << tcpHeader.isAck();
    qDebug() << "PSH" << tcpHeader.isPsh();
    qDebug() << "RST" << tcpHeader.isRst();
    qDebug() << "SYN" << tcpHeader.isSyn();
    qDebug() << "FIN" << tcpHeader.isFin();

    qDebug() << "Подготовка пакета завершена, выполняем отправку...";
    const auto headerData = tcpHeader.generateCompleteHeader(targetAddress.s_addr, targetAddress.s_addr, tcpHeader.getHdrLen() * sizeof(uint32_t));

    while(true) {
        sleep(1);
        // Наш TCP пакет пока что будет состоять только из заголовка без опций и данных
        if (sendto(fd, headerData.get(), tcpHeader.length(), 0, reinterpret_cast<sockaddr*>(&destAddr), sizeof(destAddr)) < 0)
            perror("packet send error:");
    }


    return 0;//a.exec();
}


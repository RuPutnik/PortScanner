#include "tcp_header.h"

#include <netinet/in.h>
#include <memory.h>
#include <random>
#include <chrono>

#include <QDebug>


TcpHeader::TcpHeader():
    srcPort{0}, dstPort{0},
    ackNumber{0},
    seqNumber{0},
    hdrLenAndFlags{htons(static_cast<uint16_t>((length() / sizeof(int32_t)) << 12))},
    windowSize{0}, //TODO Убрать в константу htons(64240)
    chksum{0},
    urgent{0}
{}

std::unique_ptr<const char[]> TcpHeader::data() const
{
    char* rawDataHeader = new char[length()];
    memcpy(rawDataHeader, this, length());
    //TODO Все таки похоже нужно заполнять данный массив не тупым копированием памяти данного объекта, т.к память под опции динамична...
   // setChksum(calcCheckSum());
    return std::unique_ptr<const char[]>{rawDataHeader};
}

uint16_t TcpHeader::length() const noexcept
{
    return sizeof(*this);
}

uint16_t TcpHeader::getSrcPort() const noexcept
{
    return ntohs(srcPort);
}

void TcpHeader::setSrcPort(uint16_t newSrcPort) noexcept
{
    srcPort = htons(newSrcPort);
}

uint16_t TcpHeader::getDstPort() const noexcept
{
    return ntohs(dstPort);
}

void TcpHeader::setDstPort(uint16_t newDstPort) noexcept
{
    dstPort = htons(newDstPort);
}

uint32_t TcpHeader::getSeqNumber() const noexcept
{
    return ntohl(seqNumber);
}

void TcpHeader::setSeqNumber(uint32_t newSeqNumber) noexcept
{
    seqNumber = htonl(newSeqNumber);
}

uint32_t TcpHeader::getAckNumber() const noexcept
{
    return ntohl(ackNumber);
}

void TcpHeader::setAckNumber(uint32_t newAckNumber) noexcept
{
    ackNumber = htonl(newAckNumber);
}

uint8_t TcpHeader::getHdrLen() const noexcept
{
    return (ntohs(hdrLenAndFlags) >> 12);
}

void TcpHeader::setHdrLen(uint8_t newHdrLen) noexcept
{
    if(newHdrLen > 0xF) //т.к. больше 4 бит по протоколу нельзя на размер использовать
        return;

    const uint16_t hdrTmp = static_cast<uint16_t>(newHdrLen) << 12;
    uint16_t hdrLenAndFlagsHostEndian = hdrLenAndFlagsHE();
    hdrLenAndFlagsHostEndian = (hdrLenAndFlagsHostEndian & 0x00FF) | hdrTmp;
    hdrLenAndFlags = htons(hdrLenAndFlagsHostEndian);
}

bool TcpHeader::isUrg() const noexcept
{
    return hdrLenAndFlagsHE() & 0x0020;
}

bool TcpHeader::isAck() const noexcept
{
    return hdrLenAndFlagsHE() & 0x0010;
}

bool TcpHeader::isPsh() const noexcept
{
    return hdrLenAndFlagsHE() & 0x0008;
}

bool TcpHeader::isRst() const noexcept
{
    return hdrLenAndFlagsHE() & 0x0004;
}

bool TcpHeader::isSyn() const noexcept
{
    return hdrLenAndFlagsHE() & 0x0002;
}

bool TcpHeader::isFin() const noexcept
{
    return hdrLenAndFlagsHE() & 0x0001;
}

uint8_t TcpHeader::getFlags() const noexcept
{
    return hdrLenAndFlagsHE() & 0x003F; // Получаем значения 6 младших бит
}

void TcpHeader::setFlags(uint8_t flags) noexcept
{
    hdrLenAndFlags = htons((hdrLenAndFlagsHE() & 0xF000) | flags);
}

void TcpHeader::resetFlags() noexcept
{
    setFlags(0);
}

uint16_t TcpHeader::getWindowSize() const noexcept
{
    return ntohs(windowSize);
}

void TcpHeader::setWindowSize(uint16_t newWindowSize) noexcept
{
    windowSize = htons(newWindowSize);
}

uint16_t TcpHeader::getChksum() const noexcept
{
    return ntohs(chksum);
}

void TcpHeader::setChksum(uint16_t newChksum) noexcept
{
    chksum = newChksum; //TODO Разобраться почему тут не нужно использовать htons
}

uint16_t TcpHeader::getUrgent() const noexcept
{
    return ntohs(urgent);
}

void TcpHeader::setUrgent(uint16_t newUrgent) noexcept
{
    urgent = htons(newUrgent);
}

void TcpHeader::debugHex() const
{
    qDebug().noquote() << "-TCP--HDR-"; //TODO Доделать
    qDebug().noquote() << "0x" + QString::number(getSrcPort(), 16).rightJustified(4, '0') + QString::number(getDstPort(), 16).rightJustified(4, '0');
    qDebug().noquote() << "0x" + QString::number(getSeqNumber(), 16).rightJustified(8, '0');
    qDebug().noquote() << "0x" + QString::number(getAckNumber(), 16).rightJustified(8, '0');
    qDebug().noquote() << "0x" + QString::number(hdrLenAndFlagsHE(), 16).rightJustified(4, '0') + QString::number(getWindowSize(), 16).rightJustified(4, '0');
    qDebug().noquote() << "0x" + QString::number(getChksum(), 16).rightJustified(4, '0') + QString::number(getUrgent(), 16).rightJustified(4, '0');
    qDebug().noquote() << "----------";
}

void TcpHeader::debugBin() const
{
    qDebug().noquote() << "----------"; //TODO Доделать
    qDebug().noquote() << "0b" + QString::number(getSrcPort(), 2).rightJustified(16, '0') + QString::number(getDstPort(), 2).rightJustified(16, '0');
    qDebug().noquote() << "0b" + QString::number(getSeqNumber(), 2).rightJustified(32, '0');
    qDebug().noquote() << "0b" + QString::number(getAckNumber(), 2).rightJustified(32, '0');
    qDebug().noquote() << "0b" + QString::number(hdrLenAndFlagsHE(), 2).rightJustified(16, '0') + QString::number(getWindowSize(), 2).rightJustified(16, '0');
    qDebug().noquote() << "0b" + QString::number(getChksum(), 2).rightJustified(16, '0') + QString::number(getUrgent(), 2).rightJustified(16, '0');
    qDebug().noquote() << "----------";
}

uint16_t TcpHeader::calcCheckSum(uint32_t srcIp, uint32_t dstIp, uint16_t lenTcp) const
{
    const PseudoTcpHeader pseudoHeader{srcIp, dstIp, lenTcp};

    const int szPsdTcpHdr = sizeof(PseudoTcpHeader) / 2;

    uint16_t buffDataPackets[szPsdTcpHdr + (lenTcp / 2)]; //Здесь будут храниться псевдозаголовок TCP и настоящий заголовок TCP, а так же по идее должны опции и данные

    memcpy(buffDataPackets, &pseudoHeader, sizeof(PseudoTcpHeader));

    std::swap(buffDataPackets[0], buffDataPackets[1]); //TODO Разобраться почему. М.б. нужно работать лучше с массивом char...
    std::swap(buffDataPackets[2], buffDataPackets[3]);

    memcpy(static_cast<void*>(buffDataPackets) + sizeof(PseudoTcpHeader), this, lenTcp); //Преобразуем к void* т.к. нам нужно сместиться на размер PseudoTcpHeader в байтах

    return calcCheckSum_(buffDataPackets, sizeof(buffDataPackets));
}

uint16_t TcpHeader::calcCheckSum_(uint16_t* buff, uint16_t buffByteSize) const
{
    // Compute Internet Checksum for "buffSize" bytes
    // beginning at location "buff".

    int32_t sum = 0;

    while(buffByteSize > 1)  {
        // This is the inner loop
        sum += *(buff++);
        buffByteSize -= 2;
    }

    // Add left-over byte, if any
    if(buffByteSize > 0){
        sum += * (unsigned char *) buff;
    }

    // Fold 32-bit sum to 16 bits
    while(sum >> 16){
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return static_cast<uint16_t>(~sum);
}

void TcpHeader::updateChkSum(uint32_t srcIp, uint32_t dstIp, uint16_t lenTcp)
{
    setChksum(calcCheckSum(srcIp, dstIp, lenTcp));
}

uint16_t TcpHeader::hdrLenAndFlagsHE() const noexcept
{
    return ntohs(hdrLenAndFlags);
}

uint32_t TcpHeader::generateRandomNumber() const
{
    const auto time_since_epoch = std::chrono::high_resolution_clock::now().time_since_epoch();
    std::mt19937 engine;
    engine.seed(time_since_epoch.count());
    std::uniform_int_distribution<uint32_t> dist{1};
    return dist(engine);
}

TcpHeader::PseudoTcpHeader::PseudoTcpHeader(uint32_t ipSource, uint32_t ipDestination, uint16_t tcpPacketLengthBytes):
    srcIp{ipSource}, dstIp{ipDestination},
    protoId{htons(6)}, tcpByteLen{htons(tcpPacketLengthBytes)}
{}
//TODO Создать нормальный проект с сабмодулями и санитайзерами

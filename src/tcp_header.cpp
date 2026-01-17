#include "tcp_header.h"

#include <QDebug>

#include <netinet/in.h>
#include <memory.h>
#include <random>
#include <chrono>

TcpHeader::TcpHeader()
  /*  srcPort{0}, dstPort{0},
    seqNumber{0},
    ackNumber{0},
    hdrLenAndFlags{htons(static_cast<uint16_t>((length() / sizeof(int32_t)) << 12))},
    windowSize{0},//defaultWindowSize},
    chksum{0},
    urgent{0}*/
{
    setSeqNumber(generateRandomNumber());
    setWindowSize(defaultWindowSize);
    setHdrLen(static_cast<uint8_t>(length() / sizeof(int32_t)));
}

std::unique_ptr<const char[]> TcpHeader::generateCompleteHeader(uint32_t srcIp, uint32_t dstIp, uint16_t lenTcp)
{    
    char* const rawDataHeader = new char[length()];

    updateChkSum(srcIp, dstIp, lenTcp);

    memcpy(rawDataHeader, tcpHeaderFormat.getInternalBuffer(), length());

    return std::unique_ptr<const char[]>{rawDataHeader};
}

uint16_t TcpHeader::length() const noexcept
{
    return static_cast<uint16_t>(tcpHeaderFormat.getLength());
}

uint16_t TcpHeader::getSrcPort() const
{
    return tcpHeaderFormat.readFieldValue<uint16_t>("srcPort");
}

void TcpHeader::setSrcPort(uint16_t newSrcPort)
{
    tcpHeaderFormat.setFieldValue("srcPort", newSrcPort);
}

uint16_t TcpHeader::getDstPort() const
{
    return tcpHeaderFormat.readFieldValue<uint16_t>("dstPort");
}

void TcpHeader::setDstPort(uint16_t newDstPort)
{
    tcpHeaderFormat.setFieldValue("dstPort", newDstPort);
}

uint32_t TcpHeader::getSeqNumber() const
{
    return tcpHeaderFormat.readFieldValue<uint32_t>("seqNumber");
}

void TcpHeader::setSeqNumber(uint32_t newSeqNumber)
{
    tcpHeaderFormat.setFieldValue("seqNumber", newSeqNumber);
}

uint32_t TcpHeader::getAckNumber() const
{
    return tcpHeaderFormat.readFieldValue<uint32_t>("ackNumber");
}

void TcpHeader::setAckNumber(uint32_t newAckNumber)
{
    tcpHeaderFormat.setFieldValue("ackNumber", newAckNumber);
}

uint8_t TcpHeader::getHdrLen() const
{
    return tcpHeaderFormat.readFieldValue<uint8_t>("headerLength");
}

void TcpHeader::setHdrLen(uint8_t newHdrLen)
{
    if(newHdrLen > 0xF) //т.к. больше 4 бит по протоколу нельзя на размер использовать
        return;

    tcpHeaderFormat.setFieldValue("headerLength", newHdrLen);
}

bool TcpHeader::isUrg() const
{
    return tcpHeaderFormat.readFieldValue<bool>("urg");
}

bool TcpHeader::isAck() const
{
    return tcpHeaderFormat.readFieldValue<bool>("ack");
}

bool TcpHeader::isPsh() const
{
    return tcpHeaderFormat.readFieldValue<bool>("psh");
}

bool TcpHeader::isRst() const
{
    return tcpHeaderFormat.readFieldValue<bool>("rst");
}

bool TcpHeader::isSyn() const
{
    return tcpHeaderFormat.readFieldValue<bool>("syn");
}

bool TcpHeader::isFin() const
{
    return tcpHeaderFormat.readFieldValue<bool>("fin");
}

uint8_t TcpHeader::getFlags() const
{
    return tcpHeaderFormat.readGhostFieldValue<uint8_t>(106, 6); //Флаги начинаются со 106 бита
}

void TcpHeader::setFlags(uint8_t flags)
{
    tcpHeaderFormat.setGhostFieldValue(106, 6, flags);
}

void TcpHeader::resetFlags()
{
    setFlags(0);
}

uint16_t TcpHeader::getWindowSize() const
{
    return tcpHeaderFormat.readFieldValue<uint16_t>("windowSize");
}

void TcpHeader::setWindowSize(uint16_t newWindowSize)
{
    tcpHeaderFormat.setFieldValue("windowSize", newWindowSize);
}

uint16_t TcpHeader::getChksum() const
{
    return tcpHeaderFormat.readFieldValue<uint16_t>("chksum");
}

void TcpHeader::setChksum(uint16_t newChksum)
{
    tcpHeaderFormat.setFieldValue("chksum", newChksum); //TODO Разобраться почему тут не нужно использовать htons
}

uint16_t TcpHeader::getUrgent() const
{
    return tcpHeaderFormat.readFieldValue<uint16_t>("urgent");
}

void TcpHeader::setUrgent(uint16_t newUrgent)
{
    tcpHeaderFormat.setFieldValue("urgent", newUrgent);
}

void TcpHeader::debugHex() const
{
    qDebug().noquote() << tcpHeaderFormat.getDataVisualization(1, 4);
  /*  qDebug().noquote() << "-TCP--HDR-"; //TODO Доделать
    qDebug().noquote() << "0x" + QString::number(getSrcPort(), 16).rightJustified(4, '0') + QString::number(getDstPort(), 16).rightJustified(4, '0');
    qDebug().noquote() << "0x" + QString::number(getSeqNumber(), 16).rightJustified(8, '0');
    qDebug().noquote() << "0x" + QString::number(getAckNumber(), 16).rightJustified(8, '0');
    qDebug().noquote() << "0x" + QString::number(hdrLenAndFlagsHE(), 16).rightJustified(4, '0') + QString::number(getWindowSize(), 16).rightJustified(4, '0');
    qDebug().noquote() << "0x" + QString::number(getChksum(), 16).rightJustified(4, '0') + QString::number(getUrgent(), 16).rightJustified(4, '0');
    qDebug().noquote() << "----------";*/
}

void TcpHeader::debugBin() const
{
    //qDebug().noquote() << tcpHeaderFormat.getDataVisualization(1, 4, kivk_lib::Protocol::BASE::BIN);
   /* qDebug().noquote() << "----------"; //TODO Доделать
    qDebug().noquote() << "0b" + QString::number(getSrcPort(), 2).rightJustified(16, '0') + QString::number(getDstPort(), 2).rightJustified(16, '0');
    qDebug().noquote() << "0b" + QString::number(getSeqNumber(), 2).rightJustified(32, '0');
    qDebug().noquote() << "0b" + QString::number(getAckNumber(), 2).rightJustified(32, '0');
    qDebug().noquote() << "0b" + QString::number(hdrLenAndFlagsHE(), 2).rightJustified(16, '0') + QString::number(getWindowSize(), 2).rightJustified(16, '0');
    qDebug().noquote() << "0b" + QString::number(getChksum(), 2).rightJustified(16, '0') + QString::number(getUrgent(), 2).rightJustified(16, '0');
    qDebug().noquote() << "----------";*/
}

uint16_t TcpHeader::calcCheckSum(uint32_t srcIp, uint32_t dstIp, uint16_t lenTcp) const
{
    const PseudoTcpHeader pseudoHeader{srcIp, dstIp, lenTcp};

    const int szPsdTcpHdr = sizeof(PseudoTcpHeader) / 2;
    const uint16_t lenBuffDataPacket = szPsdTcpHdr + (lenTcp / 2);

    std::unique_ptr<uint16_t[]> buffDataPacket{new uint16_t[lenBuffDataPacket]}; //Здесь будут храниться псевдозаголовок TCP и настоящий заголовок TCP, а так же по идее должны опции и данные

    memcpy(buffDataPacket.get(), &pseudoHeader, sizeof(PseudoTcpHeader));
    memcpy(static_cast<void*>(buffDataPacket.get()) + sizeof(PseudoTcpHeader), tcpHeaderFormat.getInternalBuffer(), lenTcp); //Преобразуем к void* т.к. нам нужно сместиться на размер PseudoTcpHeader в байтах

    return htons(calcCheckSum_(buffDataPacket.get(), lenBuffDataPacket * 2));
}

uint16_t TcpHeader::calcCheckSum_(uint16_t* buff, uint16_t buffByteSize) const
{
    // Compute Internet Checksum for "buffSize" bytes
    // beginning at location "buff".

    int32_t sum = 0;

    while(buffByteSize > 1)  {
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

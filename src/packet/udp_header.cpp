#include "udp_header.h"

#include <QDebug>

namespace network {

UdpHeader::UdpHeader():
    IHeader{std::nullopt, {{
        {"srcPort", 16}, {"dstPort", 16},
        {"packetBytesLength", 16}, {"chksum", 16}
    }}}
{}

UdpHeader::UdpHeader(uint32_t sourceIp, uint32_t destinationIp):
    IHeader{std::pair{sourceIp, destinationIp}, {{
        {"srcPort", 16}, {"dstPort", 16},
        {"packetBytesLength", 16}, {"chksum", 16}
    }}}
{}

uint32_t UdpHeader::maxPayloadLengthBytes() const
{
    return network::maxTransportPacketLenBytes - UdpHeader::maxUdpHeaderLenBytes; // = 1472 байта
}

uint16_t UdpHeader::getSrcPort() const
{
    return headerFormat.readFieldValue<uint16_t>("srcPort");
}

void UdpHeader::setSrcPort(uint16_t newSrcPort)
{
    headerFormat.setFieldValue("srcPort", newSrcPort);
}

uint16_t UdpHeader::getDstPort() const
{
    return headerFormat.readFieldValue<uint16_t>("dstPort");
}

void UdpHeader::setDstPort(uint16_t newDstPort)
{
    headerFormat.setFieldValue("dstPort", newDstPort);
}

uint16_t UdpHeader::getPacketBytesLength() const
{
    return headerFormat.readFieldValue<uint16_t>("packetBytesLength");
}

void UdpHeader::setPayloadBytesLength(uint16_t payloadByteslength)
{
    headerFormat.setFieldValue("packetBytesLength", lengthBytes() + payloadByteslength);
}

uint16_t UdpHeader::getChksum() const
{
    return headerFormat.readFieldValue<uint16_t>("chksum");
}

void UdpHeader::setChksum(uint16_t chksum)
{
    headerFormat.setFieldValue("chksum", chksum);
}

void UdpHeader::debugHex() const
{
    qDebug().noquote() << "---UDP-HEADER---";
    qDebug().noquote() << "   SP     DP ";
    qDebug().noquote() << "0x" + QString::number(getSrcPort(), 16).rightJustified(4, '0') + " 0x" + QString::number(getDstPort(), 16).rightJustified(4, '0');
    qDebug().noquote() << "  LEN   CHKS ";
    qDebug().noquote() << "0x" + QString::number(getPacketBytesLength(), 16).rightJustified(4, '0') + " 0x" + QString::number(getChksum(), 16).rightJustified(4, '0');
    qDebug().noquote() << "----------------";
}

void UdpHeader::debugBin() const
{
    qDebug().noquote() << "---------------UDP----HEADER---------------";

    qDebug().noquote() << "    SOURCE PORT         DEST PORT ";
    qDebug().noquote() << "0b" + QString::number(getSrcPort(), 2).rightJustified(16, '0') + " 0b" + QString::number(getDstPort(), 2).rightJustified(16, '0');
    qDebug().noquote() << "    LENGTH PACKET      CHECK SUMM ";
    qDebug().noquote() << "0b" + QString::number(getPacketBytesLength(), 2).rightJustified(16, '0') + " 0b" + QString::number(getChksum(), 2).rightJustified(16, '0');
    qDebug().noquote() << "-------------------------------------------";
}

std::unique_ptr<const char[]> UdpHeader::generateCompleteHeader([[maybe_unused]] const std::shared_ptr<char[]>& payload, [[maybe_unused]] uint32_t payloadLenBytes)
{
    if(ipAdresses.has_value()){
        headerFormat.setFieldValue("chksum", calcCheckSum(payload, payloadLenBytes));
    }

    char* const rawDataHeader = new char[lengthBytes()];

    memcpy(rawDataHeader, headerFormat.getInternalBuffer(), lengthBytes());

    return std::unique_ptr<const char[]>{rawDataHeader};
}

uint16_t UdpHeader::getProtoId() const
{
    return IPPROTO_UDP;
}

}

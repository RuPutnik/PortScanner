#include "ip_header.h"

namespace network {

IpHeader::IpHeader():
    IHeader{{}, {}, {{
        {"version", 4}, {"ihl", 4}, {"dscp", 6}, {"ecn", 2}, {"packetLength", 16},
        {"id", 16}, {"flags", 3}, {"fragmentOffset", 13},
        {"ttl", 8}, {"protocol", 8}, {"chksum", 16},
        {"sourceIP", 32},
        {"targetIP", 32},
    }}}
{}

uint16_t IpHeader::setHeaderData(const std::vector<unsigned char>& dataPacket)
{
    const uint16_t lengthIpHeaderBytes = netWordByteLen * (dataPacket[0] & 0x0F); //Берем только 4 младших бита первого байта

    if(lengthIpHeaderBytes > headerFormat.getLength()){
        headerFormat.appendField({"options", static_cast<uint32_t>(bitSize(lengthIpHeaderBytes - headerFormat.getLength()))});
    }

    headerFormat.setInternalBufferValues(dataPacket.data()); //Копирует только необходимое количество байт (=длине заголовка)

    return lengthIpHeaderBytes;
}

std::unique_ptr<const char[]> IpHeader::generateCompleteHeader([[maybe_unused]] const std::shared_ptr<char[]>& payload, [[maybe_unused]] uint32_t payloadLenBytes)
{
    headerFormat.setFieldValue("chksum", calcCheckSum(nullptr, 0));

    char* const rawDataHeader = new char[lengthBytes()];

    memcpy(rawDataHeader, headerFormat.getInternalBuffer(), lengthBytes());

    return std::unique_ptr<const char[]>{rawDataHeader};
}

uint32_t IpHeader::maxPayloadLengthBytes() const
{
    return maxTransportPacketLenBytes;
}

void IpHeader::debugHex() const
{
    printf("-----IP4-HEADER-----\n");
    printf("Ver IHL  DE   PLen\n");
    printf("0x%01X 0x%01X 0x%02X 0x%04X\n", headerFormat.readFieldValue<uint16_t>("version"), headerFormat.readFieldValue<uint8_t>("ihl"),
                              headerFormat.readFieldValue<uint8_t>("dscp") + headerFormat.readFieldValue<uint8_t>("ecn"),
                              getPacketLength());
    printf("  Id  FLG+FOffset\n");
    printf("0x%04X 0x%04X\n", headerFormat.readFieldValue<uint16_t>("id"),
           headerFormat.readFieldValue<uint8_t>("flags") + headerFormat.readFieldValue<uint8_t>("fragmentOffset"));
    printf("TTL  Prot  CHKS\n");
    printf("0x%02X 0x%02X 0x%04X\n", getTTL(), getProtoId(), headerFormat.readFieldValue<uint16_t>("chksum"));
    printf(" SourceIP \n");
    printf("0x%08X\n", getSourceIP());
    printf(" TargetIP \n");
    printf("0x%08X\n", getTargetIP());
    printf("--------------------\n");
}

void IpHeader::debugBin() const
{
    std::cout << headerFormat.getBinaryVisualization(true, 1, 2, 1, 32, true) << std::endl;
}

uint16_t IpHeader::getProtoId() const
{
    return headerFormat.readFieldValue<uint16_t>("protocol");
}

uint8_t IpHeader::getTTL() const
{
    return headerFormat.readFieldValue<uint8_t>("ttl");
}

uint32_t IpHeader::getSourceIP() const
{
    return headerFormat.readFieldValue<uint32_t>("sourceIP");
}

uint32_t IpHeader::getTargetIP() const
{
    return headerFormat.readFieldValue<uint32_t>("targetIP");
}

uint16_t IpHeader::getHeaderLength() const
{
    return headerFormat.readFieldValue<uint8_t>("ihl") * netWordByteLen;
}

uint16_t IpHeader::getPacketLength() const
{
    return headerFormat.readFieldValue<uint16_t>("packetLength");
}

bool IpHeader::considerPseudoHeaderCalcCksum() const
{
    return false;
}

std::shared_ptr<IHeader> IpHeader::clone()
{
    return std::shared_ptr<IpHeader>(new IpHeader{*this});
}

}

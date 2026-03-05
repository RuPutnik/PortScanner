#include "ip_header.h"

#include  "../tools.h"

namespace network {

IpHeader::IpHeader():
    IHeader{{}, {}, {{
        {"version", 4}, {"ihl", 4}, {"dscp", 6}, {"ecn", 2}, {"packetLength", 16},
        {"id", 16}, {"flags", 3}, {"fragmentOffset", 12},
        {"ttl", 8}, {"protocol", 8}, {"chksum", 16},
        {"sourceIP", 32},
        {"targetIP", 32},
    }}}
{}

uint16_t IpHeader::setHeaderData(const std::vector<unsigned char>& dataPacket)
{
    const uint16_t lengthIpHeaderBytes = wordByteSize * (dataPacket[0] & 0x0F); //Берем только 4 младших бита первого байта

    if(lengthIpHeaderBytes > headerFormat.getLength()){
        headerFormat.appendField({"options", static_cast<uint32_t>(bitSize(lengthIpHeaderBytes - headerFormat.getLength()))});
    }

    headerFormat.setInternalBufferValues(dataPacket.data()); //Копирует только необходимое количество байт (=длине заголовка)

    return lengthIpHeaderBytes;
}

std::unique_ptr<const char[]> IpHeader::generateCompleteHeader(const std::shared_ptr<char[]>& payload, uint32_t payloadLenBytes)
{
    //TODO
}

uint32_t IpHeader::maxPayloadLengthBytes() const
{
    return maxTransportPacketLenBytes;
}

void IpHeader::debugHex() const
{
 //TODO
}

void IpHeader::debugBin() const
{
 //TODO
}

uint16_t IpHeader::getProtoId() const
{
    return headerFormat.readFieldValue<uint16_t>("protocol");
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
    return headerFormat.readFieldValue<uint8_t>("ihl") * wordByteSize;
}

std::shared_ptr<IHeader> IpHeader::clone()
{
    return std::shared_ptr<IpHeader>(new IpHeader{*this});
}

}

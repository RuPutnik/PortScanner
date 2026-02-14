#include "i_header.h"

IHeader::IHeader(const kivk_lib::Protocol& protHeaderFormat):
    headerFormat{protHeaderFormat}
{}

uint16_t IHeader::lengthBytes() const
{
    return static_cast<uint16_t>(headerFormat.getLength());
}

IHeader::PseudoIpHeader::PseudoIpHeader(uint32_t ipSource, uint32_t ipDestination, uint16_t tcpPacketLengthBytes):
    srcIp{ipSource}, dstIp{ipDestination},
    protoId{htons(6)}, tcpByteLen{htons(tcpPacketLengthBytes)}
{}

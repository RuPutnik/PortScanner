#include "icmp_header.h"

namespace network {

IcmpHeader::IcmpHeader(Type type):
    IHeader{std::nullopt, {{
        {"type", 8}, {"code", 8}, {"chksum", 16},
        {"identifier", 16}, {"seqNumber", 16}
    }}}
{
    setType(type);
    setIdentifier(generateRandomNumber<uint16_t>());
}

std::unique_ptr<const char[]> network::IcmpHeader::generateCompleteHeader(const std::shared_ptr<char[]>& payload, uint32_t payloadLenBytes)
{
    headerFormat.setFieldValue("chksum", calcCheckSum(payload, payloadLenBytes));

    char* const rawDataHeader = new char[lengthBytes()];

    memcpy(rawDataHeader, headerFormat.getInternalBuffer(), lengthBytes());

    return std::unique_ptr<const char[]>{rawDataHeader};
}

uint32_t network::IcmpHeader::maxPayloadLengthBytes() const
{
    return network::maxTransportPacketLenBytes - headerFormat.getLength();
}

void network::IcmpHeader::debugHex() const
{
    //TODO
}

void network::IcmpHeader::debugBin() const
{
    //TODO
}

IcmpHeader::Type IcmpHeader::getType() const
{
    return static_cast<Type>(headerFormat.readFieldValue<uint8_t>("type"));
}

void IcmpHeader::setType(Type t)
{
    headerFormat.setFieldValue("type", static_cast<uint8_t>(t));
}

uint8_t IcmpHeader::getCode() const
{
    return headerFormat.readFieldValue<uint8_t>("code");
}

void IcmpHeader::setCode(uint8_t c)
{
    headerFormat.setFieldValue("code", c);
}

uint16_t IcmpHeader::getChksum() const
{
    return headerFormat.readFieldValue<uint16_t>("chksum");
}

void IcmpHeader::setChksum(uint16_t chksum)
{
    headerFormat.setFieldValue("chksum", chksum);
}

uint16_t IcmpHeader::getIdentifier() const
{
    return headerFormat.readFieldValue<uint16_t>("identifier");
}

void IcmpHeader::setIdentifier(uint16_t iden)
{
    headerFormat.setFieldValue("identifier", iden);
}

uint16_t IcmpHeader::getSeqNumber() const
{
    return headerFormat.readFieldValue<uint16_t>("seqNumber");
}

void IcmpHeader::setSeqNumber(uint16_t seqNumber)
{
    headerFormat.setFieldValue("seqNumber", seqNumber);
}

uint16_t IcmpHeader::getProtoId() const
{
    return IPPROTO_ICMP;
}

}



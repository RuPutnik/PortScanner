#ifndef ICMP_HEADER_H
#define ICMP_HEADER_H

#include "i_header.h"

namespace network {

class IcmpHeader final : public IHeader
{
public:
    enum class Type
    {
        Unknown = -1,
        EchoReply = 0,
        UnreachableDestNode = 3,
        SourceSuppression = 4,
        RouteRedirection = 5,
        EchoRequest = 8,
        TimeExceeded = 11,
        ParameterProblem = 12,
        TimestampRequest = 13,
        TimestampReply = 14,
        InfoRequest = 15,
        InfoReply = 16
    };

    IcmpHeader(Type type);

    std::unique_ptr<const char[]> generateCompleteHeader(const std::shared_ptr<char[]>& payload, uint32_t payloadLenBytes) override;
    uint32_t maxPayloadLengthBytes() const override;
    void debugHex() const override;
    void debugBin() const override;

    Type getType() const;
    void setType(Type t);

    uint8_t getCode() const;
    void setCode(uint8_t c);

    uint16_t getChksum() const;
    void setChksum(uint16_t chksum);

    uint16_t getIdentifier() const;
    void setIdentifier(uint16_t iden);

    uint16_t getSeqNumber() const;
    void setSeqNumber(uint16_t seqNumber);

    uint16_t getProtoId() const override;
    std::string getTextCode() const;

    timeval getTimestampLabel();

    uint32_t setHeaderData(const std::vector<unsigned char>& dataPacket) override;
};

}

#endif // ICMP_HEADER_H

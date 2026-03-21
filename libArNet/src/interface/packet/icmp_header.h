#ifndef ICMP_HEADER_H
#define ICMP_HEADER_H

#include <netinet/ip_icmp.h>

#include "i_header.h"

namespace network {

class IcmpHeader final : public IHeader
{
public:
    enum class Type
    {
        Unknown = -1,
        EchoReply = ICMP_ECHOREPLY,
        UnreachableDestNode = ICMP_DEST_UNREACH,
        SourceSuppression = ICMP_SOURCE_QUENCH,
        RouteRedirection = ICMP_REDIRECT,
        EchoRequest = ICMP_ECHO,
        TimeExceeded = ICMP_TIME_EXCEEDED,
        ParameterProblem = ICMP_PARAMETERPROB,
        TimestampRequest = ICMP_TIMESTAMP,
        TimestampReply = ICMP_TIMESTAMPREPLY,
        InfoRequest = ICMP_INFO_REQUEST,
        InfoReply = ICMP_INFO_REPLY
    };

    IcmpHeader(Type type);
    IcmpHeader(const std::string& sourceIp, const std::string& destinationIp, Type type = Type::Unknown);
    IcmpHeader(uint32_t sourceIp, uint32_t destinationIp, Type type = Type::Unknown);

    std::unique_ptr<const char[]> generateCompleteHeader(const std::shared_ptr<char[]>& payload, uint32_t payloadLenBytes) override;
    uint32_t maxPayloadLengthBytes() const override;
    std::shared_ptr<IHeader> clone() override;
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

    uint16_t setHeaderData(const std::vector<unsigned char>& dataPacket) override;

private:
    bool considerPseudoHeaderCalcCksum() const override;

};

}

#endif // ICMP_HEADER_H

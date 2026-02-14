#ifndef I_HEADER_H
#define I_HEADER_H

#include <cstdint>

#include "../tools.h"
#include <protocol.h>
#include <netinet/ip.h>

class IHeader
{
public:
    virtual ~IHeader() = default;

    IHeader(const kivk_lib::Protocol& protHeaderFormat);

    virtual std::unique_ptr<const char[]> generateCompleteHeader(const std::shared_ptr<char[]>& payload, uint32_t tcpPayloadLenBytes) = 0;
    uint16_t lengthBytes() const;
    virtual uint32_t maxPayloadLengthBytes() const = 0;
    virtual void debugHex() const = 0;
    virtual void debugBin() const = 0;

protected:
    struct PseudoIpHeader final
    {
        PseudoIpHeader(uint32_t ipSource, uint32_t ipDestination, uint16_t packetLengthBytes);

        uint32_t srcIp;
        uint32_t dstIp;
        const uint16_t protoId;
        uint16_t tcpByteLen;
    };

    kivk_lib::Protocol headerFormat;

};

#endif // I_HEADER_H

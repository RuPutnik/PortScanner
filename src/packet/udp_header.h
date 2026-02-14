#ifndef UDP_HEADER_H
#define UDP_HEADER_H

#include "i_header.h"

class UdpHeader final : public IHeader
{
public:
    const static inline uint32_t maxUdpHeaderLenBytes = 8;

    UdpHeader();

    std::unique_ptr<const char[]> generateCompleteHeader(const std::shared_ptr<char[]> &payload, uint32_t payloadLenBytes) override;

    uint32_t maxPayloadLengthBytes() const override;

    uint16_t getSrcPort() const;
    void setSrcPort(uint16_t newSrcPort);

    uint16_t getDstPort() const;
    void setDstPort(uint16_t newDstPort);

    uint16_t getPacketBytesLength() const;
    void setPayloadBytesLength(uint16_t payloadByteslength);

    uint16_t getChksum() const;
    void setChksum(uint16_t chksum);

    void debugHex() const override;
    void debugBin() const override;

};

#endif // UDP_HEADER_H

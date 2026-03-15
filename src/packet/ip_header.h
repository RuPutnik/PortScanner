#ifndef IP_HEADER_H
#define IP_HEADER_H

#include "i_header.h"

namespace network {

class IpHeader final : public IHeader
{
public:
    IpHeader();

    uint16_t setHeaderData(const std::vector<unsigned char>& dataPacket) override;
    std::unique_ptr<const char[]> generateCompleteHeader(const std::shared_ptr<char[]> &payload, uint32_t payloadLenBytes) override;
    uint32_t maxPayloadLengthBytes() const override;
    std::shared_ptr<IHeader> clone() override;
    void debugHex() const override;
    void debugBin() const override;
    uint16_t getProtoId() const override;

    uint8_t getTTL() const;
    uint32_t getSourceIP() const;
    uint32_t getTargetIP() const;
    uint16_t getHeaderLength() const;
    uint16_t getPacketLength() const;

private:
    bool considerPseudoHeaderCalcCksum() const override;

};

}

#endif // IP_HEADER_H

#ifndef UDP_HEADER_H
#define UDP_HEADER_H

#include "i_header.h"

namespace network
{

class UdpHeader final : public IHeader
{
public:
    const static inline uint32_t maxUdpHeaderLenBytes = 8;

    UdpHeader();
    UdpHeader(const std::string& sourceIp, const std::string& destinationIp);
    UdpHeader(uint32_t sourceIp, uint32_t destinationIp);

    std::unique_ptr<const char[]> generateCompleteHeader(const std::shared_ptr<char[]> &payload, uint32_t payloadLenBytes) override;
    std::shared_ptr<IHeader> clone() override;
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
    uint16_t getProtoId() const override;

    uint16_t setHeaderData(const std::vector<unsigned char>& dataPacket) override;

private:
    bool considerPseudoHeaderCalcCksum() const override;

};

}

#endif // UDP_HEADER_H

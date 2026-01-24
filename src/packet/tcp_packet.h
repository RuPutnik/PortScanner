#ifndef TCP_PACKET_H
#define TCP_PACKET_H

#include "i_packet.h"
#include "tcp_header.h"

namespace network {

class TcpPacket final : public IPacket
{
public:
    TcpPacket(TcpHeader header_, std::shared_ptr<char[]> payload_, uint32_t amountBytes);
    TcpPacket(TcpHeader header_, const std::string& payload_);
    TcpPacket(TcpHeader header_);

    uint32_t getBytesLength() override;
    std::unique_ptr<const char[]> getData() override;

    void setPayload(const std::shared_ptr<char[]>& newPayload, uint32_t amountBytes);
    void setPayload(const std::string& newPayload);

    void debugHex() const;
    void debugBin() const;

private:
    constexpr static inline uint32_t maxTcpPacketLenBytes = ethernetMTULenBytes - ipHeaderLenBytes;  // = 1480
    constexpr static inline uint32_t maxPayloadLenBytes = maxTcpPacketLenBytes - TcpHeader::maxTcpHeaderLenBytes; // = 1420 байт, 355 слов (4 байта)

    TcpHeader header;
    std::shared_ptr<char[]> payload;
    uint32_t lengthPayload;

    std::shared_ptr<char[]> reverseByteOrder(char *data, uint32_t lenBytes) const;
};

}

#endif // TCP_PACKET_H

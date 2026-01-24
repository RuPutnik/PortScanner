#ifndef TCP_PACKET_H
#define TCP_PACKET_H

#include "i_packet.h"
#include "tcp_header.h"

namespace network {

class TcpPacket final : public IPacket
{
public:
   // TcpPacket();

    uint32_t getBytesLength() override;
    std::unique_ptr<const char[]> getData() override;

private:
    constexpr static inline uint32_t maxTcpPacketLenBytes = ethernetMTULenBytes - ipHeaderLenBytes;  // = 1480
    constexpr static inline uint32_t maxPayloadLenBytes = maxTcpPacketLenBytes - TcpHeader::maxTcpHeaderLenBytes; // = 1420 байт, 355 слов (4 байта)
    TcpHeader header;
    char* data;

};

}

#endif // TCP_PACKET_H

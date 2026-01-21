#ifndef ICMP_PACKET_H
#define ICMP_PACKET_H

#include "i_packet.h"
#include "icmp_header.h"

namespace network {

class IcmpPacket final : public IPacket
{
public:
    IcmpPacket();

    uint32_t getBytesLength() override;
    std::unique_ptr<const char[]> getData() override;
};

}

#endif // ICMP_PACKET_H

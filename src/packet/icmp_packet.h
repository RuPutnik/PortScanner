#ifndef ICMP_PACKET_H
#define ICMP_PACKET_H

#include "i_packet.h"
#include "icmp_header.h"

namespace network {

class IcmpPacket final : public IPacket
{
public:
    IcmpPacket();
};

}

#endif // ICMP_PACKET_H

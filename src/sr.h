#ifndef SR_H
#define SR_H

#include <netinet/in.h>

#include "packet/i_header.h"
#include "packet/net_packet.h"

namespace network {

enum class PACKET_TYPE
{
    ICMP = IPPROTO_ICMP,
    TCP = IPPROTO_TCP
};

template<class H>
ssize_t sendPacketTo(int fileDescriptor, NetPacket<H>, const std::string& ipv4Address)
{

}

}

#endif // SR_H

#ifndef SR_H
#define SR_H

#include <netinet/in.h>

namespace network {

enum class PACKET_TYPE
{
    ICMP = IPPROTO_ICMP,
    TCP = IPPROTO_TCP
};

}

#endif // SR_H

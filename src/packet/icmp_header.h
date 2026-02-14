#ifndef ICMP_HEADER_H
#define ICMP_HEADER_H

#include "i_header.h"

namespace network {

class IcmpHeader final : public IHeader
{
public:
    IcmpHeader();
};

}

#endif // ICMP_HEADER_H

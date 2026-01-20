#ifndef TCP_PACKET_H
#define TCP_PACKET_H

#include "i_packet.h"
#include "tcp_header.h"

//TODO Надо бы по хорошему тогда добавить и класс TcpPacket...

namespace network {

class TcpPacket final : public IPacket
{
public:
   // TcpPacket();

private:
    TcpHeader header;
    char* data;

};

}

#endif // TCP_PACKET_H

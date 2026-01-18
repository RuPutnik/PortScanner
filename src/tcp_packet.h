#ifndef TCP_PACKET_H
#define TCP_PACKET_H

#include "tcp_header.h"

//TODO Надо бы по хорошему тогда добавить и класс TcpPacket...
class TcpPacket
{
public:
   // TcpPacket();

private:
    TcpHeader header;
    std::string data;

};

#endif // TCP_PACKET_H

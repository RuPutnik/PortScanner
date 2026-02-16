#include "sr.h"

#include <sys/socket.h>
#include <string>

namespace network {

Socket::Socket(PACKET_TYPE type)
{
    socketFd = socket(AF_INET, SOCK_RAW, static_cast<int>(type));
    if(socketFd < 0){
        throw std::runtime_error{std::string{"Error create raw socket: "} + std::to_string(errno)};
    }
}

Socket::~Socket()
{
    close(socketFd);
}

int Socket::getSocketFd() const
{
    return socketFd;
}

}

#include "sr.h"

#include <sys/socket.h>
#include <string>
#include <ranges>

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

std::pair<std::vector<unsigned char>, uint32_t> blockingReadPacket(int fileDescriptor, int flags)
{
    sockaddr_in incomingAddr{AF_INET, 0, {htonl(INADDR_ANY)}, {0}};
    memset(incomingAddr.sin_zero, 0, sizeof(incomingAddr.sin_zero));

    if(bind(fileDescriptor, reinterpret_cast<sockaddr*>(&incomingAddr), sizeof(incomingAddr)) < 0)
    {
        return {{}, errno};
    }

    sockaddr_in incAddr;
    constexpr size_t sizeMsg = ETH_DATA_LEN;
    unsigned char buff[sizeMsg];

    sockaddr rawAddr;
    std::vector<unsigned char> dataResult;
    socklen_t addrBytesLen;

    const auto amountBytes = recvfrom(fileDescriptor, buff, sizeMsg, flags, &rawAddr, &addrBytesLen);
    if(amountBytes <= 0){
        return {dataResult, errno};
    }

    memcpy(&incAddr, &rawAddr, sizeof(sockaddr)); //TODO Подумать, что с этим делать

    for(int i = 0; i < amountBytes; i++){
        dataResult.push_back(buff[i]);
    }

    return {dataResult, 0};
}

std::pair<std::vector<unsigned char>, uint32_t> blockingReadPacket(const Socket& socket, int flags)
{
    return blockingReadPacket(socket.getSocketFd(), flags);
}

uint32_t blockingReadPackets(int fileDescriptor, std::vector<unsigned char>& data, bool& conditionFinishRead, int miscrosecInterval, int flags)
{
    const auto sleepMicroseconds = miscrosecInterval < 0 ? 1000 : static_cast<__useconds_t>(miscrosecInterval);

    while(conditionFinishRead)
    {
        const auto[bytes, errCode] = blockingReadPacket(fileDescriptor, flags);

        if(errCode > 0)
            return errCode;

        std::ranges::copy(bytes, std::back_inserter(data));

        usleep(sleepMicroseconds);
    }

    return 0;
}

uint32_t blockingReadPackets(const Socket& socket, std::vector<unsigned char> &data, bool& conditionFinishRead, int miscrosecInterval, int flags)
{
    return blockingReadPackets(socket.getSocketFd(), data, conditionFinishRead, miscrosecInterval, flags);
}

uint32_t blockingReadPackets(int fileDescriptor, const std::function<void (const std::vector<unsigned char> &)>& dataExecutor, bool& conditionFinishRead, int miscrosecInterval, int flags)
{
    const auto sleepMicroseconds = miscrosecInterval < 0 ? 1000 : static_cast<__useconds_t>(miscrosecInterval);

    while(conditionFinishRead)
    {
        const auto[bytes, errCode] = blockingReadPacket(fileDescriptor, flags);

        if(errCode > 0)
            return errCode;

        dataExecutor(bytes);

        usleep(sleepMicroseconds);
    }

    return 0;
}

uint32_t blockingReadPackets(const Socket& socket, const std::function<void (const std::vector<unsigned char> &)> &dataExecutor, bool& conditionFinishRead, int miscrosecInterval, int flags)
{
    return blockingReadPackets(socket.getSocketFd(), dataExecutor, conditionFinishRead, miscrosecInterval, flags);
}

/*
uint32_t blockingReadPackets(std::vector<char>& data, bool& conditionFinishRead, int miscrosecInterval, int flags)
{

}

uint32_t blockingReadPackets(const std::function<void (const std::vector<char> &)>& dataExecutor, bool& conditionFinishRead, int miscrosecInterval, int flags)
{

}
*/
}

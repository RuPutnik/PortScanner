#ifndef SR_H
#define SR_H

#include <arpa/inet.h>
#include <netinet/in.h>

#include "packet/i_header.h"
#include "packet/net_packet.h"

namespace network {

enum class PACKET_TYPE : int
{
    ICMP = IPPROTO_ICMP,
    TCP = IPPROTO_TCP,
    UDP = IPPROTO_UDP
};

class Socket
{
public:
    Socket(PACKET_TYPE type);
    ~Socket();

    int getSocketFd() const;

private:
    int socketFd;
};

class IPacketHandler
{
public:
    virtual ~IPacketHandler() = default;
    void handleData(const std::vector<unsigned char>& incomingNetData);
    std::optional<NetPacket> resolvePacket(std::vector<unsigned char> incomingNetData);
    virtual void handlePacket(const NetPacket& incomingNetData) = 0;

};

//TODO use std::expected<>
[[maybe_unused]] std::pair<std::optional<ssize_t>, uint32_t> sendPacketTo(int fileDescriptor, NetPacket packet, const std::string& ipv4Address, int flags = 0)
{
    in_addr targetAddress;
    if(inet_pton(AF_INET, ipv4Address.c_str(), &targetAddress.s_addr) < 0){
        return {std::nullopt, errno};
    }

    sockaddr_in addr{AF_INET, 0, targetAddress, {0}};

    memset(addr.sin_zero, 0, sizeof(addr.sin_zero));

    const auto packetData = packet.getData();
    const ssize_t amountBytes = sendto(fileDescriptor, packetData.get(), packet.getBytesLength(), flags, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));

    if(amountBytes > 0){
        return {amountBytes, 0};
    }else{
        return {std::nullopt, errno};
    }
}

[[maybe_unused]] std::pair<std::optional<ssize_t>, uint32_t> sendPacketTo(const Socket& socket, NetPacket packet, const std::string& ipv4Address, int flags = 0)
{
    return sendPacketTo(socket.getSocketFd(), std::move(packet), ipv4Address, flags);
}

[[maybe_unused]] std::pair<std::vector<unsigned char>, uint32_t> blockingReadPacket(int fileDescriptor, int flags = 0);
[[maybe_unused]] std::pair<std::vector<unsigned char>, uint32_t> blockingReadPacket(const Socket& socket, int flags = 0);

[[maybe_unused]] uint32_t blockingReadPackets(int fileDescriptor, const std::function<void (const std::vector<unsigned char>&)>& dataExecutor, std::atomic<bool>& conditionFinishRead, int microsecInterval = -1, int flags = 0);
[[maybe_unused]] uint32_t blockingReadPackets(const Socket& socket, const std::function<void (const std::vector<unsigned char>&)>& dataExecutor, std::atomic<bool>& conditionFinishRead, int microsecInterval = -1, int flags = 0);

[[maybe_unused]] uint32_t blockingReadPackets(int fileDescriptor, IPacketHandler* packetHandler, std::atomic<bool>& conditionFinishRead, int microsecInterval = -1, int flags = 0);
[[maybe_unused]] uint32_t blockingReadPackets(const Socket& socket, IPacketHandler* packetHandler, std::atomic<bool>& conditionFinishRead, int microsecInterval = -1, int flags = 0);

}

#endif // SR_H

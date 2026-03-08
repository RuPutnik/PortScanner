#ifndef SR_H
#define SR_H

#include <arpa/inet.h>
#include <netinet/in.h>

#include "packet/net_packet.h"

namespace network {

enum class PACKET_TYPE : int
{
    ICMP = IPPROTO_ICMP,
    TCP = IPPROTO_TCP,
    UDP = IPPROTO_UDP,
    ANY = IPPROTO_IP //TODO ?
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

[[maybe_unused]] network::expected<ssize_t, uint32_t> sendPacketTo(int fileDescriptor, NetPacket packet, const std::string& ipv4Address, int flags = 0);
[[maybe_unused]] network::expected<ssize_t, uint32_t> sendPacketTo(const Socket& socket, NetPacket packet, const std::string& ipv4Address, int flags = 0);

[[maybe_unused]] std::pair<std::vector<unsigned char>, uint32_t> blockingReadPacket(int fileDescriptor, int flags = 0);
[[maybe_unused]] std::pair<std::vector<unsigned char>, uint32_t> blockingReadPacket(const Socket& socket, int flags = 0);

[[maybe_unused]] uint32_t blockingReadPackets(int fileDescriptor, const std::function<void (const std::vector<unsigned char>&)>& dataExecutor, std::atomic<bool>& conditionFinishRead, int microsecInterval = -1, int flags = 0);
[[maybe_unused]] uint32_t blockingReadPackets(const Socket& socket, const std::function<void (const std::vector<unsigned char>&)>& dataExecutor, std::atomic<bool>& conditionFinishRead, int microsecInterval = -1, int flags = 0);

[[maybe_unused]] uint32_t blockingReadPackets(int fileDescriptor, IPacketHandler* packetHandler, std::atomic<bool>& conditionFinishRead, int microsecInterval = -1, int flags = 0);
[[maybe_unused]] uint32_t blockingReadPackets(const Socket& socket, IPacketHandler* packetHandler, std::atomic<bool>& conditionFinishRead, int microsecInterval = -1, int flags = 0);

}

#endif // SR_H

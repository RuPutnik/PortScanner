#include "sr.h"

#include <sys/socket.h>
#include <string>
#include <ranges>

#include "packet/icmp_header.h"
#include "packet/tcp_header.h"
#include "packet/udp_header.h"

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

uint32_t blockingReadPackets(int fileDescriptor, const std::function<void (const std::vector<unsigned char> &)>& dataExecutor, std::atomic<bool>& conditionFinishRead, int microsecInterval, int flags)
{
    const auto sleepMicroseconds = microsecInterval < 0 ? 1000 : static_cast<__useconds_t>(microsecInterval);

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

uint32_t blockingReadPackets(const Socket& socket, const std::function<void (const std::vector<unsigned char> &)>& dataExecutor, std::atomic<bool>& conditionFinishRead, int microsecInterval, int flags)
{
    return blockingReadPackets(socket.getSocketFd(), dataExecutor, conditionFinishRead, microsecInterval, flags);
}

uint32_t blockingReadPackets(int fileDescriptor, IPacketHandler* packetHandler, std::atomic<bool> &conditionFinishRead, int microsecInterval, int flags)
{
    const auto sleepMicroseconds = microsecInterval < 0 ? 1000 : static_cast<__useconds_t>(microsecInterval);

    while(conditionFinishRead)
    {
        const auto[bytes, errCode] = blockingReadPacket(fileDescriptor, flags);

        if(errCode > 0)
            return errCode;

        packetHandler->handleData(bytes);

        usleep(sleepMicroseconds);
    }

    return 0;
}

uint32_t blockingReadPackets(const Socket &socket, IPacketHandler *packetHandler, std::atomic<bool> &conditionFinishRead, int microsecInterval, int flags)
{
    return blockingReadPackets(socket.getSocketFd(), packetHandler, conditionFinishRead, microsecInterval, flags);
}

void IPacketHandler::handleData(const std::vector<unsigned char>& incomingNetData)
{
    const auto resolvedPacket = resolvePacket(incomingNetData);
    qDebug() << "Incoming Packet Proto ID: " << resolvedPacket->getProtoId();

    if(resolvedPacket.has_value()){
        handlePacket(std::move(resolvedPacket.value()));
    }else{
        qDebug() << "Unknown type packet!";
    }
}

std::optional<NetPacket> IPacketHandler::resolvePacket(std::vector<unsigned char> incomingNetData)
{
    if(incomingNetData.size() < 20){ //Минимальный размер IP пакета
        return std::nullopt;
    }

    //Определить тип пакета по анализу нужного поля в IP пакете
    const uint8_t protoIdIncomingData = incomingNetData[9];

    //Отбросить данные, относящиеся к заголовку IP пакета
    const uint8_t lengthIpHeaderBytes = 4 * (incomingNetData[0] & 0x0F); //Берем только 4 млашдших бита первого байта
    incomingNetData.erase(std::begin(incomingNetData), std::begin(incomingNetData) + lengthIpHeaderBytes);

    std::shared_ptr<IHeader> packetHeader;

    switch (static_cast<PACKET_TYPE>(protoIdIncomingData)) {
    case PACKET_TYPE::TCP:
        packetHeader = std::make_shared<TcpHeader>(0, 0);
        break;
    case PACKET_TYPE::UDP:
        packetHeader = std::make_shared<UdpHeader>();
        break;
    case PACKET_TYPE::ICMP:
        packetHeader = std::make_shared<IcmpHeader>(IcmpHeader::Type::Unknown);
        break;
    default:
        return std::nullopt;
    }

    return NetPacket{packetHeader, incomingNetData};
}

std::pair<std::optional<ssize_t>, uint32_t> sendPacketTo(const Socket &socket, NetPacket packet, const std::string &ipv4Address, int flags)
{
    return sendPacketTo(socket.getSocketFd(), std::move(packet), ipv4Address, flags);
}

std::pair<std::optional<ssize_t>, uint32_t> sendPacketTo(int fileDescriptor, NetPacket packet, const std::string &ipv4Address, int flags)
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

}

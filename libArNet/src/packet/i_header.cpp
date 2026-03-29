#include <i_header.h>

#include <chrono>
#include <random>

#include <arpa/inet.h>
#include <netdb.h>

IHeader::IHeader(const std::string& sourceIpAddress, const std::string& destinationIpAddress, const kivk_lib::Protocol& protHeaderFormat):
    headerFormat{protHeaderFormat}
{
    if(sourceIpAddress.empty() && destinationIpAddress.empty())
        return;

    in_addr sourceAddress{0};
    in_addr targetAddress{0};

    if(!sourceIpAddress.empty()){
        if(inet_pton(AF_INET, sourceIpAddress.data(), &sourceAddress.s_addr) < 0){
            perror("Error format IPv4 address");
            return;
        }
    }

    if(!destinationIpAddress.empty()){
        if(inet_pton(AF_INET, destinationIpAddress.data(), &targetAddress.s_addr) < 0){
            perror("Error format IPv4 address");
            return;
        }
    }

    ipAdresses = {sourceAddress.s_addr, targetAddress.s_addr};
}

IHeader::IHeader(uint32_t sourceIpAddress, uint32_t destinationIpAddress, const kivk_lib::Protocol &protHeaderFormat):
    headerFormat{protHeaderFormat},
    ipAdresses{{sourceIpAddress, destinationIpAddress}}
{}

uint16_t IHeader::lengthBytes() const
{
    return static_cast<uint16_t>(headerFormat.getLength());
}

std::optional<std::pair<uint32_t, uint32_t> > IHeader::getIPv4Addresses() const
{
    return ipAdresses;
}

std::string IHeader::getSourceIP() const
{
    if(!ipAdresses || ipAdresses->first == 0)
        return "";

    return inet_ntoa(in_addr{ipAdresses->first});
}

std::string IHeader::getTargetIP() const
{
    if(!ipAdresses || ipAdresses->second == 0)
        return "";

    return inet_ntoa(in_addr{ipAdresses->second});
}

std::string IHeader::getProtoName() const
{
    const protoent* const currProtoInfo = getprotobynumber(getProtoId());

    return {currProtoInfo->p_name};
}

uint32_t IHeader::generateRandomNumber_() const
{
    const auto time_since_epoch = std::chrono::steady_clock::now().time_since_epoch();
    std::mt19937 engine;
    engine.seed(static_cast<uint32_t>(time_since_epoch.count()));
    std::uniform_int_distribution<uint32_t> dist{1};
    return dist(engine);
}

uint16_t IHeader::calcCheckSum(const std::vector<unsigned char>& payloadPacket) const
{
    const uint32_t packetTotalLenBytes = lengthBytes() + static_cast<uint32_t>(payloadPacket.size());

    const uint32_t sizePseudoHeader = considerPseudoHeaderCalcCksum() ? sizeof(PseudoIpHeader) : 0;

    const uint32_t lenBytesBuffDataPacket = sizePseudoHeader + packetTotalLenBytes;

    //Здесь будут храниться псевдозаголовок IP, настоящий заголовок пакета, а также полезная нагрузка пакета
    const std::unique_ptr<uint16_t[]> buffDataPacket{new uint16_t[lenBytesBuffDataPacket / 2]};

    const auto[srcIp, dstIp] = ipAdresses.value_or(std::pair{0, 0});

    const PseudoIpHeader pseudoHeader{getProtoId(), srcIp, dstIp, static_cast<uint16_t>(packetTotalLenBytes)}; //Преобразование важно, т.к. в PseudoIpHeader поле длины занимает 2 байта

    memcpy(buffDataPacket.get(), &pseudoHeader, sizePseudoHeader);
    //Преобразуем к char* т.к. нам нужно сместиться на размер PseudoIpHeader в байтах
    memcpy(reinterpret_cast<char*>(buffDataPacket.get()) + sizePseudoHeader, headerFormat.getInternalBuffer(), lengthBytes());
    memcpy(reinterpret_cast<char*>(buffDataPacket.get()) + sizePseudoHeader + lengthBytes(), payloadPacket.data(), payloadPacket.size());

    return htons(calcCheckSum_(buffDataPacket.get(), lenBytesBuffDataPacket));
}

uint16_t IHeader::calcCheckSum_(uint16_t* buff, uint32_t buffByteSize) const
{
    // RFC1071
    // Compute Internet Checksum for "buffSize" bytes
    // beginning at location "buff".

    int32_t sum = 0;

    while(buffByteSize > 1)  {
        sum += *(buff++);
        buffByteSize -= 2;
    }

    // Add left-over byte, if any
    if(buffByteSize > 0){
        sum += * (unsigned char *) buff;
    }

    // Fold 32-bit sum to 16 bits
    while(sum >> 16){
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return static_cast<uint16_t>(~sum);
}

bool IHeader::isSetIpAdresses() const
{
    return ipAdresses.has_value();
}

IHeader::PseudoIpHeader::PseudoIpHeader(uint16_t protoId, uint32_t ipSource, uint32_t ipDestination, uint16_t tcpPacketLengthBytes):
    srcIp{ipSource}, dstIp{ipDestination},
    protoId{htons(protoId)}, tcpByteLen{htons(tcpPacketLengthBytes)}
{}

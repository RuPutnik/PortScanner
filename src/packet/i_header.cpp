#include "i_header.h"

#include <chrono>
#include <random>

IHeader::IHeader(const std::optional<std::pair<uint32_t, uint32_t>>& packetIpAdresses, const kivk_lib::Protocol& protHeaderFormat):
    headerFormat{protHeaderFormat},
    ipAdresses{packetIpAdresses}
{}

uint16_t IHeader::lengthBytes() const
{
    return static_cast<uint16_t>(headerFormat.getLength());
}

uint32_t IHeader::generateRandomNumber_() const
{
    const auto time_since_epoch = std::chrono::steady_clock::now().time_since_epoch();
    std::mt19937 engine;
    engine.seed(static_cast<uint32_t>(time_since_epoch.count()));
    std::uniform_int_distribution<uint32_t> dist{1};
    return dist(engine);
}

uint16_t IHeader::calcCheckSum(const std::shared_ptr<char[]>& payloadPacket, uint32_t payloadLenBytes) const
{
    const uint32_t packetTotalLenBytes = lengthBytes() + payloadLenBytes;

    const uint32_t sizePseudoHeader = isSetIpAdresses() ? sizeof(PseudoIpHeader) : 0; //Если адреса не заданы, то использовать псевдо заголовок IP не нужно

    const uint32_t lenBytesBuffDataPacket = sizePseudoHeader + packetTotalLenBytes; //TODO Для ICMP псевдозаголовок не участвует в подсчете КС, нужно что то думать...

    //Здесь будут храниться псевдозаголовок IP, настоящий заголовок пакета, а также полезная нагрузка пакета
    const std::unique_ptr<uint16_t[]> buffDataPacket{new uint16_t[lenBytesBuffDataPacket / 2]};

    const auto[srcIp, dstIp] = ipAdresses.value_or(std::pair{0, 0});

    const PseudoIpHeader pseudoHeader{getProtoId(), srcIp, dstIp, static_cast<uint16_t>(packetTotalLenBytes)}; //Преобразование важно, т.к. в PseudoIpHeader поле длины занимает 2 байта

    memcpy(buffDataPacket.get(), &pseudoHeader, sizePseudoHeader);
    //Преобразуем к char* т.к. нам нужно сместиться на размер PseudoIpHeader в байтах
    memcpy(reinterpret_cast<char*>(buffDataPacket.get()) + sizePseudoHeader, headerFormat.getInternalBuffer(), lengthBytes());
    memcpy(reinterpret_cast<char*>(buffDataPacket.get()) + sizePseudoHeader + lengthBytes(), payloadPacket.get(), payloadLenBytes);

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

#ifndef I_HEADER_H
#define I_HEADER_H

#include <cstdint>
#include <utility>
#include <optional>

#include "../tools.h"
#include <protocol.h>
#include <netinet/ip.h>

class IHeader
{
public:
    virtual ~IHeader() = default;

    IHeader(const std::optional<std::pair<uint32_t, uint32_t>>& packetIpAdresses, const kivk_lib::Protocol& protHeaderFormat);

    virtual uint16_t setHeaderData(const std::vector<unsigned char>& dataPacket) = 0; //Метод виртуальный, т.к. некоторые заголовки могут иметь плавающий размер
    virtual std::unique_ptr<const char[]> generateCompleteHeader(const std::shared_ptr<char[]>& payload, uint32_t payloadLenBytes) = 0;
    uint16_t lengthBytes() const;
    virtual uint32_t maxPayloadLengthBytes() const = 0;
    virtual void debugHex() const = 0;
    virtual void debugBin() const = 0;
    virtual uint16_t getProtoId() const = 0;
    virtual std::shared_ptr<IHeader> clone() = 0;

protected:
    struct PseudoIpHeader final
    {
        PseudoIpHeader(uint16_t protoId, uint32_t ipSource, uint32_t ipDestination, uint16_t packetLengthBytes);

        uint32_t srcIp;
        uint32_t dstIp;
        const uint16_t protoId;
        uint16_t tcpByteLen;
    };

    kivk_lib::Protocol headerFormat;
    std::optional<std::pair<uint32_t, uint32_t>> ipAdresses; //sourceIp, destinationIp

    template<class ResType>
    ResType generateRandomNumber() const
    {
        return static_cast<ResType>(generateRandomNumber_());
    }

    uint16_t calcCheckSum(const std::shared_ptr<char[]> &payloadPacket, uint32_t payloadLenBytes) const;

private:
    uint32_t generateRandomNumber_() const;
    uint16_t calcCheckSum_(uint16_t *buff, uint32_t buffByteSize) const;
    bool isSetIpAdresses() const;

};

#endif // I_HEADER_H

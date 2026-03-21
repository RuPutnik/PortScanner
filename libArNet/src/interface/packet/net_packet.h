#ifndef NET_PACKET_H
#define NET_PACKET_H

#include "i_header.h"

namespace network {

class NetPacket
{
public:
    NetPacket(std::shared_ptr<IHeader> header_, std::shared_ptr<char[]> payload_, uint32_t amountBytes):
        header{std::move(header_)}, payload{payload_}, lengthPayload{amountBytes}
    {}

    NetPacket(std::shared_ptr<IHeader> header_, const std::string& payload_):
        header{std::move(header_)}
    {
        setPayload(payload_);
    }

    NetPacket(std::shared_ptr<IHeader> header_, const std::vector<unsigned char>& data = {}):
        header{std::move(header_)},
        payload{nullptr},
        lengthPayload{0}
    {
        if(!data.empty()){
            setData(data);
        }
    }

    NetPacket(const NetPacket& packet):
        lengthPayload{packet.lengthPayload}
    {
        payload = std::shared_ptr<char[]>(new char[lengthPayload]);
        memcpy(payload.get(), packet.payload.get(), lengthPayload);
        header = packet.header->clone();
    }

    NetPacket(NetPacket&&) = default;

    NetPacket& operator=(const NetPacket& packet) noexcept
    {
        lengthPayload = packet.lengthPayload;
        payload.reset(new char[lengthPayload]);
        memcpy(payload.get(), packet.payload.get(), lengthPayload);
        header = packet.header->clone();

        return *this;
    }

    uint32_t getLengthPayload() const
    {
        return lengthPayload;
    }

    std::shared_ptr<const char[]> getPayload() const
    {
        return payload;
    }

    std::shared_ptr<const IHeader> getHeader() const
    {
        return header;
    }

    NetPacket& operator=(NetPacket&&) noexcept = default;

    uint32_t getBytesLength() const
    {
        return header->lengthBytes() + lengthPayload;
    }

    std::unique_ptr<const char[]> getData()
    {
        //Создаем массив размером в длину сегмента в байтах
        char* const tcpPacketBuffer = new char[getBytesLength()];

        //Преобразуем порядок байт данных в сетевой (BigEndian)
        const auto payloadBigEndian = reverseByteOrder(payload.get(), lengthPayload);

        //Выполняем доформирование заголовка (высчитывает контрольную сумму) и копируем результат в общий буфер
        const auto completeHeaderData = header->generateCompleteHeader(payloadBigEndian, lengthPayload);
        memcpy(tcpPacketBuffer, completeHeaderData.get(), header->lengthBytes());
        memcpy(tcpPacketBuffer + header->lengthBytes(), payloadBigEndian.get(), lengthPayload);

        return std::unique_ptr<const char[]>(tcpPacketBuffer);
    }

    void setData(const std::vector<unsigned char>& data)
    {
        const uint32_t lengthHeaderBytes = header->setHeaderData(data);

        lengthPayload = static_cast<uint32_t>(data.size()) - lengthHeaderBytes;

        payload = std::shared_ptr<char[]>(new char[lengthPayload]);

        memcpy(payload.get(), data.data() + lengthHeaderBytes, lengthPayload);
    }

    void setPayload(const std::shared_ptr<char[]>& newPayload, uint32_t amountBytes)
    {
        payload = newPayload;
        lengthPayload = amountBytes;
    }

    void setPayload(std::string newPayload)
    {
        lengthPayload = static_cast<uint32_t>(newPayload.length() + 1);

        char* copiedPayload = new char[lengthPayload];

        #if __BYTE_ORDER == __LITTLE_ENDIAN
            copiedPayload[0] = 0;
            std::ranges::reverse(newPayload);
            memcpy(copiedPayload + 1, newPayload.c_str(), lengthPayload - 1);
        #else
            memcpy(copiedPayload, newPayload.c_str(), lengthPayload);
        #endif
        payload = std::shared_ptr<char[]>(copiedPayload);
    }

    void debugPayload() const
    {
        printf("---Payload---\n");
        std::string word;
        for(std::size_t i = 0; i < lengthPayload; i++){
            std::string tempPartword;
            sprintf(tempPartword.data(), "%X", payload[static_cast<std::ptrdiff_t>(i)]);
            word += tempPartword;
            if((i+1) % 4 == 0 || i == lengthPayload - 1) {
                printf("0x%s\n", word.c_str());
                word.clear();
            }
        }
        printf("-------------\n");
    }

    void debugAsciiPayload() const
    {
        printf("---Payload---");
        std::string word;
        for(std::size_t i = 0; i < lengthPayload; i++){
            word += payload[static_cast<std::ptrdiff_t>(i)];
            if((i+1) % 4 == 0 || i == lengthPayload - 1) {
                printf("0x%s\n", word.c_str());
                word.clear();
            }
        }
        printf("-------------");
    }

    void debugHex() const
    {
        header->debugHex();
        debugPayload();
    }

    void debugBin() const
    {
        header->debugBin();
        debugPayload();
    }

    int getProtoId() const
    {
        return header->getProtoId();
    }

private:
    std::shared_ptr<IHeader> header;
    std::shared_ptr<char[]> payload;
    uint32_t lengthPayload;

    std::shared_ptr<char[]> reverseByteOrder(char *data, uint32_t lenBytes) const
    {
        const std::shared_ptr<char[]> reversedData{new char[lenBytes]};
        std::reverse_copy(data, data + lenBytes, reversedData.get());

        return reversedData;
    }
};

}

#endif // NET_PACKET_H

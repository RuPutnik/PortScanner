#ifndef NET_PACKET_H
#define NET_PACKET_H

#include <QString>
#include <QDebug>

#include <cstdint>
#include <memory>
#include <concepts>

#include <string.h>

#include "i_header.h"

namespace network {

template<class H> requires std::derived_from<H, IHeader>
class NetPacket
{
public:
    NetPacket(H header_, std::shared_ptr<char[]> payload_, uint32_t amountBytes):
        header{std::move(header_)}, payload{payload_}, lengthPayload{amountBytes}
    {}

    NetPacket(H header_, const std::string& payload_):
        header{std::move(header_)}
    {
        setPayload(payload_);
    }

    NetPacket(H header_):
        header{std::move(header_)},
        payload{nullptr},
        lengthPayload{0}
    {}

    NetPacket(const NetPacket&) = default;
    NetPacket(NetPacket&&) = default;

    NetPacket& operator=(const NetPacket&) noexcept = default;
    NetPacket& operator=(NetPacket&&) noexcept = default;

    uint32_t getBytesLength() const
    {
        return header.lengthBytes() + lengthPayload;
    }

    std::unique_ptr<const char[]> getData()
    {
        //Создаем массив размером в длину сегмента в байтах
        char* const tcpPacketBuffer = new char[getBytesLength()];

        //Преобразуем порядок байт данных в сетевой (BigEndian)
        const auto payloadBigEndian = reverseByteOrder(payload.get(), lengthPayload);

        //Выполняем доформирование заголовка (высчитывает контрольную сумму) и копируем результат в общий буфер
        const auto completeHeaderData = header.generateCompleteHeader(payloadBigEndian, lengthPayload);
        memcpy(tcpPacketBuffer, completeHeaderData.get(), header.lengthBytes());
        memcpy(tcpPacketBuffer + header.lengthBytes(), payloadBigEndian.get(), lengthPayload);

        return std::unique_ptr<const char[]>(tcpPacketBuffer);
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
        qDebug().noquote() << "---Payload---";
        QString word;
        for(int i = 0; i < lengthPayload; i++){
            word += QString::number(payload[i], 16).rightJustified(2, '0');
            if((i+1) % 4 == 0 || i == lengthPayload - 1) {
                qDebug().noquote() << "0x" + word;
                word.clear();
            }
        }
        qDebug().noquote() << "-------------";
    }

    void debugHex() const
    {
        header.debugHex();
        debugPayload();
    }

    void debugBin() const
    {
        header.debugBin();
        debugPayload();
    }

private:
    H header;
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

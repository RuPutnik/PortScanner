#include "tcp_packet.h"

#include <algorithm>

namespace network {

TcpPacket::TcpPacket(TcpHeader header_, std::shared_ptr<char[]> payload_, uint32_t amountBytes):
    header{std::move(header_)}, payload{payload_}, lengthPayload{amountBytes}
{}

TcpPacket::TcpPacket(TcpHeader header_, const std::string& payload_):
    header{std::move(header_)}
{
    setPayload(payload_);
}

TcpPacket::TcpPacket(TcpHeader header_):
    header{std::move(header_)},
    payload{{}},
    lengthPayload{0}
{}

uint32_t TcpPacket::getBytesLength()
{
    return header.lengthBytes() + lengthPayload;
}

std::unique_ptr<const char[]> TcpPacket::getData()
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

void TcpPacket::setPayload(const std::shared_ptr<char[]>& newPayload, uint32_t amountBytes)
{
    payload = newPayload;
    lengthPayload = amountBytes;
}

void TcpPacket::setPayload(const std::string& newPayload)
{
    lengthPayload = static_cast<uint32_t>(newPayload.length() + 1);
    char* copiedPayload = new char[lengthPayload];
    memcpy(copiedPayload, newPayload.c_str(), lengthPayload);

    payload = std::shared_ptr<char[]>(copiedPayload);

}

void TcpPacket::debugHex() const
{
    //TODO
}

void TcpPacket::debugBin() const
{
    //TODO
}

std::shared_ptr<char[]> TcpPacket::reverseByteOrder(char* data, uint32_t lenBytes) const
{
    const std::shared_ptr<char[]> reversedData{new char[lenBytes]};
    std::reverse_copy(data, data + lenBytes, reversedData.get());

    return reversedData;
}

}

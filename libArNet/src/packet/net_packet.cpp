#include "net_packet.h"

network::NetPacket::NetPacket(std::shared_ptr<IHeader> header_, const std::string& payload_):
    header{std::move(header_)}
{
    setPayload(payload_);
}

network::NetPacket::NetPacket(std::shared_ptr<IHeader> header_, const std::vector<unsigned char>& data):
    header{std::move(header_)}
{
    setData(data);
}

network::NetPacket::NetPacket(const NetPacket& packet)
{
    if(&packet == this)
        return;

    payload = packet.payload;
    header = packet.header->clone();
}

network::NetPacket& network::NetPacket::operator=(const NetPacket& packet) noexcept
{
    if(&packet == this)
        return *this;

    payload = packet.payload;
    header = packet.header->clone();

    return *this;
}

uint32_t network::NetPacket::getBytesLength() const
{
    return header->lengthBytes() + getLengthPayload();
}

std::vector<unsigned char> network::NetPacket::getData()
{
    //Создаем массив размером в длину сегмента в байтах
    unsigned char* const tcpPacketBuffer = new unsigned char[getBytesLength()];

    //Преобразуем порядок байт данных в сетевой (BigEndian)
    const auto payloadBigEndian = reverseByteOrder(payload);

    //Выполняем доформирование заголовка (высчитывает контрольную сумму) и копируем результат в общий буфер
    const auto completeHeaderData = header->generateCompleteHeader(payloadBigEndian);
    memcpy(tcpPacketBuffer, completeHeaderData.get(), header->lengthBytes());
    memcpy(tcpPacketBuffer + header->lengthBytes(), payloadBigEndian.data(), getLengthPayload());

    return std::vector(tcpPacketBuffer, tcpPacketBuffer + getBytesLength());
}

bool network::NetPacket::setData(const std::vector<unsigned char>& data)
{
    if(data.size() < header->lengthBytes())
        return false;

    const uint32_t lengthHeaderBytes = header->setHeaderData(data);
    const auto lengthPayload = static_cast<uint32_t>(data.size()) - lengthHeaderBytes;

    payload = std::vector<unsigned char>(lengthPayload);
    std::copy(std::begin(data) + lengthHeaderBytes, std::end(data), std::begin(payload));

    return true;
}

void network::NetPacket::setPayload(const std::vector<unsigned char>& newPayload)
{
    payload = newPayload;
}

void network::NetPacket::setPayload(std::string newPayload)
{
    const auto lengthPayload = static_cast<uint32_t>(newPayload.length() + 1);

    unsigned char* const copiedPayload = new unsigned char[lengthPayload];

#if __BYTE_ORDER == __LITTLE_ENDIAN
    copiedPayload[0] = 0;
    std::ranges::reverse(newPayload);
    memcpy(copiedPayload + 1, newPayload.c_str(), lengthPayload - 1);
#else
    memcpy(copiedPayload, newPayload.c_str(), lengthPayload);
#endif
    payload = std::vector<unsigned char>(copiedPayload, copiedPayload + lengthPayload);
}

void network::NetPacket::debugPayload() const
{
    printf("---Payload---\n");
    std::string word;
    for(std::size_t i = 0; i < payload.size(); i++){
        std::string tempPartword;
        sprintf(tempPartword.data(), "%X", payload[i]);
        word += tempPartword;
        if((i+1) % 4 == 0 || i == payload.size() - 1) {
            printf("0x%s\n", word.c_str());
            word.clear();
        }
    }
    printf("-------------\n");
}

void network::NetPacket::debugAsciiPayload() const
{
    printf("---Payload---");
    std::string word;
    for(std::size_t i = 0; i < payload.size(); i++){
        word.push_back(static_cast<char>(payload[i]));
        if((i+1) % 4 == 0 || i == payload.size() - 1) {
            printf("0x%s\n", word.c_str());
            word.clear();
        }
    }
    printf("-------------");
}

void network::NetPacket::debugHex() const
{
    header->debugHex();
    printf("\n");
    debugPayload();
}

void network::NetPacket::debugBin() const
{
    header->debugBin();
    debugPayload();
}

int network::NetPacket::getProtoId() const
{
    return header->getProtoId();
}

std::vector<unsigned char> network::NetPacket::reverseByteOrder(std::vector<unsigned char> data) const
{
    std::ranges::reverse(data);

    return data;
}

uint32_t network::NetPacket::getLengthPayload() const
{
    return static_cast<uint32_t>(payload.size());
}

const std::vector<unsigned char>& network::NetPacket::getPayload() const
{
    return payload;
}

std::shared_ptr<const IHeader> network::NetPacket::getHeader() const
{
    return header;
}

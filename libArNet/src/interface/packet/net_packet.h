#ifndef NET_PACKET_H
#define NET_PACKET_H

#include "i_header.h"

namespace network {

class NetPacket
{
public:
    NetPacket(std::shared_ptr<IHeader> header_, const std::string& payload_);
    NetPacket(std::shared_ptr<IHeader> header_, const std::vector<unsigned char>& data = {});

    NetPacket(const NetPacket& packet);
    NetPacket(NetPacket&&) noexcept = default;
    NetPacket& operator=(const NetPacket& packet) noexcept;
    NetPacket& operator=(NetPacket&&) noexcept = default;

    uint32_t getLengthPayload() const;
    const std::vector<unsigned char>& getPayload() const;
    std::shared_ptr<const IHeader> getHeader() const;
    uint32_t getBytesLength() const;
    std::vector<unsigned char> getData();
    int getProtoId() const;

    bool setData(const std::vector<unsigned char>& data);
    void setPayload(const std::vector<unsigned char>& newPayload);
    void setPayload(std::string newPayload);

    void debugPayload() const;
    void debugAsciiPayload() const;
    void debugHex() const;
    void debugBin() const;

private:
    std::shared_ptr<IHeader> header;
    std::vector<unsigned char> payload;

    std::vector<unsigned char> reverseByteOrder(std::vector<unsigned char> data) const;
};

}

#endif // NET_PACKET_H

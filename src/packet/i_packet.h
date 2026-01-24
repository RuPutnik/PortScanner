#ifndef I_PACKET_H
#define I_PACKET_H

#include <cstdint>
#include <memory>

namespace network {

class IPacket
{
public:
    IPacket() = default;
    IPacket(const IPacket&) = default;
    IPacket(IPacket&&) = default;

    IPacket& operator=(const IPacket&) noexcept = default;
    IPacket& operator=(IPacket&&) noexcept = default;

    virtual ~IPacket() = default;

    virtual uint32_t getBytesLength() = 0;
    virtual std::unique_ptr<const char[]> getData() = 0;

};

}

#endif // I_PACKET_H

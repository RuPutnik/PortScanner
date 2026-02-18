#ifndef TOOLS_H
#define TOOLS_H

#include <cstdint>
#include <limits>
#include <linux/if_ether.h>

namespace network {

template<class T>
[[maybe_unused]] constexpr static inline uint64_t bitSize() noexcept{
    static_assert(sizeof(T) <= std::numeric_limits<uint32_t>::max(), "Вычисляемое значение больше максимального значения uint32_t");
    return __CHAR_BIT__ * sizeof(T);
}

[[maybe_unused]] constexpr static inline uint64_t bitSize(uint32_t amountBytes) noexcept{
    return __CHAR_BIT__ * amountBytes;
}

const inline uint32_t ipHeaderLenBytes = 20;
constexpr static inline uint32_t maxTransportPacketLenBytes = ETH_DATA_LEN - ipHeaderLenBytes;  // = 1480

}

#endif // TOOLS_H

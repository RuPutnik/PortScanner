#ifndef TOOLS_H
#define TOOLS_H

namespace network {

template<class T>
constexpr static inline uint64_t bitSize() noexcept{
    static_assert(sizeof(T) <= std::numeric_limits<uint32_t>::max(), "Вычисляемое значение больше максимального значения uint32_t");
    return __CHAR_BIT__ * sizeof(T);
}

constexpr static inline uint64_t bitSize(uint32_t amountBytes) noexcept{
    return __CHAR_BIT__ * amountBytes;
}

}

#endif // TOOLS_H

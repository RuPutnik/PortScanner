#ifndef TOOLS_H
#define TOOLS_H

#include <optional>
#include <iostream>
#include <regex>
#include <limits>

#include <net/if.h>
#include <netdb.h>

#define ETH_DATA_LEN 1500

namespace network {

constexpr static inline uint32_t minIpHeaderLenBytes = 20;
constexpr static inline uint32_t netWordByteLen = 4;
constexpr static inline uint32_t maxTransportPacketLenBytes = ETH_DATA_LEN - minIpHeaderLenBytes;  // = 1480

template<class T>
[[maybe_unused]] constexpr static inline uint64_t bitSize() noexcept
{
    static_assert(sizeof(T) <= std::numeric_limits<uint32_t>::max(), "Вычисляемое значение больше максимального значения uint32_t");
    return __CHAR_BIT__ * sizeof(T);
}

[[maybe_unused]] constexpr static inline uint64_t bitSize(uint32_t amountBytes) noexcept{
    return __CHAR_BIT__ * amountBytes;
}

[[maybe_unused]] std::string getDefaultEthIface();

[[maybe_unused]] std::string getCurrentIpAddress();

[[maybe_unused]] std::vector<std::string> resolveHostname(const std::string& hostName);

class unexp_token{};

template<class DataType, class ErrType = uint32_t>
class expected
{
    template<class E>
    friend expected<unexp_token, E> unexpected(const E& e);
public:
    expected(const DataType& dt):
        data{dt}
    {}

    template<class E>
    expected(const expected<unexp_token, E>& e):
        error{e.getError()}
    {}

    const std::optional<DataType>& getData() const
    {
        return data;
    }

    const std::optional<ErrType>& getError() const
    {
        return error;
    }

    bool hasValue() const
    {
        return data.has_value();
    }

    bool hasError() const
    {
        return error.has_value();
    }

    operator bool() const
    {
        return hasValue();
    }

    DataType* operator->()
    {
        if(data.has_value())
            return &data;
        else
            return nullptr;
    }

private:
    expected(const ErrType& e):
        error{e}
    {}

    std::optional<DataType> data;
    std::optional<ErrType> error;
};

template<class ErrType>
expected<unexp_token, ErrType> unexpected(const ErrType& e)
{
    return {e};
}

}

#endif // TOOLS_H

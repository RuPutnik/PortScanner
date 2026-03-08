#ifndef TOOLS_H
#define TOOLS_H

#include <arpa/inet.h>
#include <cstdint>
#include <string>
#include <limits>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <fstream>
#include <netinet/in.h>


#include <QDebug>

namespace network {

const inline uint32_t minIpHeaderLenBytes = 20;
constexpr static inline uint32_t maxTransportPacketLenBytes = ETH_DATA_LEN - minIpHeaderLenBytes;  // = 1480
const inline uint32_t netWordByteLen = 4;

template<class T>
[[maybe_unused]] constexpr static inline uint64_t bitSize() noexcept{
    static_assert(sizeof(T) <= std::numeric_limits<uint32_t>::max(), "Вычисляемое значение больше максимального значения uint32_t");
    return __CHAR_BIT__ * sizeof(T);
}

[[maybe_unused]] constexpr static inline uint64_t bitSize(uint32_t amountBytes) noexcept{
    return __CHAR_BIT__ * amountBytes;
}

inline std::string getDefaultEthIface()
{
    std::ifstream procNetRoute{"/proc/net/route"};
    if(!procNetRoute.is_open()){
        return {};
    }

    std::string mainEthIfaceName;
    std::string ethsInfoData;

    while(std::getline(procNetRoute, ethsInfoData, '\n')){
        QStringList params = QString{ethsInfoData.c_str()}.simplified().split(" ");
        if(params.size() < 4)
            continue;

        if(params[1].toInt() == 0 && (params[3].toInt() & 0x3)){
            mainEthIfaceName = params[0].toStdString();
            break;
        }
    }

    return mainEthIfaceName;
}

[[maybe_unused]] inline std::string getCurrentIpAddress()
{
    const int fdSocket = socket(AF_INET, SOCK_DGRAM, 0);

    const std::string ifname = getDefaultEthIface();

    class ifreq ifr;
    strcpy(ifr.ifr_name, ifname.c_str());

    ioctl(fdSocket, SIOCGIFADDR, &ifr);

    uint32_t currAddrDigital;
    memcpy(&currAddrDigital, ifr.ifr_addr.sa_data + 2, 4);

    close(fdSocket);
    return inet_ntoa(in_addr{currAddrDigital});
}

[[maybe_unused]] inline std::vector<std::string> resolveHostname(const std::string& hostName)
{
    const hostent* result = gethostbyname(hostName.data());

    if(!result)
        return {};

    std::vector<std::string> addresses;

    for(int i = 0;; i++){
        const char* const currAddr = result->h_addr_list[i];
        if(currAddr == nullptr) break;

        uint32_t currAddrDigital;
        memcpy(&currAddrDigital, currAddr, static_cast<size_t>(result->h_length));

        addresses.emplace_back(inet_ntoa(in_addr{currAddrDigital}));
    }

    return addresses;
}

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

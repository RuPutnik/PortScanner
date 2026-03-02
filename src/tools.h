#ifndef TOOLS_H
#define TOOLS_H

#include <cstdint>
#include <string>
#include <limits>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <fstream>
#include <netinet/in.h>

#include <QFile>
#include <QDebug>

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

inline std::string getDefaultEthIface()
{
    std::ifstream procNetRoute1{"/proc/net/route"};
    if(!procNetRoute1.is_open()){
        return {};
    }

    std::string mainEthIfaceName;
    std::string ethsInfoData;

    while(std::getline(procNetRoute1, ethsInfoData, '\n')){
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

inline char* getCurrentIpAddress()
{
    int fdSocket = socket(AF_INET, SOCK_DGRAM, 0);
    static char ipAddress[INET_ADDRSTRLEN];
    memset(ipAddress, 0, sizeof(ipAddress));

    const std::string ifname = getDefaultEthIface();
    qDebug() << ifname;

    class ifreq ifr = {0};
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname.c_str());

    ioctl(fdSocket, SIOCGIFADDR, &ifr);

    sprintf(ipAddress, "%hhu.%hhu.%hhu.%hhu",
            static_cast<unsigned char>(ifr.ifr_addr.sa_data[2]),
            static_cast<unsigned char>(ifr.ifr_addr.sa_data[3]),
            static_cast<unsigned char>(ifr.ifr_addr.sa_data[4]),
            static_cast<unsigned char>(ifr.ifr_addr.sa_data[5]));

    close(fdSocket);
    return ipAddress;
}

inline std::string resolveHostname(const std::string& hostName)
{

}

}

#endif // TOOLS_H

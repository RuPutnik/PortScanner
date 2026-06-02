#include "tools.h"

#include <fstream>
#include <sstream>

#include <arpa/inet.h>
#include <sys/ioctl.h>

namespace network
{

std::string getDefaultEthIface()
{
    std::ifstream procNetRoute{"/proc/net/route"};
    if(!procNetRoute.is_open()){
        return {};
    }

    std::string mainEthIfaceName;
    std::string currEthInfoData;
    std::string currEthInfoCurrParam;

    while(std::getline(procNetRoute, currEthInfoData, '\n')){
        currEthInfoData = std::regex_replace(currEthInfoData, std::regex{"[\\s\\t]+"}, " ");

        std::stringstream currEthLineStream{currEthInfoData};
        std::vector<std::string> ethParams;

        while (std::getline(currEthLineStream, currEthInfoCurrParam, ' ')) {
            ethParams.push_back(currEthInfoCurrParam);
        }

        if(ethParams.size() < 4)
            continue;

        try{
            if(std::stoi(ethParams[1]) == 0 && (std::stoi(ethParams[3]) & 0x3)){
                mainEthIfaceName = ethParams[0];
                break;
            }
        }catch(const std::invalid_argument& iae){
            continue;
        }
    }

    return mainEthIfaceName;
}

std::string getCurrentIpAddress()
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

std::vector<std::string> resolveHostname(const std::string& hostName)
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

uint32_t textIpV4ToUint(const std::string& ipv4Address)
{
    uint32_t currAddress = 0;
    inet_pton(AF_INET, ipv4Address.data(), &currAddress);

    return ntohl(currAddress);
}

}

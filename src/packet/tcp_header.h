#ifndef TCP_HEADER_H
#define TCP_HEADER_H

#include <memory>
#include <unordered_map>
#include <string>

#include <protocol.h>

#include "../tools.h"

namespace network {

class TcpHeader final
{
public:
    enum Flags
    {
        URG = 0b100000,
        ACK = 0b010000,
        PSH = 0b001000,
        RST = 0b000100,
        SYN = 0b000010,
        FIN = 0b000001
    };

    enum class Options : uint8_t
    {
        EndOptions = 0,
        NOP = 1,
        MSS = 2,
        WindowScaling = 3,
        SACK_Permitted = 4,
        SACK = 5,
        Timestamps = 8,
        FastOpen = 34
    };

    struct OptionValue
    {
        enum TypeValue{
            UINT8 = 8,
            UINT16 = 16,
            UINT32 = 32,
            UINT64 = 64
        };

        TypeValue type;
        uint64_t value;
    };

    using OptionValues = std::vector<OptionValue>;

    //20 байт минимальный размер заголовка (без опций) и 40 байт максимальный размер опций в заголовке
    const static inline uint32_t maxTcpHeaderLenBytes = 60;

    TcpHeader(uint32_t sourceIp, uint32_t destinationIp);

    std::unique_ptr<const char[]> generateCompleteHeader(uint16_t lenTcpDataBytes);
    uint16_t lengthBytes() const noexcept;

    uint16_t getSrcPort() const;
    void setSrcPort(uint16_t newSrcPort);

    uint16_t getDstPort() const;
    void setDstPort(uint16_t newDstPort);

    uint32_t getSeqNumber() const;
    void setSeqNumber(uint32_t newSeqNumber);

    uint32_t getAckNumber() const;
    void setAckNumber(uint32_t newAckNumber);

    uint8_t getHdrLen() const;
    void setHdrLen(uint8_t newHdrLen);

    bool isUrg() const;
    bool isAck() const;
    bool isPsh() const;
    bool isRst() const;
    bool isSyn() const;
    bool isFin() const;

    uint8_t getFlags() const;
    void setFlags(uint8_t flags);
    void resetFlags();

    uint16_t getWindowSize() const;
    void setWindowSize(uint16_t newWindowSize);

    uint16_t getChksum() const;

    uint16_t getUrgent() const;
    void setUrgent(uint16_t newUrgent);

    void debugHex(uint16_t lenTcpDataBytes = 0) const;
    void debugBin(uint16_t lenTcpDataBytes = 0) const;
    uint16_t calcCheckSum(uint32_t srcIp, uint32_t dstIp, uint16_t lenTcp) const;

    // Работа с опциями
    bool addOption(Options option, const OptionValues& values = {}, bool lastOption = false);
    bool setOptionValues(Options option, const OptionValues& values);
    std::string getOptionsAsText() const;

private:
    struct PseudoTcpHeader final
    {
        PseudoTcpHeader(uint32_t ipSource, uint32_t ipDestination, uint16_t tcpPacketLengthBytes);

        uint32_t srcIp;
        uint32_t dstIp;
        const uint16_t protoId;
        uint16_t tcpByteLen;
    };

    using OptionData = std::pair<int32_t, std::string>; //Размер в байтах, текстовое название

    const static inline uint32_t bitLenOptionId = static_cast<uint32_t>(bitSize<uint8_t>()); //Длина в битах поля с кодом опции
    const static inline uint32_t bitLenOptionLen = static_cast<uint32_t>(bitSize<uint8_t>()); //Длина в битах поля с длиной опции
    const static inline std::string optionIdProtFieldName = "_id"; //Постфиксы названий полей в протоколе опций
    const static inline std::string optionLenProtFieldName = "_len";
    const static inline std::string optionValProtFieldName = "_value_";

    constexpr static inline uint16_t defaultWindowSize = std::numeric_limits<int16_t>::max();
    const static std::unordered_map<TcpHeader::Options, TcpHeader::OptionData> optionsParams;

    kivk_lib::Protocol tcpHeaderFormat{{
        {"srcPort", 16}, {"dstPort", 16},
        {"seqNumber", 32},
        {"ackNumber", 32},
        {"headerLength", 4}, {"reserver", 6}, {"urg", 1}, {"ack", 1}, {"psh", 1}, {"rst", 1}, {"syn", 1}, {"fin", 1}, {"windowSize", 16},
        {"chksum", 16}, {"urgent", 16}
    }};

    uint32_t srcIp;
    uint32_t dstIp;
    std::unordered_map<TcpHeader::Options, OptionValues> headerOptions;
    bool optionsFilled;

    void setChksum(uint16_t newChksum);
    void updateChkSum(uint16_t lenTcp);
    uint32_t generateRandomNumber() const;
    uint16_t calcCheckSum_(uint16_t *buff, uint16_t buffByteSize) const;
    bool containsOption(Options opt) const;
};

}

#endif // TCP_HEADER_H

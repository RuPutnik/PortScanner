#ifndef TCP_HEADER_H
#define TCP_HEADER_H

#include <stdint-gcc.h>
#include <memory>
#include <limits>
#include <unordered_map>
#include <string>

#include <protocol.h>

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

    enum class Options
    {
        EndOptions = 0,
        NOP = 1,
        MSS = 2,
        WindowScaling = 3,
        SACK = 4,
        Timestamps = 8,
        FastOpen = 34
    };

    TcpHeader();

    std::unique_ptr<const char[]> generateCompleteHeader(uint32_t srcIp, uint32_t dstIp, uint16_t lenTcp);
    uint16_t length() const noexcept;

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

    void debugHex() const;
    void debugBin() const;
    uint16_t calcCheckSum(uint32_t srcIp, uint32_t dstIp, uint16_t lenTcp) const;

private:
    struct PseudoTcpHeader final
    {
        PseudoTcpHeader(uint32_t ipSource, uint32_t ipDestination, uint16_t tcpPacketLengthBytes);

        uint32_t srcIp;
        uint32_t dstIp;
        const uint16_t protoId;
        uint16_t tcpByteLen;
    };

    using OptionData = std::pair<int, std::string>; //Размер, текстовое название

    kivk_lib::Protocol tcpHeaderFormat{{
        {"srcPort", 16}, {"dstPort", 16},
        {"seqNumber", 32},
        {"ackNumber", 32},
        {"headerLength", 4}, {"reserver", 6}, {"urg", 1}, {"ack", 1}, {"psh", 1}, {"rst", 1}, {"syn", 1}, {"fin", 1}, {"windowSize", 16},
        {"chksum", 16}, {"urgent", 16}
    }};

    const static inline uint16_t defaultWindowSize = std::numeric_limits<int16_t>::max();
    const static std::unordered_map<Options, OptionData> optionsParams;

    //TODO Добавить поддержку опций (высокоуровневую)

    void setChksum(uint16_t newChksum);
    void updateChkSum(uint32_t srcIp, uint32_t dstIp, uint16_t lenTcp);
    uint32_t generateRandomNumber() const;
    uint16_t calcCheckSum_(uint16_t *buff, uint16_t buffByteSize) const;
};

#endif // TCP_HEADER_H

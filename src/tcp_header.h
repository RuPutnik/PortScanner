#ifndef TCP_HEADER_H
#define TCP_HEADER_H

#include <stdint-gcc.h>
#include <memory>

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

    TcpHeader();

    std::unique_ptr<const char[]> data() const;
    uint16_t length() const noexcept;

    uint16_t getSrcPort() const noexcept;
    void setSrcPort(uint16_t newSrcPort) noexcept;

    uint16_t getDstPort() const noexcept;
    void setDstPort(uint16_t newDstPort) noexcept;

    uint32_t getSeqNumber() const noexcept;
    void setSeqNumber(uint32_t newSeqNumber) noexcept;

    uint32_t getAckNumber() const noexcept;
    void setAckNumber(uint32_t newAckNumber) noexcept;

    uint8_t getHdrLen() const noexcept;
    void setHdrLen(uint8_t newHdrLen) noexcept;

    bool isUrg() const noexcept;
    bool isAck() const noexcept;
    bool isPsh() const noexcept;
    bool isRst() const noexcept;
    bool isSyn() const noexcept;
    bool isFin() const noexcept;

    uint8_t getFlags() const noexcept;
    void setFlags(uint8_t flags) noexcept;
    void resetFlags() noexcept;

    uint16_t getWindowSize() const noexcept;
    void setWindowSize(uint16_t newWindowSize) noexcept;

    uint16_t getChksum() const noexcept;
    void setChksum(uint16_t newChksum) noexcept;

    uint16_t getUrgent() const noexcept;
    void setUrgent(uint16_t newUrgent) noexcept;

    void debugHex() const;
    void debugBin() const;
    uint16_t calcCheckSum(uint32_t srcIp, uint32_t dstIp, uint16_t lenTcp) const;
    void updateChkSum(uint32_t srcIp, uint32_t dstIp, uint16_t lenTcp);

private:
    struct PseudoTcpHeader final
    {
        PseudoTcpHeader(uint32_t ipSource, uint32_t ipDestination, uint16_t tcpPacketLengthBytes);

        uint32_t srcIp;
        uint32_t dstIp;
        const uint16_t protoId;
        uint16_t tcpByteLen;
    };

    uint16_t srcPort;
    uint16_t dstPort;
    uint32_t seqNumber;
    uint32_t ackNumber;
    uint16_t hdrLenAndFlags; // hdrLen : 4 + reserved : 6 + urgBit + ackBit + pshBit + rstBit + synBit + finBit
    uint16_t windowSize;
    mutable uint16_t chksum;
    uint16_t urgent;

    //TODO Добавить поддержку опций (высокоуровневую)

    uint16_t hdrLenAndFlagsHE() const noexcept; //HE - Host Endian
    uint32_t generateRandomNumber() const;
    uint16_t calcCheckSum_(uint16_t *buff, uint16_t buffByteSize) const;
} __attribute__((packed));

#endif // TCP_HEADER_H

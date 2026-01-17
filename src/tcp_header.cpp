#include "tcp_header.h"

#include <QDebug>

#include <netinet/in.h>
#include <memory.h>
#include <random>
#include <chrono>

const std::unordered_map<TcpHeader::Options, TcpHeader::OptionData> TcpHeader::optionsParams
{
    {Options::EndOptions, {1, "End of Options List"}},
    {Options::NOP, {1, "NOP"}},
    {Options::MSS, {4, "Maximum Segment Size"}},
    {Options::WindowScaling, {3, "Window Scaling"}},
    {Options::SACK_Permitted, {2, "Selective ACK Permitted"}},
    {Options::SACK, {-1, "Selective ACK"}},
    {Options::Timestamps, {10, "Timestamps"}},
    {Options::FastOpen, {18, "TCP Fast Open"}}
};

TcpHeader::TcpHeader()
{
    setSeqNumber(generateRandomNumber());
    setWindowSize(defaultWindowSize);
    setHdrLen(static_cast<uint8_t>(lengthBytes() / sizeof(int32_t)));
}

std::unique_ptr<const char[]> TcpHeader::generateCompleteHeader(uint32_t srcIp, uint32_t dstIp, uint16_t lenTcp) const
{
    kivk_lib::Protocol finalProtocol = tcpHeaderFormat + generateOptionsPartHeader();

    char* const rawDataHeader = new char[finalProtocol.getLength()];

    updateChkSum(finalProtocol, srcIp, dstIp, lenTcp);

    memcpy(rawDataHeader, finalProtocol.getInternalBuffer(), finalProtocol.getLength());

    return std::unique_ptr<const char[]>{rawDataHeader};
}

uint16_t TcpHeader::lengthBytes() const noexcept
{
    return static_cast<uint16_t>(tcpHeaderFormat.getLength());
}

uint16_t TcpHeader::getSrcPort() const
{
    return tcpHeaderFormat.readFieldValue<uint16_t>("srcPort");
}

void TcpHeader::setSrcPort(uint16_t newSrcPort)
{
    tcpHeaderFormat.setFieldValue("srcPort", newSrcPort);
}

uint16_t TcpHeader::getDstPort() const
{
    return tcpHeaderFormat.readFieldValue<uint16_t>("dstPort");
}

void TcpHeader::setDstPort(uint16_t newDstPort)
{
    tcpHeaderFormat.setFieldValue("dstPort", newDstPort);
}

uint32_t TcpHeader::getSeqNumber() const
{
    return tcpHeaderFormat.readFieldValue<uint32_t>("seqNumber");
}

void TcpHeader::setSeqNumber(uint32_t newSeqNumber)
{
    tcpHeaderFormat.setFieldValue("seqNumber", newSeqNumber);
}

uint32_t TcpHeader::getAckNumber() const
{
    return tcpHeaderFormat.readFieldValue<uint32_t>("ackNumber");
}

void TcpHeader::setAckNumber(uint32_t newAckNumber)
{
    tcpHeaderFormat.setFieldValue("ackNumber", newAckNumber);
}

uint8_t TcpHeader::getHdrLen() const
{
    return tcpHeaderFormat.readFieldValue<uint8_t>("headerLength");
}

void TcpHeader::setHdrLen(uint8_t newHdrLen)
{
    if(newHdrLen > 0xF) //т.к. больше 4 бит по протоколу нельзя на размер использовать
        return;

    tcpHeaderFormat.setFieldValue("headerLength", newHdrLen);
}

bool TcpHeader::isUrg() const
{
    return tcpHeaderFormat.readFieldValue<bool>("urg");
}

bool TcpHeader::isAck() const
{
    return tcpHeaderFormat.readFieldValue<bool>("ack");
}

bool TcpHeader::isPsh() const
{
    return tcpHeaderFormat.readFieldValue<bool>("psh");
}

bool TcpHeader::isRst() const
{
    return tcpHeaderFormat.readFieldValue<bool>("rst");
}

bool TcpHeader::isSyn() const
{
    return tcpHeaderFormat.readFieldValue<bool>("syn");
}

bool TcpHeader::isFin() const
{
    return tcpHeaderFormat.readFieldValue<bool>("fin");
}

uint8_t TcpHeader::getFlags() const
{
    return tcpHeaderFormat.readGhostFieldValue<uint8_t>(106, 6); //Флаги начинаются со 106 бита
}

void TcpHeader::setFlags(uint8_t flags)
{
    tcpHeaderFormat.setGhostFieldValue(106, 6, flags);
}

void TcpHeader::resetFlags()
{
    setFlags(0);
}

uint16_t TcpHeader::getWindowSize() const
{
    return tcpHeaderFormat.readFieldValue<uint16_t>("windowSize");
}

void TcpHeader::setWindowSize(uint16_t newWindowSize)
{
    tcpHeaderFormat.setFieldValue("windowSize", newWindowSize);
}

uint16_t TcpHeader::getChksum(uint32_t srcIp, uint32_t dstIp, uint16_t lenTcp) const
{
    //Если опций у заголовка нет, просто берем текущую контрольную сумму
    if(headerOptions.empty()){
        return tcpHeaderFormat.readFieldValue<uint16_t>("chksum");
    }

    //Если есть опции, создаем полный заголовок, считаем его контрольную сумму
    kivk_lib::Protocol finalProtocol = tcpHeaderFormat + generateOptionsPartHeader();
    updateChkSum(finalProtocol, srcIp, dstIp, lenTcp);

    return finalProtocol.readFieldValue<uint16_t>("chksum");
}

void TcpHeader::setChksum(uint16_t newChksum)
{
    tcpHeaderFormat.setFieldValue("chksum", newChksum); //TODO Разобраться почему тут не нужно использовать htons
}

uint16_t TcpHeader::getUrgent() const
{
    return tcpHeaderFormat.readFieldValue<uint16_t>("urgent");
}

void TcpHeader::setUrgent(uint16_t newUrgent)
{
    tcpHeaderFormat.setFieldValue("urgent", newUrgent);
}

void TcpHeader::debugHex() const
{
    const auto fullHeader = tcpHeaderFormat + generateOptionsPartHeader();
    qDebug().noquote() << fullHeader.getDataVisualization(1, 4);
  /*  qDebug().noquote() << "-TCP--HDR-"; //TODO Доделать
    qDebug().noquote() << "0x" + QString::number(getSrcPort(), 16).rightJustified(4, '0') + QString::number(getDstPort(), 16).rightJustified(4, '0');
    qDebug().noquote() << "0x" + QString::number(getSeqNumber(), 16).rightJustified(8, '0');
    qDebug().noquote() << "0x" + QString::number(getAckNumber(), 16).rightJustified(8, '0');
    qDebug().noquote() << "0x" + QString::number(hdrLenAndFlagsHE(), 16).rightJustified(4, '0') + QString::number(getWindowSize(), 16).rightJustified(4, '0');
    qDebug().noquote() << "0x" + QString::number(getChksum(), 16).rightJustified(4, '0') + QString::number(getUrgent(), 16).rightJustified(4, '0');
    qDebug().noquote() << "----------";*/
}

void TcpHeader::debugBin() const
{
    const auto fullHeader = tcpHeaderFormat + generateOptionsPartHeader();
    qDebug().noquote() << fullHeader.getDataVisualization(1, 4, kivk_lib::Protocol::BASE::BIN);
   /* qDebug().noquote() << "----------"; //TODO Доделать
    qDebug().noquote() << "0b" + QString::number(getSrcPort(), 2).rightJustified(16, '0') + QString::number(getDstPort(), 2).rightJustified(16, '0');
    qDebug().noquote() << "0b" + QString::number(getSeqNumber(), 2).rightJustified(32, '0');
    qDebug().noquote() << "0b" + QString::number(getAckNumber(), 2).rightJustified(32, '0');
    qDebug().noquote() << "0b" + QString::number(hdrLenAndFlagsHE(), 2).rightJustified(16, '0') + QString::number(getWindowSize(), 2).rightJustified(16, '0');
    qDebug().noquote() << "0b" + QString::number(getChksum(), 2).rightJustified(16, '0') + QString::number(getUrgent(), 2).rightJustified(16, '0');
    qDebug().noquote() << "----------";*/
}

uint16_t TcpHeader::calcCheckSum(uint32_t srcIp, uint32_t dstIp, uint16_t lenTcp) const
{
    const PseudoTcpHeader pseudoHeader{srcIp, dstIp, lenTcp};

    const int sizePseudoTcpHeader = sizeof(PseudoTcpHeader) / 2;
    const uint16_t lenBuffDataPacket = sizePseudoTcpHeader + (lenTcp / 2);

    //Здесь будут храниться псевдозаголовок TCP и настоящий заголовок TCP, а так же по идее должны опции и данные
    const std::unique_ptr<uint16_t[]> buffDataPacket{new uint16_t[lenBuffDataPacket]};

    memcpy(buffDataPacket.get(), &pseudoHeader, sizeof(PseudoTcpHeader));
    //Преобразуем к void* т.к. нам нужно сместиться на размер PseudoTcpHeader в байтах
    memcpy(static_cast<void*>(buffDataPacket.get()) + sizeof(PseudoTcpHeader), tcpHeaderFormat.getInternalBuffer(), lenTcp);

    return htons(calcCheckSum_(buffDataPacket.get(), lenBuffDataPacket * 2));
}

bool TcpHeader::addOption(Options option, const OptionValues& values){
    if(headerOptions.find(option) != std::end(headerOptions))
        return false;


    headerOptions[option] = values;
    return true;
}

bool TcpHeader::setOptionValues(Options option, const OptionValues& values){
    if(headerOptions.find(option) == std::end(headerOptions))
        return false;

    headerOptions[option] = values;
    return true;
}

void TcpHeader::resetOptions()
{
    headerOptions.clear();
}

void TcpHeader::resetOption(Options option)
{
    headerOptions.erase(option);
}

std::string TcpHeader::getOptionsAsText() const
{
    std::string totalOptionsLine = "Options: (";

    for(const auto& [option, values] : headerOptions)
    {
        const std::string optionName = optionsParams.at(option).second;

        std::string optionValuesLine;
        for(const auto& currOptionValue : values){
            optionValuesLine += std::to_string(currOptionValue.value) + ", ";
        }

        optionValuesLine = optionValuesLine.substr(0, optionValuesLine.length() - 2);
        totalOptionsLine += optionName + ": {" + optionValuesLine + "}" + ", ";
    }

    totalOptionsLine = totalOptionsLine.substr(0, totalOptionsLine.length() - 2);
    totalOptionsLine += ")";

    return totalOptionsLine;
}

kivk_lib::Protocol TcpHeader::generateOptionsPartHeader() const
{
    return {};//TODO Сгенерировать итоговый заголовок с учётом Опций
}

uint16_t TcpHeader::calcCheckSum_(uint16_t* buff, uint16_t buffByteSize) const
{
    // Compute Internet Checksum for "buffSize" bytes
    // beginning at location "buff".

    int32_t sum = 0;

    while(buffByteSize > 1)  {
        sum += *(buff++);
        buffByteSize -= 2;
    }

    // Add left-over byte, if any
    if(buffByteSize > 0){
        sum += * (unsigned char *) buff;
    }

    // Fold 32-bit sum to 16 bits
    while(sum >> 16){
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return static_cast<uint16_t>(~sum);
}

void TcpHeader::updateChkSum(kivk_lib::Protocol& prot, uint32_t srcIp, uint32_t dstIp, uint16_t lenTcp) const
{
    prot.setFieldValue("chksum", calcCheckSum(srcIp, dstIp, lenTcp));
}

uint32_t TcpHeader::generateRandomNumber() const
{
    const auto time_since_epoch = std::chrono::high_resolution_clock::now().time_since_epoch();
    std::mt19937 engine;
    engine.seed(time_since_epoch.count());
    std::uniform_int_distribution<uint32_t> dist{1};
    return dist(engine);
}

TcpHeader::PseudoTcpHeader::PseudoTcpHeader(uint32_t ipSource, uint32_t ipDestination, uint16_t tcpPacketLengthBytes):
    srcIp{ipSource}, dstIp{ipDestination},
    protoId{htons(6)}, tcpByteLen{htons(tcpPacketLengthBytes)}
{}

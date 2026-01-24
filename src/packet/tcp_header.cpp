#include "tcp_header.h"

#include <QDebug>

#include <netinet/in.h>
#include <memory>
#include <random>
#include <chrono>

namespace network {

const std::unordered_map<TcpHeader::Options, TcpHeader::OptionData> TcpHeader::optionsParams
{
    {Options::EndOptions, {1, "End Options List"}},
    {Options::NOP, {1, "NOP"}},
    {Options::MSS, {4, "Maximum Segment Size"}},
    {Options::WindowScaling, {3, "Window Scaling"}},
    {Options::SACK_Permitted, {2, "Selective ACK Permitted"}},
    {Options::SACK, {-1, "Selective ACK"}},
    {Options::Timestamps, {10, "Timestamps"}},
    {Options::FastOpen, {18, "TCP Fast Open"}}
};

TcpHeader::TcpHeader(uint32_t sourceIp, uint32_t destinationIp):
    srcIp{sourceIp},
    dstIp{destinationIp},
    optionsFilled{false}
{
    setSeqNumber(generateRandomNumber());
    setWindowSize(defaultWindowSize);
}

std::unique_ptr<const char[]> TcpHeader::generateCompleteHeader(uint16_t lenTcpDataBytes)
{
    //TODO Учитывать данные пакета при расчете КС
    updateChkSum(lengthBytes());

    char* const rawDataHeader = new char[lengthBytes()];

    memcpy(rawDataHeader, tcpHeaderFormat.getInternalBuffer(), lengthBytes());

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

uint16_t TcpHeader::getChksum() const
{
    return tcpHeaderFormat.readFieldValue<uint16_t>("chksum");
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

void TcpHeader::debugHex(uint16_t lenTcpDataBytes) const
{
    qDebug().noquote() << "---TCP-HEADER---";
    qDebug().noquote() << "   SP     DP ";
    qDebug().noquote() << "0x" + QString::number(getSrcPort(), 16).rightJustified(4, '0') + " 0x" + QString::number(getDstPort(), 16).rightJustified(4, '0');

    qDebug().noquote() << "  SEQ NUM";
    qDebug().noquote() << "0x" + QString::number(getSeqNumber(), 16).rightJustified(8, '0');

    qDebug().noquote() << "  ACK NUM";
    qDebug().noquote() << "0x" + QString::number(getAckNumber(), 16).rightJustified(8, '0');

    qDebug().noquote() << "HDL FLAGS  WSIZE";
    qDebug().noquote() << "0x" + QString::number(getHdrLen(), 16).rightJustified(1, '0') + " 0x" +QString::number(getFlags(), 16).rightJustified(3, '0') + " 0x" +
                                 QString::number(getWindowSize(), 16).rightJustified(4, '0');

    qDebug().noquote() << " CHKS    URG ";
    qDebug().noquote() << "0x" + QString::number(getChksum(), 16).rightJustified(4, '0') + " 0x" + QString::number(getUrgent(), 16).rightJustified(4, '0');

    if(!headerOptions.empty()){
        qDebug().noquote() << " OPTIONS";

        for(uint32_t i = bitSize(20), end = bitSize(tcpHeaderFormat.getLength()); i < end; i+= bitSize<uint32_t>()){
            qDebug().noquote() << "0x" + QString::number(tcpHeaderFormat.readGhostFieldValue<uint32_t>(i, bitSize<uint32_t>()), 16).rightJustified(8, '0');
        }
    }

    qDebug().noquote() << "----------------";
}

void TcpHeader::debugBin(uint16_t lenTcpDataBytes) const
{
    qDebug().noquote() << "---------------TCP----HEADER---------------";

    qDebug().noquote() << "    SOURCE PORT         DEST PORT ";
    qDebug().noquote() << "0b" + QString::number(getSrcPort(), 2).rightJustified(16, '0') + " 0b" + QString::number(getDstPort(), 2).rightJustified(16, '0');

    qDebug().noquote() << "          SEQUENCE NUMBER      ";
    qDebug().noquote() << "0b" + QString::number(getSeqNumber(), 2).rightJustified(32, '0');

    qDebug().noquote() << "        ACKNOWLEDGEMENT NUM";
    qDebug().noquote() << "0b" + QString::number(getAckNumber(), 2).rightJustified(32, '0');

    qDebug().noquote() << "HD LEN RESERVED   UAPRSF     WINDOW SIZE";
    qDebug().noquote() << "0b" + QString::number(getHdrLen(), 2).rightJustified(4, '0') + " 0b000000" + " 0b" +QString::number(getFlags(), 2).rightJustified(6, '0') +
                         " 0b" + QString::number(getWindowSize(), 2).rightJustified(16, '0');

    qDebug().noquote() << "     CHECK SUMM           URGENT ";
    qDebug().noquote() << "0b" + QString::number(getChksum(), 2).rightJustified(16, '0') + " 0b" + QString::number(getUrgent(), 2).rightJustified(16, '0');

    if(!headerOptions.empty()){
        qDebug().noquote() << "             OPTIONS";

        for(uint32_t i = bitSize(20), end = bitSize(tcpHeaderFormat.getLength()); i < end; i+= bitSize<uint32_t>()){
            qDebug().noquote() << "0b" + QString::number(tcpHeaderFormat.readGhostFieldValue<uint32_t>(i, bitSize<uint32_t>()), 2).rightJustified(bitSize<uint32_t>(), '0');
        }
    }

    qDebug().noquote() << "-------------------------------------------";
}

uint16_t TcpHeader::calcCheckSum(uint32_t srcIp, uint32_t dstIp, uint16_t lenTcp) const
{
    const PseudoTcpHeader pseudoHeader{srcIp, dstIp, lenTcp};

    const uint16_t lenBytesBuffDataPacket = sizeof(PseudoTcpHeader) + lenTcp;

    //Здесь будут храниться псевдозаголовок TCP и настоящий заголовок TCP, а так же по идее должны опции и данные
    const std::unique_ptr<uint16_t[]> buffDataPacket{new uint16_t[lenBytesBuffDataPacket / 2]};

    memcpy(buffDataPacket.get(), &pseudoHeader, sizeof(PseudoTcpHeader));
    //Преобразуем к void* т.к. нам нужно сместиться на размер PseudoTcpHeader в байтах
    memcpy(reinterpret_cast<char*>(buffDataPacket.get()) + sizeof(PseudoTcpHeader), tcpHeaderFormat.getInternalBuffer(), lenTcp);

    return htons(calcCheckSum_(buffDataPacket.get(), lenBytesBuffDataPacket));
}

bool TcpHeader::addOption(Options option, const OptionValues& values, bool lastOption)
{
    if(optionsFilled){
        qDebug() << "Список опций уже сформирован";
        return false;
    }

    if(option == Options::NOP || option == Options::EndOptions){
        qDebug() << "Опции NOP и EndOptions являются служебными и запрещены к явному добавлению";
        return false;
    }

    if(headerOptions.find(option) != std::end(headerOptions))
        return false;

    headerOptions[option] = values;

    //Получаем информацию об опции
    auto [optionLenBytes, optionName] = optionsParams.at(option);

    if(option == Options::SACK){ //Для опции SACK считаем её размер исходя из количества блоков - значений, каждое по 8 байт
        optionLenBytes = std::accumulate(std::begin(values), std::end(values), 2, [](const auto accum, const auto& currValue){
            return accum + currValue.type;
        });
    }

    //Добавляем в протокол ячейки для записи кода и длины опции (в байтах)
    tcpHeaderFormat.appendField({optionName + optionIdProtFieldName, bitLenOptionId});
    tcpHeaderFormat.appendField({optionName + optionLenProtFieldName, bitLenOptionLen});

    //Устанавливаем значения кода и длины ячейки
    tcpHeaderFormat.setFieldValue(optionName + optionIdProtFieldName, static_cast<uint8_t>(option));
    tcpHeaderFormat.setFieldValue(optionName + optionLenProtFieldName, optionLenBytes);

    //Создаем и заполняем поля значений опций
    for(uint32_t i = 0; i < values.size(); i++){
        const auto& [lenValueBits, value] = values.at(i);
        tcpHeaderFormat.appendField({optionName + optionValProtFieldName + std::to_string(i), lenValueBits});
        tcpHeaderFormat.setFieldValue(optionName + optionValProtFieldName + std::to_string(i), value);
    }

    appendNopOptions(optionsParams.at(option));

    if(lastOption){
        appendEndOptionsBytes();
    }

    setHdrLen(static_cast<uint8_t>(lengthBytes() / sizeof(int32_t)));

    return true;
}

bool TcpHeader::setOptionValues(Options option, const OptionValues& values)
{
    //Тут нет защиты от некорректного количества параметров (или от количества, которое отличается от того, что было указано при добавлении опции)
    if(option == Options::NOP || option == Options::EndOptions){
        qDebug() << "Опции NOP и EndOptions являются служебными и запрещены к явному использованию";
        return false;
    }

    if(headerOptions.find(option) == std::end(headerOptions))
        return false;

    headerOptions[option] = values;

    const auto nameOption = optionsParams.at(option).second;

    for(uint32_t i = 0; i < values.size(); i++){
        const auto currValue = values.at(i).value;
        tcpHeaderFormat.setFieldValue(nameOption + optionValProtFieldName + std::to_string(i), currValue);
    }

    return true;
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

    if(!headerOptions.empty()){
        totalOptionsLine = totalOptionsLine.substr(0, totalOptionsLine.length() - 2);
    }
    totalOptionsLine += ")";

    return totalOptionsLine;
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

bool TcpHeader::containsOption(Options opt) const
{
    return headerOptions.find(opt) != headerOptions.end();
}

void TcpHeader::appendNopOptions(const OptionData& option)
{
    //Получаем информацию об опции
    const auto [optionLenBytes, optionName] = option;

    //Расчитываем количество NOP для выравнивания к 4 байтам опции и добавляем их
    const int nearDivWithoutRemainder = calcNearDivisibleWithoutRemainder(optionLenBytes);
    const int amountNOP = nearDivWithoutRemainder - optionLenBytes;

    for(int i = 0; i < amountNOP; i++){
        tcpHeaderFormat.appendField({"nop_" + std::to_string(i) + "_" + optionName, bitSize<uint8_t>()});
        tcpHeaderFormat.setFieldValue("nop_" + std::to_string(i) + "_" + optionName, static_cast<uint8_t>(Options::NOP));
    }
}

void TcpHeader::appendEndOptionsBytes()
{
    optionsFilled = true;

    if(tcpHeaderFormat.getLength() < maxTcpHeaderLenBytes)
    {
        //Если это была последняя опция и в заголовке еще есть место, добавляем опцию конца списка опций и Padding, выравнивая заголовок до конца 32-битного слова
        tcpHeaderFormat.appendField({optionsParams.at(Options::EndOptions).second, bitSize<uint32_t>()});
        tcpHeaderFormat.setFieldValue(optionsParams.at(Options::EndOptions).second, static_cast<uint8_t>(Options::EndOptions));
    }
}

int TcpHeader::calcNearDivisibleWithoutRemainder(int value, int delimeter)
{
    int nearestDivisible = value;

    while((nearestDivisible % delimeter) != 0){
        nearestDivisible++;
    }

    return nearestDivisible;
}

void TcpHeader::updateChkSum(uint16_t lenTcp)
{
    tcpHeaderFormat.setFieldValue("chksum", calcCheckSum(srcIp, dstIp, lenTcp));
}

uint32_t TcpHeader::generateRandomNumber() const
{
    const auto time_since_epoch = std::chrono::steady_clock::now().time_since_epoch();
    std::mt19937 engine;
    engine.seed(static_cast<uint32_t>(time_since_epoch.count()));
    std::uniform_int_distribution<uint32_t> dist{1};
    return dist(engine);
}

TcpHeader::PseudoTcpHeader::PseudoTcpHeader(uint32_t ipSource, uint32_t ipDestination, uint16_t tcpPacketLengthBytes):
    srcIp{ipSource}, dstIp{ipDestination},
    protoId{htons(6)}, tcpByteLen{htons(tcpPacketLengthBytes)}
{}

}

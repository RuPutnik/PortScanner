#include "tcp_header.h"

#include <netinet/in.h>
#include <memory>
#include <numeric>

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

TcpHeader::TcpHeader(const std::string &sourceIp, const std::string &destinationIp):
    IHeader{sourceIp, destinationIp, {{
            {"srcPort", 16}, {"dstPort", 16},
            {"seqNumber", 32},
            {"ackNumber", 32},
            {"headerLength", 4}, {"reserver", 6}, {"urg", 1}, {"ack", 1}, {"psh", 1}, {"rst", 1}, {"syn", 1}, {"fin", 1}, {"windowSize", 16},
            {"chksum", 16}, {"urgent", 16}
        }}},
    optionsFilled{false}
{
    setSeqNumber(generateRandomNumber<uint32_t>());
    setWindowSize(defaultWindowSize);
    setHdrLen(static_cast<uint8_t>(lengthBytes() / sizeof(int32_t)));
}

TcpHeader::TcpHeader(uint32_t sourceIp, uint32_t destinationIp):
    TcpHeader{"", ""}
{
    ipAdresses = {sourceIp, destinationIp};
}

std::unique_ptr<const char[]> TcpHeader::generateCompleteHeader(const std::shared_ptr<char[]>& payload, uint32_t payloadLenBytes)
{
    headerFormat.setFieldValue("chksum", calcCheckSum(payload, payloadLenBytes));

    char* const rawDataHeader = new char[lengthBytes()];

    memcpy(rawDataHeader, headerFormat.getInternalBuffer(), lengthBytes());

    return std::unique_ptr<const char[]>{rawDataHeader};
}

uint16_t TcpHeader::getSrcPort() const
{
    return headerFormat.readFieldValue<uint16_t>("srcPort");
}

void TcpHeader::setSrcPort(uint16_t newSrcPort)
{
    headerFormat.setFieldValue("srcPort", newSrcPort);
}

uint16_t TcpHeader::getDstPort() const
{
    return headerFormat.readFieldValue<uint16_t>("dstPort");
}

void TcpHeader::setDstPort(uint16_t newDstPort)
{
    headerFormat.setFieldValue("dstPort", newDstPort);
}

uint32_t TcpHeader::getSeqNumber() const
{
    return headerFormat.readFieldValue<uint32_t>("seqNumber");
}

void TcpHeader::setSeqNumber(uint32_t newSeqNumber)
{
    headerFormat.setFieldValue("seqNumber", newSeqNumber);
}

uint32_t TcpHeader::getAckNumber() const
{
    return headerFormat.readFieldValue<uint32_t>("ackNumber");
}

void TcpHeader::setAckNumber(uint32_t newAckNumber)
{
    headerFormat.setFieldValue("ackNumber", newAckNumber);
}

uint8_t TcpHeader::getHdrLen() const
{
    return headerFormat.readFieldValue<uint8_t>("headerLength");
}

void TcpHeader::setHdrLen(uint8_t newHdrLen)
{
    if(newHdrLen > 0xF) //т.к. больше 4 бит по протоколу нельзя на размер использовать
        return;

    headerFormat.setFieldValue("headerLength", newHdrLen);
}

bool TcpHeader::isUrg() const
{
    return headerFormat.readFieldValue<bool>("urg");
}

bool TcpHeader::isAck() const
{
    return headerFormat.readFieldValue<bool>("ack");
}

bool TcpHeader::isPsh() const
{
    return headerFormat.readFieldValue<bool>("psh");
}

bool TcpHeader::isRst() const
{
    return headerFormat.readFieldValue<bool>("rst");
}

bool TcpHeader::isSyn() const
{
    return headerFormat.readFieldValue<bool>("syn");
}

bool TcpHeader::isFin() const
{
    return headerFormat.readFieldValue<bool>("fin");
}

uint8_t TcpHeader::getFlags() const
{
    return headerFormat.readGhostFieldValue<uint8_t>(106, 6); //Флаги начинаются со 106 бита
}

void TcpHeader::setFlags(uint8_t flags)
{
    headerFormat.setGhostFieldValue(106, 6, flags);
}

void TcpHeader::resetFlags()
{
    setFlags(0);
}

uint16_t TcpHeader::getWindowSize() const
{
    return headerFormat.readFieldValue<uint16_t>("windowSize");
}

void TcpHeader::setWindowSize(uint16_t newWindowSize)
{
    headerFormat.setFieldValue("windowSize", newWindowSize);
}

uint16_t TcpHeader::getChksum() const
{
    return headerFormat.readFieldValue<uint16_t>("chksum");
}

void TcpHeader::setChksum(uint16_t newChksum)
{
    headerFormat.setFieldValue("chksum", newChksum);
}

uint16_t TcpHeader::getUrgent() const
{
    return headerFormat.readFieldValue<uint16_t>("urgent");
}

void TcpHeader::setUrgent(uint16_t newUrgent)
{
    headerFormat.setFieldValue("urgent", newUrgent);
}

void TcpHeader::debugHex() const
{
    printf("---TCP-HEADER---\n");
    printf("   SP     DP \n");
    printf("0x%04X 0x%04X\n", getSrcPort(), getDstPort());

    printf("  SEQ NUM\n");
    printf("0x%08X\n", getSeqNumber());

    printf("  ACK NUM\n");
    printf("0x%08X\n", getAckNumber());

    printf("HDL FLAGS  WSIZE\n");
    printf("0x%01X 0x%03X 0x%04X\n", getHdrLen(), getFlags(), getWindowSize());

    printf(" CHKS    URG \n");
    printf("0x%04X 0x%04X\n", getChksum(), getUrgent());

    if(!headerOptions.empty()){
        printf(" OPTIONS\n");

        for(uint64_t i = bitSize(minIpHeaderLenBytes), end = bitSize(headerFormat.getLength()); i < end; i+= bitSize<uint32_t>()){
            printf("0x%08X\n", headerFormat.readGhostFieldValue<uint32_t>(static_cast<uint32_t>(i), bitSize<uint32_t>()));
        }
    }

    printf("----------------");
}

void TcpHeader::debugBin() const
{
    std::cout << headerFormat.getBinaryVisualization(true, 1, 2, 1, 32, true) << std::endl;
}

bool TcpHeader::addOption(Options option, const OptionValues& values, bool lastOption)
{
    if(optionsFilled){
        std::cout << "Список опций уже сформирован" << std::endl;
        return false;
    }

    if(option == Options::NOP || option == Options::EndOptions){
        std::cout << "Опции NOP и EndOptions являются служебными и запрещены к явному добавлению" << std::endl;
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
    headerFormat.appendField({optionName + optionIdProtFieldName, bitLenOptionId});
    headerFormat.appendField({optionName + optionLenProtFieldName, bitLenOptionLen});

    //Устанавливаем значения кода и длины ячейки
    headerFormat.setFieldValue(optionName + optionIdProtFieldName, static_cast<uint8_t>(option));
    headerFormat.setFieldValue(optionName + optionLenProtFieldName, optionLenBytes);

    //Создаем и заполняем поля значений опций
    for(uint32_t i = 0; i < values.size(); i++){
        const auto& [lenValueBits, value] = values.at(i);
        headerFormat.appendField({optionName + optionValProtFieldName + std::to_string(i), lenValueBits});
        headerFormat.setFieldValue(optionName + optionValProtFieldName + std::to_string(i), value);
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
        std::cout << "Опции NOP и EndOptions являются служебными и запрещены к явному использованию" << std::endl;
        return false;
    }

    if(headerOptions.find(option) == std::end(headerOptions))
        return false;

    headerOptions[option] = values;

    const auto nameOption = optionsParams.at(option).second;

    for(uint32_t i = 0; i < values.size(); i++){
        const auto currValue = values.at(i).value;
        headerFormat.setFieldValue(nameOption + optionValProtFieldName + std::to_string(i), currValue);
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
        headerFormat.appendField({"nop_" + std::to_string(i) + "_" + optionName, bitSize<uint8_t>()});
        headerFormat.setFieldValue("nop_" + std::to_string(i) + "_" + optionName, static_cast<uint8_t>(Options::NOP));
    }
}

void TcpHeader::appendEndOptionsBytes()
{
    optionsFilled = true;

    if(headerFormat.getLength() < maxTcpHeaderLenBytes)
    {
        //Если это была последняя опция и в заголовке еще есть место, добавляем опцию конца списка опций и Padding, выравнивая заголовок до конца 32-битного слова
        headerFormat.appendField({optionsParams.at(Options::EndOptions).second, bitSize<uint32_t>()});
        headerFormat.setFieldValue(optionsParams.at(Options::EndOptions).second, static_cast<uint8_t>(Options::EndOptions));
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

bool TcpHeader::considerPseudoHeaderCalcCksum() const
{
    return true;
}

uint32_t TcpHeader::maxPayloadLengthBytes() const
{
    return maxTransportPacketLenBytes - TcpHeader::maxTcpHeaderLenBytes; // = 1420 байт, 355 слов (4 байта)
}

uint16_t TcpHeader::getProtoId() const
{
    return IPPROTO_TCP;
}

uint16_t TcpHeader::setHeaderData(const std::vector<unsigned char>& dataPacket)
{
    headerFormat.setInternalBufferValues(dataPacket.data());

    const uint16_t incomingHeaderLenBytes = getHdrLen() * netWordByteLen;

    //Если длина заголовка, прочитанная из входящих данных больше длины стандартного заголовка без опций
    if(incomingHeaderLenBytes > headerFormat.getLength())
    {
        const uint16_t totalOptionLenBits = static_cast<uint16_t>(network::bitSize(incomingHeaderLenBytes - headerFormat.getLength()));
        headerFormat.appendField({"options", totalOptionLenBits});
        headerFormat.setInternalBufferValues(dataPacket.data());
    }

    return incomingHeaderLenBytes;
}

std::shared_ptr<IHeader> TcpHeader::clone()
{
    return std::shared_ptr<TcpHeader>(new TcpHeader(*this));
}

}

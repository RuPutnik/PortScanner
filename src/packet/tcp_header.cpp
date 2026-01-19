#include "tcp_header.h"

#include <QDebug>

#include <netinet/in.h>
#include <memory.h>
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
    dstIp{destinationIp}
{
    setSeqNumber(generateRandomNumber());
    setWindowSize(defaultWindowSize);
    setHdrLen(static_cast<uint8_t>(lengthBytes() / sizeof(int32_t)));
}

std::unique_ptr<const char[]> TcpHeader::generateCompleteHeader(uint16_t lenTcpDataBytes) const
{
    kivk_lib::Protocol finalProtocol = tcpHeaderFormat + generateOptionsPartHeader();

    char* const rawDataHeader = new char[finalProtocol.getLength()];

    updateChkSum(finalProtocol, lengthBytes() + lenTcpDataBytes);

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

uint16_t TcpHeader::getChksum(uint16_t lenTcp) const
{
    kivk_lib::Protocol finalProtocol = tcpHeaderFormat;

    if(!headerOptions.empty()){
        //Если есть опции, создаем полный заголовок
        finalProtocol = finalProtocol + generateOptionsPartHeader();
    }

    //считаем его контрольную сумму
    updateChkSum(finalProtocol, lenTcp);

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
    qDebug().noquote() << "0x" + QString::number(getHdrLen(), 16).rightJustified(1, '0') + " 0x" +QString::number(getFlags(), 16).rightJustified(3, '0') + " 0x" + QString::number(getWindowSize(), 16).rightJustified(4, '0');

    qDebug().noquote() << " CHKS    URG ";
    qDebug().noquote() << "0x" + QString::number(getChksum(lengthBytes() + lenTcpDataBytes), 16).rightJustified(4, '0') + " 0x" + QString::number(getUrgent(), 16).rightJustified(4, '0');

    if(!headerOptions.empty()){
        const auto optionsProtocol = generateOptionsPartHeader();

        qDebug().noquote() << " OPTIONS";

        for(int i = 0, end = 8 * optionsProtocol.getLength(); i < end; i+= (8 * sizeof(uint32_t))){
            qDebug().noquote() << "0x" + QString::number(optionsProtocol.readGhostFieldValue<uint32_t>(i, 8 * sizeof(uint32_t)), 16).rightJustified(8, '0');
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
    qDebug().noquote() << "0b" + QString::number(getHdrLen(), 2).rightJustified(4, '0') + " 0b000000" + " 0b" +QString::number(getFlags(), 2).rightJustified(6, '0') + " 0b" +QString::number(getWindowSize(), 2).rightJustified(16, '0');

    qDebug().noquote() << "     CHECK SUMM           URGENT ";
    qDebug().noquote() << "0b" + QString::number(getChksum(lengthBytes() + lenTcpDataBytes), 2).rightJustified(16, '0') + " 0b" + QString::number(getUrgent(), 2).rightJustified(16, '0');

    if(!headerOptions.empty()){
        const auto optionsProtocol = generateOptionsPartHeader();

        qDebug().noquote() << "             OPTIONS";
//TODO Везде использовать bitSize
        for(int i = 0, end = 8 * optionsProtocol.getLength(); i < end; i+= bitSize<uint32_t>()){
            qDebug().noquote() << "0b" + QString::number(optionsProtocol.readGhostFieldValue<uint32_t>(i, 8 * sizeof(uint32_t)), 2).rightJustified(32, '0');
        }
    }

    qDebug().noquote() << "-------------------------------------------";
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
    //TODO Добавить защиту от добавления NOP и EndOptions

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

    if(!headerOptions.empty()){
        totalOptionsLine = totalOptionsLine.substr(0, totalOptionsLine.length() - 2);
    }
    totalOptionsLine += ")";

    return totalOptionsLine;
}

kivk_lib::Protocol TcpHeader::generateOptionsPartHeader() const
{
    kivk_lib::Protocol optionsPartHeader;

    const uint8_t nopCode = static_cast<uint8_t>(Options::NOP);
    const uint32_t nopLength = bitSize(optionsParams.at(Options::NOP).first);

    for(const auto& [option, values] : headerOptions)
    {
        const auto& [byteLength, name] = optionsParams.at(option);

        optionsPartHeader.appendField({name + "_id", 8}); //TODO Все явные значения спрятать в константы
        optionsPartHeader.appendField({name + "_len", 8});

        optionsPartHeader.setFieldValue(name + "_id", static_cast<uint8_t>(option));
        optionsPartHeader.setFieldValue(name + "_len", byteLength);

        //Создаем и заполняем поля значений опций
        for(int i = 0; i < values.size(); i++){
            const auto& [lenValueBits, value] = values.at(i);
            optionsPartHeader.appendField({name + "_value_" + std::to_string(i), lenValueBits});
            optionsPartHeader.setFieldValue(name + "_value_" + std::to_string(i), value);
        }

        //Проставляем NOP-ы
        //TODO Попытаться сделать эти действия автоматом без явного указания по типу
        switch (option) {
        case Options::MSS:
            break;
        case Options::WindowScaling:
            optionsPartHeader.appendField({"nop_1_" + name, nopLength});
            optionsPartHeader.setFieldValue("nop_1_" + name, nopCode);
            break;
        case Options::SACK_Permitted:
            optionsPartHeader.appendField({"nop_1_" + name, nopLength});
            optionsPartHeader.setFieldValue("nop_1_" + name, nopCode);

            optionsPartHeader.appendField({"nop_2_" + name, nopLength});
            optionsPartHeader.setFieldValue("nop_2_" + name, nopCode);
            break;
        case Options::SACK:
            //TODO
            continue;
        case Options::Timestamps:
            optionsPartHeader.appendField({"nop_1_" + name, nopLength});
            optionsPartHeader.setFieldValue("nop_1_" + name, nopCode);

            optionsPartHeader.appendField({"nop_2_" + name, nopLength});
            optionsPartHeader.setFieldValue("nop_2_" + name, nopCode);
            break;
        case Options::FastOpen:
            optionsPartHeader.appendField({"nop_1_" + name, nopLength});
            optionsPartHeader.setFieldValue("nop_1_" + name, nopCode);

            optionsPartHeader.appendField({"nop_2_" + name, nopLength});
            optionsPartHeader.setFieldValue("nop_2_" + name, nopCode);
            break;
        default:
            throw std::runtime_error{"Неизвестный тип опции"};
            break;
        }
    }
    //TODO Добавить выравнивание Padding до 4 байт
    //TODO Учитывать максимальный размер заголовка, сделать константу на эту тему

    return optionsPartHeader;//TODO Сгенерировать итоговый заголовок с учётом Опций
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

void TcpHeader::updateChkSum(kivk_lib::Protocol& prot, uint16_t lenTcp) const
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

}

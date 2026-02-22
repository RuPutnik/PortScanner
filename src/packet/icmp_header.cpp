#include "icmp_header.h"

#include <QDebug>

#include <sys/time.h>

namespace network {

IcmpHeader::IcmpHeader(Type type):
    IHeader{std::nullopt, {{
        {"type", 8}, {"code", 8}, {"chksum", 16},
        {"identifier", 16}, {"seqNumber", 16}
    }}}
{
    if(type > Type::Unknown){
        setType(type);
    }

    setCode(0);
    setIdentifier(generateRandomNumber<uint16_t>());
    setSeqNumber(0);

    switch (type) {
    case Type::EchoRequest:{
        //Добавляем временную метку
        headerFormat.appendField({"timestamp1", bitSize<__time_t>()});
        headerFormat.appendField({"timestamp2", bitSize<__suseconds_t>()});

        const timeval tv = getTimestampLabel();

        headerFormat.setFieldValue("timestamp1", tv.tv_sec);
        headerFormat.setFieldValue("timestamp2", tv.tv_usec);

        break;
    }
    default:
        break;
    }
}

std::unique_ptr<const char[]> network::IcmpHeader::generateCompleteHeader(const std::shared_ptr<char[]>& payload, uint32_t payloadLenBytes)
{
    headerFormat.setFieldValue("chksum", calcCheckSum(payload, payloadLenBytes));

    char* const rawDataHeader = new char[lengthBytes()];

    memcpy(rawDataHeader, headerFormat.getInternalBuffer(), lengthBytes());

    return std::unique_ptr<const char[]>{rawDataHeader};
}

uint32_t network::IcmpHeader::maxPayloadLengthBytes() const
{
    return network::maxTransportPacketLenBytes - headerFormat.getLength();
}

void network::IcmpHeader::debugHex() const
{
    qDebug().noquote() << "---ICMP-HEADER---";
    qDebug().noquote() << " TYP  CODE   CHKS ";
    qDebug().noquote() << "0x" + QString::number(static_cast<int>(getType()), 16).rightJustified(2, '0') +
                          "  0x" + QString::number(getCode(), 16).rightJustified(2, '0') +
                          "  0x" + QString::number(getChksum(), 16).rightJustified(4, '0');
    qDebug().noquote() << " IDEN  SEQNUM ";
    qDebug().noquote() << "0x" + QString::number(getIdentifier(), 16).rightJustified(4, '0') + " 0x" + QString::number(getSeqNumber(), 16).rightJustified(4, '0');
    qDebug().noquote() << "-----------------";
}

void network::IcmpHeader::debugBin() const
{
    qDebug().noquote() << "--------------ICMP----HEADER---------------";
    qDebug().noquote() << "    TYPE      CODE        CHECK SUMM ";
    qDebug().noquote() << "0b" + QString::number(static_cast<int>(getType()), 2).rightJustified(8, '0') +
                          " 0b" + QString::number(getCode(), 2).rightJustified(8, '0') +
                          " 0b" + QString::number(getChksum(), 2).rightJustified(16, '0');
    qDebug().noquote() << "    IDENTIFIER      SEQUENCE NUMBER ";
    qDebug().noquote() << "0b" + QString::number(getIdentifier(), 2).rightJustified(16, '0') + " 0b" + QString::number(getSeqNumber(), 2).rightJustified(16, '0');
    qDebug().noquote() << "-------------------------------------------";
}

IcmpHeader::Type IcmpHeader::getType() const
{
    return static_cast<Type>(headerFormat.readFieldValue<uint8_t>("type"));
}

void IcmpHeader::setType(Type t)
{
    headerFormat.setFieldValue("type", static_cast<uint8_t>(t));
}

uint8_t IcmpHeader::getCode() const
{
    return headerFormat.readFieldValue<uint8_t>("code");
}

void IcmpHeader::setCode(uint8_t c)
{
    headerFormat.setFieldValue("code", c);
}

uint16_t IcmpHeader::getChksum() const
{
    return headerFormat.readFieldValue<uint16_t>("chksum");
}

void IcmpHeader::setChksum(uint16_t chksum)
{
    headerFormat.setFieldValue("chksum", chksum);
}

uint16_t IcmpHeader::getIdentifier() const
{
    return headerFormat.readFieldValue<uint16_t>("identifier");
}

void IcmpHeader::setIdentifier(uint16_t iden)
{
    headerFormat.setFieldValue("identifier", iden);
}

uint16_t IcmpHeader::getSeqNumber() const
{
    return headerFormat.readFieldValue<uint16_t>("seqNumber");
}

void IcmpHeader::setSeqNumber(uint16_t seqNumber)
{
    headerFormat.setFieldValue("seqNumber", seqNumber);
}

uint16_t IcmpHeader::getProtoId() const
{
    return IPPROTO_ICMP;
}

std::string IcmpHeader::getTextCode() const
{
    switch (getType())
    {
    case Type::EchoReply:
        if(getCode()){
            return "Эхо-ответ";
        }
        break;
    case Type::UnreachableDestNode:
        switch(getCode()){
        case 0:
            return "Сеть недостижима";
        case 1:
            return "Узел недостижим";
        case 2:
            return "Протокол недостижим";
        case 3:
            return "Порт недостижим";
        case 4:
            return "Необходима фрагментация, но установлен флаг её запрета (DF)";
        case 5:
            return "Неверный маршрут от источника";
        case 6:
            return "Сеть назначения неизвестна";
        case 7:
            return "Узел назначения неизвестен";
        case 8:
            return "Узел-источник изолирован";
        case 9:
            return "Сеть административно запрещена";
        case 10:
            return "Узел административно запрещен";
        case 11:
            return "Сеть недоступна для ToS";
        case 12:
            return "Узел недоступен для Tos";
        case 13:
            return "Коммуникации административно запрещены";
        case 14:
            return "Нарушение порядка предпочтения узлов";
        case 15:
            return "Активно отсечение порядка предпочтения";
        }
        break;
    case Type::SourceSuppression:
        if(getCode() == 0){
            return "Сдерживание источника";
        }
        break;
    case Type::RouteRedirection:
        switch (getCode()) {
        case 0:
            return "Перенаправление пакетов в сеть";
        case 1:
            return "Перенаправление пакетов к узлу";
        case 2:
            return "Перенаправление для каждого типа обслуживания (ToS)";
        case 3:
            return "Перенаправление пакета к узлу для каждого типа обслуживания";
        }
        break;
    case Type::EchoRequest:
        if(getCode() == 0){
            return "Эхо-запрос";
        }
        break;
    case Type::TimeExceeded:
        switch (getCode()) {
        case 0:
            return "Время жизни пакета (TTL) истекло при транспортировке";
        case 1:
            return "Время жизни пакета истекло при сборке фрагментов";
        }
        break;
    case Type::ParameterProblem:
        switch (getCode()) {
        case 0:
            return "Указатель говорит об ошибке";
        case 1:
            return "Отсутствует требуемая опция";
        case 2:
            return "Некорректная длина";
        }
        break;
    case Type::TimestampRequest:
        if(getCode() == 0){
            return "Запрос метки времени";
        }
        break;
    case Type::TimestampReply:
        if(getCode() == 0){
            return "Ответ с меткой времени";
        }
        break;
    case Type::InfoRequest:
        if(getCode() == 0){
            return "Информационный запрос";
        }
        break;
    case Type::InfoReply:
        if(getCode() == 0){
            return "Информационный ответ";
        }
        break;
    }

    return "";
}

timeval IcmpHeader::getTimestampLabel()
{
    timeval tv{0, 0};

    gettimeofday(&tv, nullptr);

    return tv;
}

uint32_t IcmpHeader::setHeaderData(const std::vector<unsigned char>& dataPacket)
{

}

}



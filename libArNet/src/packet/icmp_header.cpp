#include "icmp_header.h"

#include <sys/time.h>

namespace network {

IcmpHeader::IcmpHeader(Type type):
    IcmpHeader{{}, {}, type}
{}

IcmpHeader::IcmpHeader(const std::string& sourceIp, const std::string& destinationIp, Type type):
    IHeader{sourceIp, destinationIp, {{
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

IcmpHeader::IcmpHeader(uint32_t sourceIp, uint32_t destinationIp, Type type):
    IcmpHeader{"", "", type}
{
    ipAdresses = {sourceIp, destinationIp};
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
    printf("---ICMP-HEADER---\n");
    printf(" TYP  CODE   CHKS \n");
    printf("0x%02X  0x%02X  0x%04X\n", static_cast<int>(getType()), getCode(), getChksum());
    printf(" IDEN  SEQNUM \n");
    printf("0x%04X 0x%04X\n", getIdentifier(), getSeqNumber());
    printf("-----------------\n");
}

void network::IcmpHeader::debugBin() const
{
    std::cout << headerFormat.getBinaryVisualization(true, 1, 2, 1, 32, true) << std::endl;
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
        case ICMP_NET_UNREACH:
            return "Сеть недостижима";
        case ICMP_HOST_UNREACH:
            return "Узел недостижим";
        case ICMP_PROT_UNREACH:
            return "Протокол недостижим";
        case ICMP_PORT_UNREACH:
            return "Порт недостижим";
        case ICMP_FRAG_NEEDED:
            return "Необходима фрагментация, но установлен флаг её запрета (DF)";
        case ICMP_SR_FAILED:
            return "Неверный маршрут от источника";
        case ICMP_NET_UNKNOWN:
            return "Сеть назначения неизвестна";
        case ICMP_HOST_UNKNOWN:
            return "Узел назначения неизвестен";
        case ICMP_HOST_ISOLATED:
            return "Узел-источник изолирован";
        case ICMP_NET_ANO:
            return "Сеть административно запрещена";
        case ICMP_HOST_ANO:
            return "Узел административно запрещен";
        case ICMP_NET_UNR_TOS:
            return "Сеть недоступна для ToS";
        case ICMP_HOST_UNR_TOS:
            return "Узел недоступен для Tos";
        case ICMP_PKT_FILTERED:
            return "Коммуникации административно запрещены";
        case ICMP_PREC_VIOLATION:
            return "Нарушение порядка предпочтения узлов";
        case ICMP_PREC_CUTOFF:
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
        case ICMP_REDIR_NET:
            return "Перенаправление пакетов в сеть";
        case ICMP_REDIR_HOST:
            return "Перенаправление пакетов к узлу";
        case ICMP_REDIR_NETTOS:
            return "Перенаправление для каждого типа обслуживания (ToS)";
        case ICMP_REDIR_HOSTTOS:
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
        case ICMP_EXC_TTL:
            return "Время жизни пакета (TTL) истекло при транспортировке";
        case ICMP_EXC_FRAGTIME:
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

    default:
        return "";
    }

    return "";
}

timeval IcmpHeader::getTimestampLabel()
{
    timeval tv{0, 0};

    gettimeofday(&tv, nullptr);

    return tv;
}

uint16_t IcmpHeader::setHeaderData(const std::vector<unsigned char>& dataPacket)
{
    //Тут мы не учитываем возможные опции, так как от того, что эти данные могут уйти в полезную нагрузку никакого вреда нет
    headerFormat.setInternalBufferValues(dataPacket.data());
    return static_cast<uint16_t>(headerFormat.getLength());
}

bool IcmpHeader::considerPseudoHeaderCalcCksum() const
{
    return false;
}

std::shared_ptr<IHeader> IcmpHeader::clone()
{
    return std::shared_ptr<IcmpHeader>(new IcmpHeader(*this));
}

}



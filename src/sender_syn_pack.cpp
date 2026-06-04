#include "sender_syn_pack.h"

#include <QThread>
#include <QSet>

#include <sr.h>
#include <tcp_header.h>

#include "settings_reader.h"
#include "scanner_logger.h"

SenderSynPack::SenderSynPack(const QSet<Task>& tasks_, QObject *parent)
    : QObject{parent},
    tasks{tasks_}
{}

void SenderSynPack::onRunSendSyn()
{
    const auto settings = SettingsReader::getSettings();
    if(!settings){
        ScannerLogger::logging("Ошибка чтения настроек!");
        return;
    }

    bool hasActualTasks = false;
    const uint32_t hostIp = network::textIpV4ToUint(network::getCurrentIpAddress());

    for(int i = 0; i < settings->getAmountAttempt(); i++)
    {
        for(const auto& currTask : tasks)
        {
            if(currTask.finished)
                continue;

            hasActualTasks = true;

            auto tcpSynHeader = std::make_shared<network::TcpHeader>(hostIp, currTask.ip);
            tcpSynHeader->setDstPort(currTask.port);
            if(settings->getSrcPort() == 0){
                tcpSynHeader->setSrcPort(currTask.port);
            }
            else
            {
                tcpSynHeader->setSrcPort(settings->getSrcPort());
            }
            tcpSynHeader->setAckNumber(settings->getAckNumber());
            tcpSynHeader->setWindowSize(settings->getWindowSize());
            tcpSynHeader->setUrgent(settings->getUrgent());
            tcpSynHeader->setFlags(network::TcpHeader::SYN);
            tcpSynHeader->addOption(network::TcpHeader::Options::MSS, {{network::TcpHeader::OptionValue::UINT16, settings->getMss()}});

            if(settings->isSackPermitted()){
                tcpSynHeader->addOption(network::TcpHeader::Options::SACK_Permitted);
            }

            network::NetPacket synPacket{tcpSynHeader};

            //TODO Отсылаем пакет SYN

            QThread::msleep(settings->getTimeIntervalSendSyn());
        }

        if(!hasActualTasks){
            return;
        }

        hasActualTasks = false;
        QThread::msleep(settings->getTimeIntervalAttempt());
    }
}

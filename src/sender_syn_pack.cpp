#include "sender_syn_pack.h"

#include <QThread>
#include <QSet>

#include <sr.h>
#include <tcp_header.h>

#include "settings_scanner.h"

SenderSynPack::SenderSynPack(const QSet<Task>& tasks_, QObject *parent)
    : QObject{parent},
    tasks{tasks_}
{}

void SenderSynPack::onRunSendSyn()
{
    const auto settings = SettingsScanner::getSettings();
    bool hasActualTasks = false;
    const uint32_t hostIp = network::textIpV4ToUint(network::getCurrentIpAddress());

    for(int i = 0; i < settings.getAmountAttempt(); i++)
    {
        for(const auto& currTask : tasks)
        {
            if(currTask.finished)
                continue;

            hasActualTasks = true;

            auto tcpSynHeader = std::make_shared<network::TcpHeader>(hostIp, currTask.ip);
            tcpSynHeader->setDstPort(currTask.port);
            tcpSynHeader->setSrcPort(currTask.port);
            tcpSynHeader->setSeqNumber(1);
            tcpSynHeader->setWindowSize(65535);
            tcpSynHeader->setUrgent(0);
            tcpSynHeader->setFlags(network::TcpHeader::SYN);
            tcpSynHeader->addOption(network::TcpHeader::Options::MSS, {{network::TcpHeader::OptionValue::UINT16, 1460}});
            tcpSynHeader->addOption(network::TcpHeader::Options::SACK_Permitted);

            network::NetPacket synPacket{tcpSynHeader};

            //TODO Отсылаем пакет SYN

            QThread::msleep(settings.getTimeIntervalSendSyn());
        }

        if(!hasActualTasks){
            return;
        }

        hasActualTasks = false;
        QThread::msleep(settings.getTimeIntervalAttempt());
    }
}

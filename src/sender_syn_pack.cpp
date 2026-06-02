#include "sender_syn_pack.h"

#include <QThread>
#include <QSet>

#include <sr.h>

#include "settings_scanner.h"

SenderSynPack::SenderSynPack(const QSet<Task>& tasks_, QObject *parent)
    : QObject{parent},
    tasks{tasks_}
{}

void SenderSynPack::onRunSendSyn()
{
    const auto settings = SettingsScanner::getSettings();

    for(int i = 0; i < settings.getAmountAttempt(); i++)
    {
        for(const auto& currTask : tasks)
        {
            if(currTask.finished)
                continue;

            //TODO Отсылаем пакет SYN

            QThread::msleep(settings.getTimeIntervalSendSyn());
        }

        QThread::msleep(settings.getTimeIntervalAttempt());
    }
}

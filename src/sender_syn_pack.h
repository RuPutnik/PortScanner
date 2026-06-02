#pragma once

#include <QObject>

#include "task.h"

class SenderSynPack : public QObject
{
    Q_OBJECT
public:
    explicit SenderSynPack(const QSet<Task>& tasks_, QObject *parent = nullptr);

public slots:
    void onRunSendSyn();

signals:

private:
    const QSet<Task>& tasks;

};

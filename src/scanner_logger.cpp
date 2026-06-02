#include "scanner_logger.h"

#include <QTextEdit>
#include <QThread>
#include <QTextStream>

void ScannerLogger::initLogger(LocationLogging logLocation, const QString& filePath, QTextEdit* loggingEdit)
{
    if(wasInit)
        return;

    wasInit = true;

    location = logLocation;
    switch (location) {
    case FILE:
        logFile.setFileName(filePath);
        if(!logFile.open(QIODevice::ReadWrite))
        {
            location = WINDOW;
            loggingTextEdit = loggingEdit;
            const QString textError = "Файл %1 не удалось инициализировать для логирования. Логирование будет вестись в окно программы";
            if(loggingEdit->thread() != QThread::currentThread()){
                QMetaObject::invokeMethod(loggingEdit, "append", Qt::BlockingQueuedConnection,
                                        Q_ARG(QString, QString{textError}.arg(filePath)));
            }
            else
            {
                loggingEdit->append(textError.arg(filePath));
            }
        }
        break;
    case WINDOW:
        loggingTextEdit = loggingEdit;
        break;
    case BOTH:
        loggingTextEdit = loggingEdit;
        break;
    }
}

void ScannerLogger::logging(const QString& text)
{
    if(!wasInit)
        return;

    switch (location) {
    case FILE:{
        QTextStream textStream{&logFile};
        textStream << text;

        break;
    }
    case WINDOW:
        if(loggingTextEdit->thread() != QThread::currentThread()){
            QMetaObject::invokeMethod(loggingTextEdit, "append", Qt::BlockingQueuedConnection,
                                      Q_ARG(QString, text));
        }
        else
        {
            loggingTextEdit->append(text);
        }
        break;
    case BOTH:
        if(loggingTextEdit->thread() != QThread::currentThread()){
            QMetaObject::invokeMethod(loggingTextEdit, "append", Qt::BlockingQueuedConnection,
                                      Q_ARG(QString, text));
        }
        else
        {
            loggingTextEdit->append(text);
        }

        QTextStream textStream{&logFile};
        textStream << text;

        break;
    }
}

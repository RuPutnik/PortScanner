#pragma once

#include <QString>
#include <QFile>

class QTextEdit;

class ScannerLogger
{
public:
    enum LocationLogging{
        FILE,
        WINDOW,
        BOTH
    };

    static void initLogger(LocationLogging logLocation, const QString& filePath, QTextEdit* loggingEdit);
    static void logging(const QString& text);

private:
    ScannerLogger() = default;
    static inline LocationLogging location;
    static inline QFile logFile;
    static inline QTextEdit* loggingTextEdit = nullptr;
    static inline bool wasInit = false;
};


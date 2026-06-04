#include "settings_reader.h"

#include <QFile>

std::optional<SettingsScanner> SettingsReader::getSettings()
{
    QFile settingsFile{settingFileName};
    if(!settingsFile.open(QIODevice::ReadOnly)){
        return std::nullopt;
    }

    QJsonParseError parserError;

    const QJsonDocument settingsDoc = QJsonDocument::fromJson(settingsFile.readAll(), &parserError);

    if(parserError.error != QJsonParseError::NoError){
        return std::nullopt;
    }

    const QJsonObject rootObject = settingsDoc.object();

    const int amountAttempt = rootObject.value("amountAttempt").toInt(2);
    const uint32_t timeIntervalSendSynMs = static_cast<uint32_t>(rootObject.value("timeIntervalSendSynMs").toInteger(50));
    const uint32_t timeIntervalAttemptMs = static_cast<uint32_t>(rootObject.value("timeIntervalAttemptMs").toInteger(5000));
    const uint16_t srcPort = static_cast<uint16_t>(rootObject.value("srcPort").toInt(0));
    const uint32_t ackNumber = static_cast<uint32_t>(rootObject.value("ackNumber").toInteger(1));
    const uint16_t windowSize = static_cast<uint16_t>(rootObject.value("windowSize").toInt(65535));
    const uint16_t urgent = static_cast<uint16_t>(rootObject.value("urgent").toInt(0));
    const uint16_t mss = static_cast<uint16_t>(rootObject.value("mss").toInt(1460));
    const bool sackPermitted = rootObject.value("sackPermitted").toBool(true);

    static SettingsScanner settings{amountAttempt, timeIntervalSendSynMs, timeIntervalAttemptMs,
                                    srcPort, ackNumber, windowSize,
                                    urgent, mss, sackPermitted};

    return settings;
}

#pragma once

#include <QJsonObject>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QJsonValue>
#include <QString>

#include <optional>

#include "settings_scanner.h"

class SettingsReader
{
public:
    static std::optional<SettingsScanner> getSettings();

private:
    SettingsReader() = default;

    const static inline QString settingFileName = "scanner_settings.json";
};

